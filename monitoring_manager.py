#!/usr/bin/env python3                                                                 # run this file with python3 if executed directly
# coding: utf-8                                                                        # use UTF-8 encoding

import logging                                                                         # used to print info/warning/error logs
import requests                                                                        # used to send HTTP requests to vcpe-monitoring container


class MonitoringManager:                                                               # client/orchestrator used by agent.py
    def __init__(self, monitoring_base_url="http://vcpe-monitoring:8090/api/v1"):       # default API URL of vcpe-monitoring container
        self.monitoring_base_url = monitoring_base_url

    def _as_list(self, value):                                                          # helper to normalize a value into a list
        if value is None:                                                               # if the value does not exist
            return []                                                                   # return empty list
        if isinstance(value, list):                                                     # if the value is already a list
            return value                                                                # return it as it is
        return [value]                                                                  # otherwise wrap a single value as a list

    def _ip_from_prefix(self, prefix):                                                   # helper to extract IP from prefix
        if not prefix:                                                                  # if prefix is missing
            return None                                                                 # no destination IP can be extracted
        return str(prefix).split("/", 1)[0]                                             # convert 8.8.8.8/32 into 8.8.8.8

    def _calculate_interval_from_slo(self, slo):                                         # calculate probe interval using YANG SLO values
        if not isinstance(slo, dict):                                                    # if SLO object is missing or invalid
            return 30                                                                   # use default slow probing interval

        max_latency = slo.get("max-latency-ms")                                         # read max latency threshold from YANG datastore
        max_jitter = slo.get("max-jitter-ms")                                           # read max jitter threshold from YANG datastore
        max_loss = slo.get("max-loss-percent")                                          # read max packet loss threshold from YANG datastore
        min_bandwidth = slo.get("min-bandwidth-kbps")                                   # read minimum bandwidth threshold from YANG datastore

        try:                                                                            # convert numeric YANG values safely
            max_latency = float(max_latency) if max_latency is not None else None        # convert max latency to float
            max_jitter = float(max_jitter) if max_jitter is not None else None           # convert max jitter to float
            max_loss = float(max_loss) if max_loss is not None else None                 # convert max loss to float
            min_bandwidth = float(min_bandwidth) if min_bandwidth is not None else None  # convert min bandwidth to float
        except ValueError:                                                              # if conversion fails
            return 30                                                                   # use default interval

        if max_latency is not None and max_latency <= 30:                                # strict latency SLO means frequent probing
            return 2                                                                    # probe every 2 seconds

        if max_jitter is not None and max_jitter <= 10:                                  # strict jitter SLO also means frequent probing
            return 2                                                                    # probe every 2 seconds

        if max_loss is not None and max_loss <= 1:                                       # strict loss SLO needs moderately frequent probing
            return 5                                                                    # probe every 5 seconds

        if min_bandwidth is not None:                                                    # bandwidth-aware traffic needs periodic bandwidth check
            return 10                                                                   # probe every 10 seconds for bandwidth-sensitive classes

        return 30                                                                       # default probing interval for best-effort traffic

    def _select_probe_tools(self, slo):                                                  # choose probe tools based on required SLO metrics
        if not isinstance(slo, dict):                                                    # if no SLO is provided
            return ["ping"]                                                             # use ping as default reachability/RTT probe

        tools = set()                                                                    # use a set to avoid duplicate tools

        if slo.get("max-latency-ms") is not None:                                       # if RTT/latency is part of the SLO
            tools.add("ping")                                                           # ping can measure RTT

        if slo.get("max-loss-percent") is not None:                                     # if packet loss is part of the SLO
            tools.add("ping")                                                           # ping can estimate packet loss

        if slo.get("max-jitter-ms") is not None:                                        # if jitter is part of the SLO
            tools.add("ping")                                                           # first implementation can estimate jitter from RTT variation

        if slo.get("min-bandwidth-kbps") is not None:                                   # if bandwidth is part of the SLO
            tools.add("iperf3")                                                         # iperf3 is needed for active bandwidth/throughput measurement

        if not tools:                                                                    # if no known SLO parameter exists
            tools.add("ping")                                                           # keep ping as safe default

        return sorted(list(tools))                                                       # return stable list such as ["iperf3", "ping"]

    def start_underlay_flow_monitoring(self, traffic_class, flow_id):                    # start monitoring for internet/underlay traffic class
        five_tuple = traffic_class.get("five-tuple", {})                                # read 5-tuple object from YANG traffic class
        dst_prefix = five_tuple.get("dst-prefix")                                       # read destination prefix from 5-tuple
        destination_ip = self._ip_from_prefix(dst_prefix)                                # convert destination prefix to probe destination IP

        if not destination_ip or destination_ip == "any":                                # active probe needs a specific destination
            raise ValueError("Cannot start flow monitoring without a specific dst-prefix") # fail clearly when destination is not usable

        slo = traffic_class.get("slo") or {}                                             # read SLO object from traffic class; uses your YANG object name

        payload = {                                                                      # payload sent to vcpe-monitoring
            "flow_id": str(flow_id),                                                     # underlay flow ID; this is fwmark received from forwarder via agent.py
            "destination_ip": destination_ip,                                            # target IP where probe packets are sent
            "probe_tools": self._select_probe_tools(slo),                                # selected tools based on SLO metrics
            "interval_sec": self._calculate_interval_from_slo(slo)                       # selected probe frequency based on SLO strictness
        }

        url = f"{self.monitoring_base_url}/monitoring/flows"                             # vcpe-monitoring endpoint for flow monitoring
        logging.info("Sending flow monitoring request: %s", payload)                     # log request for debugging

        response = requests.post(url, json=payload, timeout=5)                            # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      # raise exception if vcpe-monitoring returns error

        return payload                                                                   # return sent payload for agent logging/debugging

    def stop_underlay_flow_monitoring(self, flow_id):                                    # stop underlay flow monitoring
        url = f"{self.monitoring_base_url}/monitoring/flows/{flow_id}"                   # vcpe-monitoring endpoint for deleting flow monitor
        logging.info("Stopping flow monitoring for flow_id=%s", flow_id)                 # log flow stop request

        response = requests.delete(url, timeout=5)                                       # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                      # raise exception if delete fails

    def start_overlay_tunnel_monitoring(self, tunnel):                                   # start monitoring for overlay WireGuard tunnel
        tunnel_id = tunnel.get("name")                                                   # YANG tunnel name is used as tunnel_id
        resolved_peer = tunnel.get("resolved-peer", {})                                  # peer details are expected under resolved-peer
        destination_ip = resolved_peer.get("peer-address")                               # use peer-address as tunnel monitoring destination

        if not tunnel_id:                                                                # tunnel monitoring needs tunnel ID
            raise ValueError("Cannot start tunnel monitoring without tunnel name")        # fail clearly if tunnel name is missing

        if not destination_ip:                                                           # tunnel monitoring needs remote endpoint/peer IP
            raise ValueError("Cannot start tunnel monitoring without peer-address")       # fail clearly if peer IP is missing

        payload = {                                                                      # payload sent to vcpe-monitoring
            "tunnel_id": str(tunnel_id),                                                  # overlay tunnel ID; not a flow_id
            "destination_ip": destination_ip,                                            # tunnel peer/endpoint IP used as probe target
            "probe_tools": ["ping"],                                                     # first version uses ping for tunnel health
            "interval_sec": 5                                                            # fixed simple interval for tunnel monitoring
        }

        url = f"{self.monitoring_base_url}/monitoring/tunnels"                           # vcpe-monitoring endpoint for tunnel monitoring
        logging.info("Sending tunnel monitoring request: %s", payload)                   # log request for debugging

        response = requests.post(url, json=payload, timeout=5)                            # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      # raise exception if vcpe-monitoring returns error

        return payload                                                                   # return sent payload for agent logging/debugging

    def stop_overlay_tunnel_monitoring(self, tunnel_id):                                  # stop overlay tunnel monitoring
        url = f"{self.monitoring_base_url}/monitoring/tunnels/{tunnel_id}"               # vcpe-monitoring endpoint for deleting tunnel monitor
        logging.info("Stopping tunnel monitoring for tunnel_id=%s", tunnel_id)            # log tunnel stop request

        response = requests.delete(url, timeout=5)                                       # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                      # raise exception if delete fails
