#!/usr/bin/env python3
# coding: utf-8
import json                                                                        #converting Python objects into JSON strings
import logging                                                                     #to print info and error logs.
import time
import requests
import os
import base64
import xml.etree.ElementTree as ET                                                  #to parse XML transaction messages sent by Clixon callback plugin

from http.server import BaseHTTPRequestHandler, HTTPServer                          #simple internal HTTP server for receiving Clixon callback messages
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from config_reader import ConfigReader
#from metric_reader import MetricReader                  #REMOVE COMMENT
#from state_writer import StateWriter                    #REMOVE COMMENT
#from monitoring_manager import MonitoringManager        #REMOVE COMMENT

logging.basicConfig(level=logging.INFO)                                             # to show info messages and errors

class Agent:
    def __init__(self):                                                             #Creates object for each python module and stores it inside the agent
        self.config_reader = ConfigReader()
        #self.metric_reader = MetricReader()              #REMOVE COMMENT
        #self.state_writer = StateWriter()                #REMOVE COMMENT
        #self.monitoring_manager = MonitoringManager()    #REMOVE COMMENT

        self.generated_tunnel_keys = {}
        self.forwarder_base_url = "http://vcpe-forwarder:9090"
        self.forwarder_dry_run = True                                               #Since forwarder is not ready yet,a dry-run will be enabled by default (false send real API calls)

    # =====================================================================================
    # Basic helpers
    # =====================================================================================
    def _allocate_fwmark(self, class_name, index):                                   #called by "_make_steering_decisions()". CPE agent assigned fwmark for a traffic class.
        return 1000 + index

    def _index_states_by_name(self, states):                                         #called by "_make_steering_decisions()"
        indexed = {}
        for item in states:                                                          #Loops through each state item in the list
            name = item.get("name")                                                  #Reads the name field from the state dictionary
            if name:
                indexed[name] = item                                                 #If the state has a name, store that item in the dictionary using the name as key
        return indexed

    def _local_name(self, tag):
        if tag is None:
            return ""
        if "}" in tag:
            return tag.split("}", 1)[1]                                              # splits the string variable tag at the first } and returns everything that comes after it
        return tag

    def _first_child(self, element):
        if element is None:
            return None
        children = list(element)
        return children[0] if children else None

    def _bool_value(self, value, default=True):
        if value is None:
            return default
        return str(value).lower() in ["true", "1", "yes"]                            # This converts text into Python boolean.

    def _xml_to_dict(self, element):                                                 # Convert XML parent object from Clixon into a Python dictionary to avoids hardcoding every YANG leaf one by one
        if element is None:
            return {}

        result = {}
        for child in list(element):
            name = self._local_name(child.tag)
            if len(list(child)) == 0:
                value = child.text
            else:
                value = self._xml_to_dict(child)

            if name in result:
                if not isinstance(result[name], list):
                    result[name] = [result[name]]
                result[name].append(value)
            else:
                result[name] = value

        return result

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _has_change(self, changed_leafs, *names):                                                 # agent decides whether to send a field to the forwarder.
        return any(name in changed_leafs for name in names)

    def _add_changed(self, payload, changed_leafs, yang_leaf, api_field, value, transform=None):   # helper for sending only changed values
        if yang_leaf not in changed_leafs:
            return
        if transform:
            value = transform(value)
        payload[api_field] = value

    def _port_range(self, value):                                                                  # Even when YANG has only one port, forwarder may expect port ranges. This converts a single port into forwarder format.
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None or value == "any":
            return None
        port = int(value)
        return {"start": port, "end": port}

    def _generate_wireguard_tunnel_keys(self, tunnel_name):                                          # generate and save WireGuard tunnel keys uding curve25519
        private_dir = "/var/lib/sdwan-cpe/keys"
        public_dir = "/var/lib/clixon/local-public-keys"

        private_path = f"{private_dir}/{tunnel_name}.private"
        public_path = f"{public_dir}/{tunnel_name}.pub"

        try:
            if os.path.exists(private_path) and os.path.exists(public_path):
                with open(private_path, "r") as f:
                    private_key = f.read().strip()

                with open(public_path, "r") as f:
                    public_key = f.read().strip()

                return private_key, public_key

            private_key_obj = X25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()

            private_key_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())

            public_key_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)

            private_key = base64.b64encode(private_key_bytes).decode("ascii")
            public_key = base64.b64encode(public_key_bytes).decode("ascii")

            os.makedirs(private_dir, exist_ok=True)
            os.makedirs(public_dir, exist_ok=True)

            with open(private_path, "w") as f:
                f.write(private_key)
            os.chmod(private_path, 0o600)

            with open(public_path, "w") as f:
                f.write(public_key)
            os.chmod(public_path, 0o644)

            logging.info("Created WireGuard keys for tunnel %s", tunnel_name)
            return private_key, public_key

        except Exception as e:
            logging.exception("Failed to get or create WireGuard keys for tunnel %s: %s", tunnel_name, e)
            return None, None

    # =====================================================================================
    # Publish operations data in Datastore
    # =====================================================================================
    def detect_and_store_nat_type(self, wan_name, interface_name, role):
        if role == "ipvpn":
            logging.info("Skipping NAT detection for IPvPN WAN link %s", wan_name)
            return None

        if not wan_name or not interface_name:
            return None

        if self.forwarder_dry_run:
            logging.info("Dry-run: NAT detection skipped for WAN link %s", wan_name)
            return None

        try:
            operation = self._operation("POST", f"/api/v1/wan-links/{wan_name}/nat-detection",
                {"interface_name": interface_name})

            self._send_forwarder_transaction([operation], validate_only=False)

            url = f"{self.forwarder_base_url}/api/v1/wan-links/{wan_name}/nat-type"
            response = requests.get(url, headers={"Accept": "application/json"}, timeout=10)
            response.raise_for_status()

            nat_type = response.json().get("nat-type")
            if not nat_type:
                return None

            state_dir = "/var/lib/clixon/wan-link-nat-types"
            os.makedirs(state_dir, exist_ok=True)

            with open(f"{state_dir}/{wan_name}.nat", "w") as f:
                f.write(nat_type)

            logging.info("Stored nat-type=%s for wan-link=%s", nat_type, wan_name)
            return nat_type

        except Exception as e:
            logging.exception("NAT detection failed for WAN link %s: %s", wan_name, e)
            return None

    # =====================================================================================
    # Forwarder API helpers
    # =====================================================================================
    def _operation(self, method, path, payload=None):
        operation = {"method": method, "path": path}
        if payload is not None:
            operation["payload"] = payload
        return operation

    def _send_forwarder_transaction(self, operations, validate_only):
        payload = {
            "validate_only": validate_only,
            "operations": operations}

        print("\n===== FORWARDER TRANSACTION GENERATED =====")
        print(json.dumps(payload, indent=2))

        if self.forwarder_dry_run:
            return {
                "status": "dry-run",
                "message": "Forwarder is not called because FORWARDER_DRY_RUN=1",
                "payload": payload}

        url = f"{self.forwarder_base_url}/api/v1/transactions"
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()

        if response.text:
            return response.json()

        return {"status": "ok"}

    # =====================================================================================
    # Build forwarder operations using changed node names + parent object dictionary
    # =====================================================================================
    def _build_wan_link_operations(self, parent_dict, changed_leafs, delete=False):
        name = parent_dict.get("name")
        interface_name = parent_dict.get("interface-name")
        admin_enabled = self._bool_value(parent_dict.get("admin-enabled"), True)
        address_mode = parent_dict.get("address-mode")
        static_address = parent_dict.get("static-address")

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]

        if not interface_name:
            logging.warning("WAN link %s has no interface-name", name)
            return []

        if delete:
            return [self._operation("PATCH", f"/api/v1/interfaces/{interface_name}/state", {"state": "down"})]

        operations = []

        if self._has_change(changed_leafs, "admin-enabled"):
            operations.append(
                self._operation("PATCH", f"/api/v1/interfaces/{interface_name}/state",
                                {"state": "up" if admin_enabled else "down"}))

        if self._has_change(changed_leafs, "static-address", "address-mode"):
            addresses = []
            if address_mode == "static" and static_address:
                addresses.append(static_address)

            operations.append(
                self._operation("PATCH", f"/api/v1/interfaces/{interface_name}/addresses",
                                {"addresses": addresses}))

        return operations

    def _build_lan_link_operations(self, parent_dict, changed_leafs, delete=False):
        name = parent_dict.get("name")
        bridge_name = parent_dict.get("bridge-name") or name
        ipv4_prefix = parent_dict.get("ipv4-prefix")
        member_interfaces = self._as_list(parent_dict.get("member-interface"))
        admin_enabled = self._bool_value(parent_dict.get("admin-enabled"), True)

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]

        if not bridge_name:
            logging.warning("LAN link has no name or bridge-name")
            return []

        if delete:
            return [self._operation("PATCH", f"/api/v1/bridges/{bridge_name}",
                    {"members": [], "admin_state": "down"})]

        operations = []

        bridge_payload = {}
        self._add_changed(bridge_payload, changed_leafs, "member-interface", "members", member_interfaces)
        self._add_changed(bridge_payload, changed_leafs, "admin-enabled", "admin_state",
                          "up" if admin_enabled else "down")

        if bridge_payload:
            operations.append(self._operation("PATCH", f"/api/v1/bridges/{bridge_name}", bridge_payload))

        if self._has_change(changed_leafs, "ipv4-prefix"):
            operations.append(
                self._operation("PATCH", f"/api/v1/interfaces/{bridge_name}/addresses",
                                {"addresses": [ipv4_prefix] if ipv4_prefix else []}))

        return operations

    def _build_tunnel_operations(self, parent_dict, changed_leafs, delete=False):
        name = parent_dict.get("name")

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]

        if not name:
            logging.warning("Tunnel has no name")
            return []

        if delete:
            return [self._operation("DELETE", f"/api/v1/tunnels/wireguard/{name}")]

        if name not in self.generated_tunnel_keys:
            private_key, public_key = self._generate_wireguard_tunnel_keys(name)

            if private_key and public_key:
                self.generated_tunnel_keys[name] = {
                    "private-key": private_key,
                    "public-key": public_key}

        private_key = None
        if name in self.generated_tunnel_keys:
            private_key = self.generated_tunnel_keys[name].get("private-key")

        operations = []

        local_port = parent_dict.get("local-port")
        local_address = parent_dict.get("local-address")

        tunnel_payload = {}
        self._add_changed(tunnel_payload, changed_leafs, "local-port", "listen_port",
                          local_port, lambda x: int(x) if x else 51820)
        self._add_changed(tunnel_payload, changed_leafs, "local-address", "local_addresses",
                          [local_address] if local_address else [])
        self._add_changed(tunnel_payload, changed_leafs, "admin-enabled", "admin_state",
                          "up" if self._bool_value(parent_dict.get("admin-enabled"), True) else "down")

        if self._has_change(changed_leafs, "name"):
            tunnel_payload["private_key"] = private_key
            tunnel_payload["description"] = f"WireGuard tunnel {name}"

        if tunnel_payload:
            operations.append(
                self._operation("PATCH", f"/api/v1/tunnels/wireguard/{name}", tunnel_payload))

        peer_id = (
            parent_dict.get("peer-cpe-id")
            or parent_dict.get("peer-id")
            or f"{name}-peer")

        resolved_peer = parent_dict.get("resolved-peer", {})

        peer_address = resolved_peer.get("peer-address")
        peer_port = resolved_peer.get("peer-port")
        peer_public_key = resolved_peer.get("peer-public-key")
        allowed_prefixes = self._as_list(resolved_peer.get("allowed-prefix"))
        keepalive = parent_dict.get("keepalive-seconds")

        peer_payload = {}

        self._add_changed(peer_payload, changed_leafs, "peer-public-key", "public_key", peer_public_key)
        self._add_changed(peer_payload, changed_leafs, "allowed-prefix", "allowed_ips", allowed_prefixes)
        self._add_changed(peer_payload, changed_leafs, "keepalive-seconds", "persistent_keepalive",
                          keepalive, lambda x: int(x) if x else 25)

        if self._has_change(changed_leafs, "peer-address", "peer-port"):
            if peer_address and peer_port:
                peer_payload["endpoint"] = f"{peer_address}:{peer_port}"

        if peer_payload:
            operations.append(
                self._operation("PATCH", f"/api/v1/tunnels/wireguard/{name}/peers/{peer_id}", peer_payload))

        return operations

    def _build_firewall_rule_operations(self, parent_dict, changed_leafs, delete=False):
        rule_id = parent_dict.get("id")

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]

        if not rule_id:
            logging.warning("Firewall rule has no id")
            return []

        policy_id = f"firewall-rule-{rule_id}"

        if delete:
            return [self._operation("DELETE", f"/api/v1/flow-policies/{policy_id}")]

        payload = {}
        match = {}

        self._add_changed(payload, changed_leafs, "priority", "priority",
                          parent_dict.get("priority"), lambda x: int(x) if x else 1000)

        if self._has_change(changed_leafs, "action"):
            payload["action"] = {"type": "allow" if parent_dict.get("action") == "allow" else "deny"}

        self._add_changed(payload, changed_leafs, "log", "log", self._bool_value(parent_dict.get("log"), False))

        self._add_changed(match, changed_leafs, "src-prefix", "src_prefix", parent_dict.get("src-prefix"))
        self._add_changed(match, changed_leafs, "dst-prefix", "dst_prefix", parent_dict.get("dst-prefix"))

        if self._has_change(changed_leafs, "l4-protocol"):
            protocol = parent_dict.get("l4-protocol")
            if protocol and protocol != "any":
                match["protocol"] = protocol

        if self._has_change(changed_leafs, "src-port"):
            src_ports = self._port_range(parent_dict.get("src-port"))
            if src_ports:
                match["src_ports"] = src_ports

        if self._has_change(changed_leafs, "dst-port"):
            dst_ports = self._port_range(parent_dict.get("dst-port"))
            if dst_ports:
                match["dst_ports"] = dst_ports

        if match:
            payload["match"] = match

        if not payload:
            return []

        return [self._operation("PATCH", f"/api/v1/flow-policies/{policy_id}", payload)]

    def _build_traffic_class_operations(self, parent_dict, changed_leafs, delete=False):
        class_name = parent_dict.get("name")
        five_tuple = parent_dict.get("five-tuple", {})

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]

        if not class_name:
            logging.warning("Traffic class has no name")
            return []

        policy_id = f"traffic-class-{class_name}"

        if delete:
            return [self._operation("DELETE", f"/api/v1/flow-policies/{policy_id}")]

        match = {}

        self._add_changed(match, changed_leafs, "src-prefix", "src_prefix", five_tuple.get("src-prefix"))
        self._add_changed(match, changed_leafs, "dst-prefix", "dst_prefix", five_tuple.get("dst-prefix"))

        if self._has_change(changed_leafs, "l4-protocol"):
            protocol = five_tuple.get("l4-protocol")
            if protocol and protocol != "any":
                match["protocol"] = protocol

        if self._has_change(changed_leafs, "src-port"):
            src_ports = self._port_range(five_tuple.get("src-port"))
            if src_ports:
                match["src_ports"] = src_ports

        if self._has_change(changed_leafs, "dst-port"):
            dst_ports = self._port_range(five_tuple.get("dst-port"))
            if dst_ports:
                match["dst_ports"] = dst_ports

        if not match:
            return []

        return [self._operation("PATCH", f"/api/v1/flow-policies/{policy_id}", {"match": match})]

    def _build_operations_from_object(self, object_type, parent_dict, changed_leafs, delete=False):
        if object_type == "wan-link":
            return self._build_wan_link_operations(parent_dict, changed_leafs, delete)

        if object_type == "lan-link":
            return self._build_lan_link_operations(parent_dict, changed_leafs, delete)

        if object_type == "tunnel":
            return self._build_tunnel_operations(parent_dict, changed_leafs, delete)

        if object_type == "rule":
            return self._build_firewall_rule_operations(parent_dict, changed_leafs, delete)

        if object_type == "class":
            return self._build_traffic_class_operations(parent_dict, changed_leafs, delete)

        logging.info("No forwarder mapping yet for object type=%s, changed_leafs=%s",
                     object_type, changed_leafs)
        return []

    def _build_operations_from_parent_xml(self, parent_xml, changed_leafs, delete=False):
        if parent_xml is None:
            return []

        object_type = self._local_name(parent_xml.tag)
        parent_dict = self._xml_to_dict(parent_xml)

        return self._build_operations_from_object(object_type, parent_dict, changed_leafs, delete)

    # =====================================================================================
    # Clixon callback handling
    # =====================================================================================
    def handle_clixon_transaction(self, xml_body):
        root = ET.fromstring(xml_body)

        phase = root.findtext("phase")
        transaction_id = root.findtext("transaction-id")
        validate_only = phase == "validate"

        if transaction_id == "0":
            logging.info("Ignoring Clixon startup transaction 0")
            return {
                "status": "ok",
                "phase": phase,
                "ignored": True,
                "reason": "startup transaction"}

        if phase not in ["validate", "commit"]:
            raise ValueError(f"Unsupported Clixon phase: {phase}")

        operations = []
        changed_objects = {}
        nat_detection_candidates = []

        changed = root.find("changed")
        if changed is not None:
            for change in changed.findall("change"):
                new_node = change.find("new")
                if new_node is None:
                    continue

                changed_leaf = new_node.findtext("node-name")
                parent_data = new_node.find("parent-data")
                parent_xml = self._first_child(parent_data)

                if parent_xml is None:
                    continue

                object_type = self._local_name(parent_xml.tag)
                parent_dict = self._xml_to_dict(parent_xml)

                object_name = (
                    parent_dict.get("name")
                    or parent_dict.get("id")
                    or parent_dict.get("class")
                    or object_type)

                object_key = f"{object_type}:{object_name}"

                if object_key not in changed_objects:
                    changed_objects[object_key] = {
                        "object_type": object_type,
                        "parent_dict": parent_dict,
                        "changed_leafs": []}

                changed_objects[object_key]["changed_leafs"].append(changed_leaf)

        for item in changed_objects.values():
            object_type = item["object_type"]
            parent_dict = item["parent_dict"]
            changed_leafs = item["changed_leafs"]

            operations.extend(
                self._build_operations_from_object(
                    object_type,
                    parent_dict,
                    changed_leafs,
                    delete=False))

            if object_type == "wan-link":
                if self._has_change(
                    changed_leafs,
                    "interface-name",
                    "role",
                    "address-mode",
                    "static-address",
                    "static-gateway",
                    "admin-enabled"):
                    nat_detection_candidates.append(parent_dict)

        added = root.find("added")
        if added is not None:
            for node in added.findall("node"):
                changed_leaf = node.findtext("node-name")
                parent_data = node.find("parent-data")
                parent_xml = self._first_child(parent_data)

                operations.extend(
                    self._build_operations_from_parent_xml(
                        parent_xml,
                        [changed_leaf],
                        delete=False))

        deleted = root.find("deleted")
        if deleted is not None:
            for node in deleted.findall("node"):
                changed_leaf = node.findtext("node-name")
                data = node.find("data")
                deleted_xml = self._first_child(data)

                operations.extend(
                    self._build_operations_from_parent_xml(
                        deleted_xml,
                        [changed_leaf],
                        delete=True))

        if not operations:
            return {
                "status": "ok",
                "phase": phase,
                "message": "No forwarder operation generated",
                "operations": []}

        forwarder_result = self._send_forwarder_transaction(
            operations=operations,
            validate_only=validate_only)

        if phase == "commit":
            for wan in nat_detection_candidates:
                self.detect_and_store_nat_type(
                    wan.get("name"),
                    wan.get("interface-name"),
                    wan.get("role"))

        return {
            "status": "ok",
            "phase": phase,
            "validate_only": validate_only,
            "operations": operations,
            "forwarder_result": forwarder_result}

    # =====================================================================================
    # Runtime steering decisions
    # =====================================================================================
    def _candidate_satisfies_slo(self, candidate_state, policy):
        if not candidate_state:                                                              #If there is no state object, candidate is invalid.
            return False

        oper_status = candidate_state.get("oper-status")                                     #Reads the operational status.
        if oper_status not in ["up", "degraded"]:                                            #Only candidates with up or degraded are accepted. Anything else is rejected
            return False

        max_latency = policy.get("max-latency-ms")                                           #Reads max allowed latency from policy.
        if max_latency is not None:
            latency = candidate_state.get("latency-ms")                                      #Reads measured latency from state
            if latency is None or latency > max_latency:                                     #Reject if latency is missing or exceeds the threshold.
                return False

        max_jitter = policy.get("max-jitter-ms")                                             #Reads max allowed jitter from policy.
        if max_jitter is not None:
            jitter = candidate_state.get("jitter-ms")                                        #Reads measured jitter from state
            if jitter is None or jitter > max_jitter:                                        #Reject if jitter is missing or exceeds the threshold
                return False

        max_loss = policy.get("max-loss-percent")                                            #Reads max allowed packet loss from policy.
        if max_loss is not None:
            loss = candidate_state.get("loss-percent")                                       #Reads measured packet loss from state
            if loss is None or loss > float(max_loss):                                       #Reject if packet loss is missing or exceeds the threshold
                return False

        min_bw = policy.get("min-bandwidth-kbps")                                            #Reads min allowed BW from policy.
        if min_bw is not None:
            bw = candidate_state.get("available-bandwidth-kbps")                             #Reads available BW from state
            if bw is None or bw < min_bw:                                                    #Reject if BW is missing or less than the threshold
                return False

        return True                                                                          #If all checks pass, candidate satisfies the SLO

    def _extract_candidate_states(self, policy, wan_state_map, tunnel_state_map):             #Return candidate type and candidate state objects according to policy.
        steering_mode = policy.get("steering-mode")                                          #Reads steering mode from policy. Default is "failover"
        candidates = []

        if steering_mode == "failover":
            failover_link_type = policy.get("failover-link-type")                            #If mode is failover, read whether policy uses tunnels or WAN links.

            if failover_link_type == "tunnel":
                ordered_names = []
                primary = policy.get("primary-tunnel")
                if primary:
                    ordered_names.append(primary)                                            #If a primary tunnel exists, add it first
                ordered_names.extend(policy.get("secondary-tunnel", []))                     #Then append all secondary tunnels.

                for name in ordered_names:
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))                           #For each configured tunnel name, look up its state and add it as candidate.

            elif failover_link_type == "wan-link":
                ordered_names = []
                primary = policy.get("primary-wan-link")
                if primary:
                    ordered_names.append(primary)                                            #If a primary wan link exists, add it first
                ordered_names.extend(policy.get("secondary-wan-link", []))                   #Then append all secondary wan links

                for name in ordered_names:
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))                         #For each configured wan link, look up its state and add it as candidate

        elif steering_mode == "load-balance":
            lb_type = policy.get("load-balance-link-type")                                   #If mode is load-balance, read whether balancing uses tunnels or WAN links.

            if lb_type == "tunnel":
                for name in policy.get("load-balance-tunnel", []):
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))                           #adds configured tunnels as load-balance candidates.

            elif lb_type == "wan-link":
                for name in policy.get("load-balance-wan-link", []):
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))                         #adds configured WAN links as load-balance candidates

        return candidates                                                                    #returns the final candidate list.

    def _make_steering_decisions(self, current_config, wan_link_states, tunnel_states):
        decisions = []                                                                        #Creates an empty list for steering decisions.

        steering_policies = current_config.get("policy", {}).get("steering", [])              #Reads steering policies from config.

        wan_state_map = self._index_states_by_name(wan_link_states)                           #Converts state lists into dictionaries for fast lookup by name
        tunnel_state_map = self._index_states_by_name(tunnel_states)                          #Converts state lists into dictionaries for fast lookup by name

        for policy in steering_policies:                                                      #Loops through each steering policy.
            traffic_class = policy.get("class")                                               #Reads traffic class associated with this policy.
            if not traffic_class:
                continue                                                                      #Skip if missing

            steering_mode = policy.get("steering-mode")                                       #Reads steering mode
            candidates = self._extract_candidate_states(policy, wan_state_map, tunnel_state_map) #Builds the list of candidate paths according to this policy.

            eligible = []                                                                     #Creates lists for accepted and rejected candidates
            rejected = []

            for link_type, name, state in candidates:                                         #Loops through each candidate.
                if self._candidate_satisfies_slo(state, policy):
                    eligible.append((link_type, name, state))                                 #If candidate passes SLO checks, put it in eligible
                else:
                    rejected.append({                                                         #If candidate fails, add summary info into rejected
                        "name": name,
                        "link-type": link_type,
                        "oper-status": state.get("oper-status"),
                        "latency-ms": state.get("latency-ms"),
                        "jitter-ms": state.get("jitter-ms"),
                        "loss-percent": state.get("loss-percent"),
                        "available-bandwidth-kbps": state.get("available-bandwidth-kbps")})

            now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())                       #Creates current UTC timestamp in ISO-like format.

            if steering_mode == "failover":                                                   #Enter failover logic.
                if eligible:                                                                  #If at least one candidate satisfies the SLO
                    selected_link_type, selected_name, selected_state = eligible[0]            #Choose the first eligible candidate.

                    if candidates and selected_name == candidates[0][1]:
                        reason = "primary path satisfies SLO"
                    else:
                        reason = "primary path failed SLO; failed over to next eligible path"

                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": selected_name,
                        "selected-path-type": selected_link_type,
                        "decision-status": "selected",
                        "reason": reason,
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [item[1] for item in eligible],
                            "rejected": rejected}}
                else:                                                                          #If no candidate is eligible, creates a no-path decision.
                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": None,
                        "selected-path-type": policy.get("failover-link-type"),
                        "decision-status": "no-path",
                        "reason": "no candidate satisfies SLO or candidates are down",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected}}

                decisions.append(decision)

            elif steering_mode == "load-balance":                                             #Enter load-balance logic
                if eligible:                                                                   #If some candidates satisfy SLO:
                    eligible_names = [item[1] for item in eligible]

                    decision = {                                                               #Creates load-balance decision listing all selected paths
                        "action": "set-load-balance-policy",
                        "traffic-class": traffic_class,
                        "eligible-paths": eligible_names,
                        "selected-path-type": policy.get("load-balance-link-type"),
                        "decision-status": "selected",
                        "reason": "Candidates satisfying SLO for Load-Balance",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": eligible_names,
                            "rejected": rejected}}
                else:                                                                          #If none are eligible, create a no-path load-balance decision.
                    decision = {
                        "action": "set-load-balance-policy",
                        "traffic-class": traffic_class,
                        "eligible-paths": [],
                        "selected-path-type": policy.get("load-balance-link-type"),
                        "decision-status": "no-path",
                        "reason": "no load-balance candidate satisfies SLO or candidates are down",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected}}

                decisions.append(decision)

        return decisions                                                                       #returns all steering decisions.

    def _build_active_path_operations(self, decision):
        traffic_class = decision.get("traffic-class")
        selected_path = decision.get("selected-path")
        path_group_id = decision.get("path-group-id") or f"{traffic_class}-failover"

        if not traffic_class or not selected_path:
            return []

        eligible_paths = decision.get("candidate-summary", {}).get("eligible", [])

        if not eligible_paths:
            eligible_paths = [selected_path]

        members = []
        for index, path_id in enumerate(eligible_paths, start=1):
            members.append({"path_id": path_id, "priority": index * 10, "weight": 100})

        payload = {
            "strategy": "ordered_failover",
            "active_path_id": selected_path,
            "members": members}

        return [self._operation("PUT", f"/api/v1/path-groups/{path_group_id}", payload)]

    def _build_load_balance_operations(self, decision):
        traffic_class = decision.get("traffic-class")
        eligible_paths = decision.get("eligible-paths", [])
        path_group_id = decision.get("path-group-id") or f"{traffic_class}-ecmp"

        if not traffic_class or not eligible_paths:
            return []

        members = []
        for path_id in eligible_paths:
            members.append({"path_id": path_id, "priority": 10, "weight": 100})

        payload = {
            "strategy": "weighted_ecmp",
            "members": members}

        return [self._operation("PUT", f"/api/v1/path-groups/{path_group_id}", payload)]

    def _build_steering_operations(self, decisions):
        operations = []
        for decision in decisions:
            action = decision.get("action")
            if action == "set-active-path":
                operations.extend(self._build_active_path_operations(decision))
            elif action == "set-load-balance-policy":
                operations.extend(self._build_load_balance_operations(decision))
        return operations

    # =====================================================================================
    # Main cycle
    # =====================================================================================
    def run_once(self):
        current_config = self.config_reader.get_intended_config()

        if not hasattr(self, "metric_reader"):
            logging.warning("metric_reader not configured")
            return {"status": "skipped", "reason": "metric_reader not configured"}

        wan_links = current_config.get("interfaces", {}).get("underlay", {}).get("wan-link", [])
        tunnels = current_config.get("overlay", {}).get("tunnel", [])

        wan_link_states = []                                                                  #Builds WAN operational states.
        for wan_link in wan_links:
            name = wan_link.get("name")
            metric = self.metric_reader.get_wan_link_metric(name)

            wan_link_states.append({
                "name": name,
                "oper-status": "down" if metric.get("stale") else "up",
                "latency-ms": metric.get("latency_ms"),
                "jitter-ms": metric.get("jitter_ms"),
                "loss-percent": metric.get("loss_percent"),
                "available-bandwidth-kbps": metric.get("available_bandwidth_kbps")})

        tunnel_states = []                                                                    #Builds tunnel operational states.
        for tunnel in tunnels:
            name = tunnel.get("name")
            metric = self.metric_reader.get_tunnel_metric(name)

            tunnel_states.append({
                "name": name,
                "oper-status": "down" if metric.get("stale") else "up",
                "active-wan-link": tunnel.get("bind-wan-link"),
                "latency-ms": metric.get("latency_ms"),
                "jitter-ms": metric.get("jitter_ms"),
                "loss-percent": metric.get("loss_percent"),
                "available-bandwidth-kbps": metric.get("available_bandwidth_kbps")})

        steering_decisions = self._make_steering_decisions(current_config, wan_link_states, tunnel_states) #Makes steering decisions using current states and policies
        steering_operations = self._build_steering_operations(steering_decisions)

        execution_results = []
        if steering_operations:
            execution_results.append(
                self._send_forwarder_transaction(
                    operations=steering_operations,
                    validate_only=False))

        result = {                                                                            #Build final result object
            "wan_link_states": wan_link_states,
            "tunnel_states": tunnel_states,
            "decisions": steering_decisions,
            "steering_operations": steering_operations,
            "execution_results": execution_results}

        logging.info("Agent runtime steering cycle completed")                                #Builds a summary dictionary of everything done in this cycle.
        print(json.dumps(result, indent=2))                                                    #Logs success message.

        return result

    def run_forever(self, interval_sec=5):                                                     # Repeat the full execution cycle continuously.
        while True:
            try:
                self.run_once()
            except Exception as e:
                logging.exception("Agent loop failed: %s", e)

            time.sleep(interval_sec)

    def run_clixon_callback_server(self, host="0.0.0.0", port=8080):
        ClixonCallbackHandler.agent = self

        server = HTTPServer((host, port), ClixonCallbackHandler)

        logging.info("Starting Clixon callback server on %s:%s", host, port)
        server.serve_forever()

class ClixonCallbackHandler(BaseHTTPRequestHandler):
    agent = None

    def do_POST(self):
        try:
            if self.path not in [
                "/internal/clixon/validate-config-change",
                "/internal/clixon/commit-config-change"]:

                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")

            result = self.agent.handle_clixon_transaction(body)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

        except Exception as e:
            logging.exception("Clixon callback handling failed: %s", e)

            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "reason": str(e)}).encode("utf-8"))

    def log_message(self, format, *args):
        return

# =====================================================================================
# Temporary fake metric reader for testing agent.py before real metric_reader.py is ready
# =====================================================================================
class FakeMetricReader:
    def get_wan_link_metric(self, name):
        if name == "UPL1":
            return {
                "latency_ms": 10,
                "jitter_ms": 1,
                "loss_percent": 0,
                "available_bandwidth_kbps": 100000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for UPL1"}

        if name == "UPL2":
            return {
                "latency_ms": 40,
                "jitter_ms": 5,
                "loss_percent": 1,
                "available_bandwidth_kbps": 50000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for UPL2"}

        if name == "UPL3":
            return {
                "latency_ms": 40,
                "jitter_ms": 5,
                "loss_percent": 1,
                "available_bandwidth_kbps": 50000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for UPL3"}

        return {
            "latency_ms": None,
            "jitter_ms": None,
            "loss_percent": None,
            "available_bandwidth_kbps": None,
            "timestamp": "test",
            "stale": True,
            "source": "fake",
            "reason": "unknown WAN link"}

    def get_tunnel_metric(self, name):
        if name == "wg01":
            return {
                "latency_ms": 105,
                "jitter_ms": 2,
                "loss_percent": 0,
                "available_bandwidth_kbps": 50000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for wg01"}

        if name == "wg02":
            return {
                "latency_ms": 30,
                "jitter_ms": 3,
                "loss_percent": 0,
                "available_bandwidth_kbps": 70000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for wg02"}

        if name == "wg03":
            return {
                "latency_ms": 30,
                "jitter_ms": 3,
                "loss_percent": 0,
                "available_bandwidth_kbps": 70000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for wg03"}

        return {
            "latency_ms": None,
            "jitter_ms": None,
            "loss_percent": None,
            "available_bandwidth_kbps": None,
            "timestamp": "test",
            "stale": True,
            "source": "fake",
            "reason": "unknown tunnel"}

if __name__ == "__main__":
    agent = Agent()

    agent.metric_reader = FakeMetricReader()                  # Temporary fake metric reader for testing agent.py before real metric_reader.py is ready
    agent.run_clixon_callback_server()                        # Start internal API used by Clixon callback plugin.
