#!/usr/bin/env python3
# coding: utf-8

import copy
import json
import logging
import time
import os
import base64
import requests
import xml.etree.ElementTree as ET

from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from config_reader import ConfigReader
from steering_manager import SteeringManager

logging.basicConfig(level=logging.INFO)


class Agent:
    def __init__(self):
        self.config_reader = ConfigReader()

        # SteeringManager is now mainly for runtime steering decisions.
        # Configuration changes from Clixon callback go directly from agent.py to forwarder.
        self.steering_manager = SteeringManager()

        self.generated_tunnel_keys = {}

        self.forwarder_base_url = os.environ.get(
            "FORWARDER_BASE_URL",
            "http://127.0.0.1:9090"
        )

    # =====================================================================================
    # Basic helpers
    # =====================================================================================

    def _allocate_fwmark(self, class_name, index):
        return 1000 + index

    def _index_states_by_name(self, states):
        indexed = {}

        for item in states:
            name = item.get("name")
            if name:
                indexed[name] = item

        return indexed

    def _bool_from_xml(self, value, default=True):
        if value is None:
            return default

        return str(value).lower() in ["true", "1", "yes"]

    def _local_name(self, tag):
        if tag is None:
            return ""

        if "}" in tag:
            return tag.split("}", 1)[1]

        return tag

    def _first_child(self, element):
        if element is None:
            return None

        children = list(element)
        return children[0] if children else None

    def _xml_leaf_text(self, parent, leaf_name):
        if parent is None:
            return None

        for child in list(parent):
            if self._local_name(child.tag) == leaf_name:
                return child.text

        return None

    def _xml_leaf_list(self, parent, leaf_name):
        values = []

        if parent is None:
            return values

        for child in list(parent):
            if self._local_name(child.tag) == leaf_name and child.text is not None:
                values.append(child.text)

        return values

    # =====================================================================================
    # WireGuard key helper
    # =====================================================================================

    def _generate_wireguard_tunnel_keys(self, tunnel_name):
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
                encryption_algorithm=serialization.NoEncryption()
            )

            public_key_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

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
            logging.exception("Failed to create WireGuard keys for tunnel %s: %s", tunnel_name, e)
            return None, None

    # =====================================================================================
    # Forwarder API helpers
    # =====================================================================================

    def _send_forwarder_transaction(self, operations, validate_only):
        payload = {
            "validate_only": validate_only,
            "operations": operations
        }

        url = f"{self.forwarder_base_url}/api/v1/transactions"

        logging.info("Sending transaction to forwarder: validate_only=%s", validate_only)
        logging.info(json.dumps(payload, indent=2))

        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()

        if response.text:
            return response.json()

        return {"status": "ok"}

    def _operation(self, method, path, payload=None):
        op = {
            "method": method,
            "path": path
        }

        if payload is not None:
            op["payload"] = payload

        return op

    # =====================================================================================
    # Build forwarder operations directly from Clixon changed parent object
    # =====================================================================================

    def _build_wan_link_operations(self, wan_xml, changed_leaf, delete=False):
        name = self._xml_leaf_text(wan_xml, "name")
        interface_name = self._xml_leaf_text(wan_xml, "interface-name")
        admin_enabled = self._bool_from_xml(self._xml_leaf_text(wan_xml, "admin-enabled"), True)
        address_mode = self._xml_leaf_text(wan_xml, "address-mode")
        static_address = self._xml_leaf_text(wan_xml, "static-address")

        if not interface_name:
            logging.warning("WAN link %s has no interface-name; no operation built", name)
            return []

        operations = []

        if delete:
            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/interfaces/{interface_name}/state",
                    {"state": "down"}
                )
            )
            return operations

        if changed_leaf in ["admin-enabled", "interface-name", "name"]:
            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/interfaces/{interface_name}/state",
                    {"state": "up" if admin_enabled else "down"}
                )
            )

        if changed_leaf in ["static-address", "static-gateway", "address-mode", "interface-name"]:
            if address_mode == "static" and static_address:
                addresses = [static_address]
            else:
                addresses = []

            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/interfaces/{interface_name}/addresses",
                    {"addresses": addresses}
                )
            )

        return operations

    def _build_lan_link_operations(self, lan_xml, changed_leaf, delete=False):
        name = self._xml_leaf_text(lan_xml, "name")
        bridge_name = self._xml_leaf_text(lan_xml, "bridge-name") or name
        ipv4_prefix = self._xml_leaf_text(lan_xml, "ipv4-prefix")
        member_interfaces = self._xml_leaf_list(lan_xml, "member-interface")
        admin_enabled = self._bool_from_xml(self._xml_leaf_text(lan_xml, "admin-enabled"), True)

        if not bridge_name:
            logging.warning("LAN link has no name/bridge-name; no operation built")
            return []

        operations = []

        if delete:
            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/bridges/{bridge_name}",
                    {
                        "bridge_id": bridge_name,
                        "members": [],
                        "admin_state": "down"
                    }
                )
            )
            return operations

        if changed_leaf in ["bridge-name", "member-interface", "admin-enabled", "name"]:
            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/bridges/{bridge_name}",
                    {
                        "bridge_id": bridge_name,
                        "members": member_interfaces,
                        "admin_state": "up" if admin_enabled else "down"
                    }
                )
            )

        if changed_leaf in ["ipv4-prefix", "bridge-name", "name"]:
            addresses = [ipv4_prefix] if ipv4_prefix else []

            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/interfaces/{bridge_name}/addresses",
                    {"addresses": addresses}
                )
            )

        return operations

    def _build_tunnel_operations(self, tunnel_xml, changed_leaf, delete=False):
        name = self._xml_leaf_text(tunnel_xml, "name")

        if not name:
            logging.warning("Tunnel has no name; no operation built")
            return []

        operations = []

        if delete:
            operations.append(
                self._operation(
                    "DELETE",
                    f"/api/v1/tunnels/wireguard/{name}"
                )
            )
            return operations

        if name not in self.generated_tunnel_keys:
            private_key, public_key = self._generate_wireguard_tunnel_keys(name)

            if private_key and public_key:
                self.generated_tunnel_keys[name] = {
                    "private-key": private_key,
                    "public-key": public_key
                }

        keys = self.generated_tunnel_keys.get(name, {})

        local_port = self._xml_leaf_text(tunnel_xml, "local-port")
        local_address = self._xml_leaf_text(tunnel_xml, "local-address")

        tunnel_payload = {
            "private_key_ref": f"secret://wireguard/{name}/private-key",
            "listen_port": int(local_port) if local_port else 51820,
            "local_addresses": [local_address] if local_address else [],
            "description": f"WireGuard tunnel {name}"
        }

        operations.append(
            self._operation(
                "PUT",
                f"/api/v1/tunnels/wireguard/{name}",
                tunnel_payload
            )
        )

        peer_id = (
            self._xml_leaf_text(tunnel_xml, "peer-cpe-id")
            or self._xml_leaf_text(tunnel_xml, "peer-id")
            or f"{name}-peer"
        )

        peer_address = self._xml_leaf_text(tunnel_xml, "peer-address")
        peer_port = self._xml_leaf_text(tunnel_xml, "peer-port")
        peer_public_key = self._xml_leaf_text(tunnel_xml, "peer-public-key")
        allowed_prefixes = self._xml_leaf_list(tunnel_xml, "allowed-prefix")
        keepalive = self._xml_leaf_text(tunnel_xml, "keepalive-seconds")

        if peer_public_key or peer_address:
            peer_payload = {
                "public_key": peer_public_key,
                "allowed_ips": allowed_prefixes,
                "persistent_keepalive": int(keepalive) if keepalive else 25,
                "description": f"Peer {peer_id} for tunnel {name}"
            }

            if peer_address and peer_port:
                peer_payload["endpoint"] = f"{peer_address}:{peer_port}"

            operations.append(
                self._operation(
                    "PUT",
                    f"/api/v1/tunnels/wireguard/{name}/peers/{peer_id}",
                    peer_payload
                )
            )

        return operations

    def _build_firewall_rule_operations(self, rule_xml, changed_leaf, delete=False):
        rule_id = self._xml_leaf_text(rule_xml, "id")

        if not rule_id:
            logging.warning("Firewall rule has no id; no operation built")
            return []

        policy_id = f"firewall-rule-{rule_id}"

        if delete:
            return [
                self._operation("DELETE", f"/api/v1/flow-policies/{policy_id}")
            ]

        priority = self._xml_leaf_text(rule_xml, "priority")
        action = self._xml_leaf_text(rule_xml, "action")
        protocol = self._xml_leaf_text(rule_xml, "l4-protocol")
        src_prefix = self._xml_leaf_text(rule_xml, "src-prefix")
        dst_prefix = self._xml_leaf_text(rule_xml, "dst-prefix")
        src_port = self._xml_leaf_text(rule_xml, "src-port")
        dst_port = self._xml_leaf_text(rule_xml, "dst-port")

        match = {}

        if src_prefix:
            match["src_prefix"] = src_prefix

        if dst_prefix:
            match["dst_prefix"] = dst_prefix

        if protocol and protocol != "any":
            match["protocol"] = protocol

        if src_port and src_port != "any":
            match["src_ports"] = {
                "start": int(src_port),
                "end": int(src_port)
            }

        if dst_port and dst_port != "any":
            match["dst_ports"] = {
                "start": int(dst_port),
                "end": int(dst_port)
            }

        payload = {
            "priority": int(priority) if priority else 1000,
            "match": match,
            "action": {
                "type": "allow" if action == "allow" else "deny"
            },
            "description": f"Firewall rule {rule_id}"
        }

        return [
            self._operation(
                "PUT",
                f"/api/v1/flow-policies/{policy_id}",
                payload
            )
        ]

    def _build_forwarder_operations_from_parent(self, parent_xml, changed_leaf, delete=False):
        if parent_xml is None:
            return []

        object_type = self._local_name(parent_xml.tag)

        if object_type == "wan-link":
            return self._build_wan_link_operations(parent_xml, changed_leaf, delete)

        if object_type == "lan-link":
            return self._build_lan_link_operations(parent_xml, changed_leaf, delete)

        if object_type == "tunnel":
            return self._build_tunnel_operations(parent_xml, changed_leaf, delete)

        if object_type == "rule":
            return self._build_firewall_rule_operations(parent_xml, changed_leaf, delete)

        logging.info("No direct forwarder mapping yet for object type: %s", object_type)
        return []

    # =====================================================================================
    # Clixon callback handling
    # =====================================================================================

    def handle_clixon_transaction(self, xml_body):
        root = ET.fromstring(xml_body)

        phase = root.findtext("phase")
        validate_only = phase == "validate"

        if phase not in ["validate", "commit"]:
            raise ValueError(f"Unsupported Clixon phase: {phase}")

        operations = []

        changed = root.find("changed")
        if changed is not None:
            for change in changed.findall("change"):
                new_node = change.find("new")

                if new_node is None:
                    continue

                node_name = new_node.findtext("node-name")

                parent_data = new_node.find("parent-data")
                parent_xml = self._first_child(parent_data)

                operations.extend(
                    self._build_forwarder_operations_from_parent(
                        parent_xml,
                        node_name,
                        delete=False
                    )
                )

        added = root.find("added")
        if added is not None:
            for node in added.findall("node"):
                node_name = node.findtext("node-name")
                parent_data = node.find("parent-data")
                parent_xml = self._first_child(parent_data)

                operations.extend(
                    self._build_forwarder_operations_from_parent(
                        parent_xml,
                        node_name,
                        delete=False
                    )
                )

        deleted = root.find("deleted")
        if deleted is not None:
            for node in deleted.findall("node"):
                node_name = node.findtext("node-name")
                data = node.find("data")
                deleted_xml = self._first_child(data)

                operations.extend(
                    self._build_forwarder_operations_from_parent(
                        deleted_xml,
                        node_name,
                        delete=True
                    )
                )

        if not operations:
            logging.info("No forwarder operations built for this Clixon transaction")
            return {
                "status": "ok",
                "phase": phase,
                "operations": []
            }

        result = self._send_forwarder_transaction(
            operations=operations,
            validate_only=validate_only
        )

        return {
            "status": "ok",
            "phase": phase,
            "validate_only": validate_only,
            "operations": operations,
            "forwarder_result": result
        }

    # =====================================================================================
    # Runtime steering decision logic
    # =====================================================================================

    def _candidate_satisfies_slo(self, candidate_state, policy):
        if not candidate_state:
            return False

        oper_status = candidate_state.get("oper-status")
        if oper_status not in ["up", "degraded"]:
            return False

        max_latency = policy.get("max-latency-ms")
        if max_latency is not None:
            latency = candidate_state.get("latency-ms")
            if latency is None or latency > max_latency:
                return False

        max_jitter = policy.get("max-jitter-ms")
        if max_jitter is not None:
            jitter = candidate_state.get("jitter-ms")
            if jitter is None or jitter > max_jitter:
                return False

        max_loss = policy.get("max-loss-percent")
        if max_loss is not None:
            loss = candidate_state.get("loss-percent")
            if loss is None or loss > float(max_loss):
                return False

        min_bw = policy.get("min-bandwidth-kbps")
        if min_bw is not None:
            bw = candidate_state.get("available-bandwidth-kbps")
            if bw is None or bw < min_bw:
                return False

        return True

    def _extract_candidate_states(self, policy, wan_state_map, tunnel_state_map):
        steering_mode = policy.get("steering-mode")
        candidates = []

        if steering_mode == "failover":
            failover_link_type = policy.get("failover-link-type")

            if failover_link_type == "tunnel":
                ordered_names = []

                primary = policy.get("primary-tunnel")
                if primary:
                    ordered_names.append(primary)

                ordered_names.extend(policy.get("secondary-tunnel", []))

                for name in ordered_names:
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))

            elif failover_link_type == "wan-link":
                ordered_names = []

                primary = policy.get("primary-wan-link")
                if primary:
                    ordered_names.append(primary)

                ordered_names.extend(policy.get("secondary-wan-link", []))

                for name in ordered_names:
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))

        elif steering_mode == "load-balance":
            lb_type = policy.get("load-balance-link-type")

            if lb_type == "tunnel":
                for name in policy.get("load-balance-tunnel", []):
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))

            elif lb_type == "wan-link":
                for name in policy.get("load-balance-wan-link", []):
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))

        return candidates

    def _make_steering_decisions(self, current_config, wan_link_states, tunnel_states):
        decisions = []

        steering_policies = current_config.get("policy", {}).get("steering", [])

        wan_state_map = self._index_states_by_name(wan_link_states)
        tunnel_state_map = self._index_states_by_name(tunnel_states)

        for policy in steering_policies:
            traffic_class = policy.get("class")
            if not traffic_class:
                continue

            steering_mode = policy.get("steering-mode")
            candidates = self._extract_candidate_states(policy, wan_state_map, tunnel_state_map)

            eligible = []
            rejected = []

            for link_type, name, state in candidates:
                if self._candidate_satisfies_slo(state, policy):
                    eligible.append((link_type, name, state))
                else:
                    rejected.append({
                        "name": name,
                        "link-type": link_type,
                        "oper-status": state.get("oper-status"),
                        "latency-ms": state.get("latency-ms"),
                        "jitter-ms": state.get("jitter-ms"),
                        "loss-percent": state.get("loss-percent"),
                        "available-bandwidth-kbps": state.get("available-bandwidth-kbps"),
                    })

            now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            if steering_mode == "failover":
                if eligible:
                    selected_link_type, selected_name, selected_state = eligible[0]

                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": selected_name,
                        "selected-path-type": selected_link_type,
                        "decision-status": "selected",
                        "reason": "selected first candidate satisfying SLO",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [item[1] for item in eligible],
                            "rejected": rejected
                        }
                    }
                else:
                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": None,
                        "selected-path-type": policy.get("failover-link-type"),
                        "decision-status": "no-path",
                        "reason": "no candidate satisfies SLO",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected
                        }
                    }

                decisions.append(decision)

            elif steering_mode == "load-balance":
                eligible_names = [item[1] for item in eligible]

                decision = {
                    "action": "set-load-balance-policy",
                    "traffic-class": traffic_class,
                    "eligible-paths": eligible_names,
                    "selected-path-type": policy.get("load-balance-link-type"),
                    "decision-status": "selected" if eligible_names else "no-path",
                    "reason": "load-balance candidates selected" if eligible_names else "no candidate satisfies SLO",
                    "last-change": now_ts,
                    "candidate-summary": {
                        "eligible": eligible_names,
                        "rejected": rejected
                    }
                }

                decisions.append(decision)

        return decisions

    def _execute_runtime_steering_decisions(self, decisions):
        results = []

        for decision in decisions:
            result = self.steering_manager.execute_decision(decision)
            results.append(result)

        return results

    def run_once(self):
        """
        Runtime cycle only.

        This is no longer used for configuration change detection.
        Config changes are handled by Clixon callback -> handle_clixon_transaction().
        """

        current_config = self.config_reader.get_intended_config()

        if not hasattr(self, "metric_reader"):
            logging.warning("metric_reader not configured; skipping runtime steering cycle")
            return {"status": "skipped", "reason": "metric_reader not configured"}

        wan_links = current_config.get("interfaces", {}).get("underlay", {}).get("wan-link", [])
        tunnels = current_config.get("overlay", {}).get("tunnel", [])

        wan_link_states = []
        for wan_link in wan_links:
            name = wan_link.get("name")
            metric = self.metric_reader.get_wan_link_metric(name)

            wan_link_states.append({
                "name": name,
                "oper-status": "down" if metric.get("stale") else "up",
                "latency-ms": metric.get("latency_ms"),
                "jitter-ms": metric.get("jitter_ms"),
                "loss-percent": metric.get("loss_percent"),
                "available-bandwidth-kbps": metric.get("available_bandwidth_kbps"),
            })

        tunnel_states = []
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
                "available-bandwidth-kbps": metric.get("available_bandwidth_kbps"),
            })

        steering_decisions = self._make_steering_decisions(
            current_config,
            wan_link_states,
            tunnel_states
        )

        execution_results = self._execute_runtime_steering_decisions(steering_decisions)

        result = {
            "wan_link_states": wan_link_states,
            "tunnel_states": tunnel_states,
            "decisions": steering_decisions,
            "execution_results": execution_results
        }

        logging.info("Runtime steering cycle completed")
        print(json.dumps(result, indent=2))

        return result

    def run_forever(self, interval_sec=5):
        while True:
            try:
                self.run_once()
            except Exception as e:
                logging.exception("Agent runtime loop failed: %s", e)

            time.sleep(interval_sec)

    def run_clixon_callback_server(self, host="0.0.0.0", port=9101):
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
                "/internal/clixon/commit-config-change",
            ]:
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
                "reason": str(e)
            }).encode("utf-8"))

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    agent = Agent()

    # This starts the internal API used by the Clixon C callback plugin.
    agent.run_clixon_callback_server()
