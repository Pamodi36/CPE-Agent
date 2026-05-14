#!/usr/bin/env python3
# coding: utf-8
import os
import copy
import json
import logging
import requests                                                                                #HTTP library used to send RESTCONF requests to the forwarder container.

logging.basicConfig(level=logging.INFO)

class SteeringManager:
    def __init__(self):
        self.base_url = os.environ.get("FORWARDER_BASE_URL", "http://vcpe-forwarder:9090")
        self.timeout = 5                                                                      #if the forwarder does not respond within 5 seconds, the request will fail.
        self.dry_run = os.environ.get("FORWARDER_DRY_RUN", "1") == "1"

        self.headers = {
            "Content-Type": "application/json",                                                #tells forwarder that the requests are sending in JSON format.
            "Accept": "application/json",                                                      #tells the forwarder to reply in JSON format.
        }

    # ============================================================
    # Public Interaction point
    # ============================================================
    def execute_decision(self, action):                                                        #main method that agent.py calls.
        action_type = action.get("action")                                                     #reads the "action" field from the incoming action dictionary from "agent.py"

        try:                                                                                   #check the action type and call the correct internal handler.

            # Configuration actions are no longer handled by SteeringManager.
            # They are handled directly by agent.py when Clixon callback sends config changes.
            if action_type in [
                "apply-wan-link-config",
                "apply-lan-link-config",
                "apply-tunnel-config",
                "apply-firewall-rule",
                "install-traffic-class",
            ]:
                return self._result_error(
                    action=action,
                    reason=f"{action_type} should be handled directly by agent.py, not SteeringManager",
                )

            if action_type == "set-active-path":
                return self._ordered_failover(action)

            if action_type == "set-load-balance-policy":
                return self._weighted_ecmp(action)

            return self._result_error(                                                        #If none of the known action types match, return an error dictionary.
                action=action,
                reason=f"Unsupported action: {action_type}",
            )

        except Exception as e:                                                                #If any unexpected Python error happens in the try block, execution jumps here.
            logging.exception("Action execution failed for %s: %s", action_type, e)
            return self._result_error(
                action=action,
                reason=str(e),
            )

    def get_nat_state_from_forwarder(self):                                                    #poll NAT status from forwarder
        url = f"{self.base_url}/api/v1/nat-state"

        response = requests.get(
            url,
            headers={"Accept": "application/json"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def store_nat_status_in_datastore(self, wan_name, nat_type):
        if not wan_name or not nat_type:
            return False

        state_dir = "/var/lib/clixon/wan-link-nat-types"                                      # directory where nat-type files will be stored
        state_file = f"{state_dir}/{wan_name}.nat"                                            # builds the filename for each wan-link

        try:
            os.makedirs(state_dir, exist_ok=True)                                             # creates the directory /var/lib/clixon/wan-link-nat-types if it does not already exist
            with open(state_file, "w") as f:
                f.write(nat_type)
            logging.info("Stored nat-type for wan link %s in runtime state file %s", wan_name, state_file)
            return True

        except Exception as e:
            logging.exception("Failed to store nat-type runtime file for %s: %s", wan_name, e)
            return False

    # ============================================================
    # Action handlers
    # ============================================================

    def _ordered_failover(self, action):
        traffic_class = action.get("traffic-class")

        if not traffic_class:
            return self._result_error(action, "Traffic class is missing")

        selected_path = action.get("selected-path")
        path_group_id = action.get("path-group-id") or f"{traffic_class}-failover"

        if not selected_path:
            return self._result_error(action, "Selected path is missing")

        members = []

        candidate_summary = action.get("candidate-summary", {})
        eligible_paths = candidate_summary.get("eligible", [])

        if not eligible_paths:
            eligible_paths = [selected_path]

        for index, path_id in enumerate(eligible_paths, start=1):
            members.append({
                "path_id": path_id,
                "priority": index * 10,
                "weight": 100,
            })

        payload = {
            "strategy": "ordered_failover",
            "active_path_id": selected_path,
            "members": members,
        }

        operation = {
            "method": "PUT",
            "path": f"/api/v1/path-groups/{path_group_id}",
            "payload": payload,
        }

        return self._send_transaction([operation], action)

    def _weighted_ecmp(self, action):
        traffic_class = action.get("traffic-class")
        eligible_paths = action.get("eligible-paths", [])

        if not traffic_class:
            return self._result_error(action, "Traffic class is missing")

        if not isinstance(eligible_paths, list):
            return self._result_error(action, "eligible-paths must be a list")

        if not eligible_paths:
            return self._result_error(action, "No eligible paths for load balancing")

        path_group_id = action.get("path-group-id") or f"{traffic_class}-ecmp"

        members = []
        for path_id in eligible_paths:
            members.append({
                "path_id": path_id,
                "priority": 10,
                "weight": 100,
            })

        payload = {
            "strategy": "weighted_ecmp",
            "members": members,
        }

        operation = {
            "method": "PUT",
            "path": f"/api/v1/path-groups/{path_group_id}",
            "payload": payload,
        }

        return self._send_transaction([operation], action)

    # ============================================================
    # Transaction sender to forwarder
    # ============================================================

    def _send_transaction(self, operations, action):                                           #common helper that sends transaction requests to forwarder
        payload = {
            "validate_only": False,
            "operations": operations,
        }

        url = f"{self.base_url}/api/v1/transactions"

        logging.info("Forwarder transaction URL: %s", url)                                     #Prints the target URL and the payload for debugging
        logging.info("Payload: %s", json.dumps(payload, indent=2))

        if self.dry_run:
            return {
                "status": "dry-run",
                "url": url,
                "payload": payload,
                "received-action": action.get("action"),
            }

        response = requests.post(                                                             #Sends the actual HTTP POST request to the forwarder.
            url,
            headers=self.headers,
            data=json.dumps(payload),
            timeout=self.timeout,
        )

        if 200 <= response.status_code < 300:
            return {
                "status": "success",
                "http-status": response.status_code,
                "response": response.json() if response.text else {},
            }

        return {
            "status": "error",
            "http-status": response.status_code,
            "response": response.text,
        }

    # ============================================================
    # Error message handler
    # ============================================================
    def _result_error(self, action, reason: str):
        return {
            "status": "error",
            "action": action.get("action"),
            "target": action.get("name") or action.get("traffic-class"),
            "reason": reason,
        }
