    # =====================================================================================
    # Monitoring manager helpers
    # =====================================================================================
    def _start_monitoring_for_object(self, object_type, parent_dict):                     # called after Clixon commit to start/update monitoring
        if not hasattr(self, "monitoring_manager"):                                       # check whether MonitoringManager is enabled
            logging.warning("monitoring_manager not configured")                          # log warning if not configured
            return                                                                        # stop without failing the agent

        try:                                                                              # protect callback path from monitoring API errors
            if object_type == "class":                                                    # traffic class means underlay flow monitoring
                class_name = parent_dict.get("name")                                      # read traffic class name from YANG object
                if not class_name:                                                        # traffic class must have a name
                    logging.warning("Cannot start monitoring: traffic class has no name")  # log missing class name
                    return                                                                # stop this monitoring request

                flow_id = self.flow_id_fwmarks.get(class_name)                            # get fwmark returned by forwarder and use it as flow_id

                if flow_id is None:                                                       # if forwarder has not returned fwmark yet
                    logging.warning(                                                      # log why monitoring cannot start
                        "Cannot start monitoring for traffic class %s because fwmark/flow_id is not available yet",
                        class_name
                    )
                    return                                                                # do not send incomplete monitoring request

                payload = self.monitoring_manager.start_underlay_flow_monitoring(          # send minimal flow monitor request
                    traffic_class=parent_dict,                                             # full object used only inside MonitoringManager
                    flow_id=flow_id                                                        # fwmark used as underlay flow_id
                )

                logging.info("Started flow monitoring for class=%s payload=%s", class_name, payload) # log successful start

            elif object_type == "tunnel":                                                  # tunnel means overlay tunnel monitoring
                payload = self.monitoring_manager.start_overlay_tunnel_monitoring(parent_dict) # send minimal tunnel monitor request
                logging.info("Started tunnel monitoring payload=%s", payload)              # log successful start

        except Exception as e:                                                             # catch API/validation errors
            logging.exception(                                                             # log full error with object
                "Failed to start monitoring for object_type=%s object=%s: %s",
                object_type,
                parent_dict,
                e
            )

    def _stop_monitoring_for_object(self, object_type, parent_dict):                      # called after Clixon commit to stop monitoring
        if not hasattr(self, "monitoring_manager"):                                       # check whether MonitoringManager is enabled
            logging.warning("monitoring_manager not configured")                          # log warning if not configured
            return                                                                        # stop without failing the agent

        try:                                                                              # protect callback path from monitoring API errors
            if object_type == "class":                                                    # deleted traffic class means stop underlay flow monitor
                class_name = parent_dict.get("name")                                      # read traffic class name
                if not class_name:                                                        # class name is required to find fwmark
                    logging.warning("Cannot stop monitoring: traffic class has no name")   # log missing name
                    return                                                                # stop this request

                flow_id = self.flow_id_fwmarks.get(class_name)                            # get fwmark/flow_id for this traffic class

                if flow_id is None:                                                       # if fwmark is unavailable
                    logging.warning(                                                      # log why stop cannot be sent
                        "Cannot stop monitoring for traffic class %s because fwmark/flow_id is not available",
                        class_name
                    )
                    return                                                                # stop without sending bad DELETE

                self.monitoring_manager.stop_underlay_flow_monitoring(flow_id)             # send DELETE for flow monitor
                self.flow_id_fwmarks.pop(class_name, None)                                # remove cached fwmark after stopping monitor

                logging.info("Stopped flow monitoring for class=%s flow_id=%s", class_name, flow_id) # log stop success

            elif object_type == "tunnel":                                                  # deleted tunnel means stop overlay tunnel monitor
                tunnel_id = parent_dict.get("name")                                       # YANG tunnel name is tunnel_id
                if not tunnel_id:                                                         # tunnel_id is required
                    logging.warning("Cannot stop monitoring: tunnel has no name")          # log missing tunnel ID
                    return                                                                # stop this request

                self.monitoring_manager.stop_overlay_tunnel_monitoring(tunnel_id)          # send DELETE for tunnel monitor
                logging.info("Stopped tunnel monitoring for tunnel_id=%s", tunnel_id)      # log stop success

        except Exception as e:                                                             # catch API/validation errors
            logging.exception(                                                             # log full error with object
                "Failed to stop monitoring for object_type=%s object=%s: %s",
                object_type,
                parent_dict,
                e
            )
