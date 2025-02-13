@load protocols/conn/known-hosts
@load protocols/modbus/known-masters-slaves
@load protocols/conn/known-services
@load base/frameworks/telemetry
@load base/frameworks/logging
@load ./scripts/telemetry
@load misc/loaded-scripts
@load misc/stats
@load base/frameworks/signatures

redef Telemetry::metrics_port = 9911/tcp;
redef LogAscii::use_json = T;
redef signature_files += "signatures/modbus.sig";

# MDNS can cause a lot more queries than the default 25.
# redef dns_max_queries = 100;