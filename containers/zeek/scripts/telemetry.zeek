@load base/frameworks/telemetry

function get_analyzer_kind(atype: AllAnalyzers::Tag): string {
    if (is_protocol_analyzer(atype))
        return "protocol";
    else if (is_packet_analyzer(atype))
        return "packet";
    else if (is_file_analyzer(atype))
        return "file";
    return "unknown";
}

global analyzer_violations_cf = Telemetry::register_counter_family(
    Telemetry::MetricOpts(
        $prefix = "zeek",
        $name = "analyzer_violations",
        $unit = "1",
        $help_text = "Number of analyzer violations broken down by analyzer",
        $label_names = vector("kind", "name")
    )
);

global analyzer_confirmations_cf = Telemetry::register_counter_family([
    $prefix = "zeek",
    $name = "analyzer_confirmations",
    $unit = "1",
    $help_text = "Number of analyzer confirmations broken down by analyzer",
    $label_names = vector("kind", "name")
]);

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) {
    local kind = get_analyzer_kind(atype);
    local name = to_lower(Analyzer::name(atype));
    Telemetry::counter_family_inc(analyzer_violations_cf, vector(kind, name));
}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) {
    local kind = get_analyzer_kind(atype);
    local name = to_lower(Analyzer::name(atype));
    Telemetry::counter_family_inc(analyzer_confirmations_cf, vector(kind, name));
}

module Tunnel;

global tunnels_active_size_gf = Telemetry::register_gauge_family([
    $prefix = "zeek",
    $name = "monitored_tunnels_active",
    $unit = "1",
    $help_text = "Number of currently active tunnels as tracked in Tunnel::active",
    $label_names = vector()
]);

global tunnels_active_size_gauge = Telemetry::gauge_with(tunnels_active_size_gf);

global tunnels_active_footprint_gf = Telemetry::register_gauge_family([
    $prefix = "zeek",
    $name = "monitored_tunnels_active_footprint",
    $unit = "1",
    $help_text = "Footprint of the Tunnel::active table",
    $label_names = vector()
]);

global tunnels_active_footprint_gauge = Telemetry::gauge_with(tunnels_active_footprint_gf);

hook Telemetry::sync() {
    Telemetry::gauge_set(tunnels_active_size_gauge, |Tunnel::active|);
    Telemetry::gauge_set(tunnels_active_footprint_gauge, val_footprint(Tunnel::active));
}

module Telemetry::DNS;

global dns_qdcount_hf = Telemetry::register_histogram_family([
    $prefix = "zeek",
    $name = "dns_qdcount",
    $unit = "1",
    $help_text = "DNS query count distribution",
    $bounds = vector(1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0),
    $label_names = vector()
]);

global dns_ancount_hf = Telemetry::register_histogram_family([
    $prefix = "zeek",
    $name = "dns_ancount",
    $unit = "1",
    $help_text = "DNS answer count distribution",
    $bounds = vector(1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0),
    $label_names = vector()
]);

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    Telemetry::histogram_family_observe(dns_qdcount_hf, vector(), msg$num_queries);
    Telemetry::histogram_family_observe(dns_ancount_hf, vector(), msg$num_answers);
}

module Telemetry::Conn;

global conn_history_cf = Telemetry::register_counter_family([
    $prefix = "zeek",
    $name = "monitored_connection_histories",
    $unit = "1",
    $help_text = "Summary of connection histories in monitored traffic",
    $label_names = vector("protocol", "history")
]);

event connection_state_remove(c: connection) {
    local proto = get_port_transport_proto(c$id$resp_p);
    local history = c$history;
    if (|history| > 5)
        history = fmt("%s..", history[:5]);
    Telemetry::counter_family_inc(conn_history_cf, vector("protocol", "history"));
}