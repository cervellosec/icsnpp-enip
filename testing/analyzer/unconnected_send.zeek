# @TEST-EXEC: zeek -C -r ${TRACES}/unconnected_send.pcap %INPUT > output
# @TEST-EXEC: zeek -C -r ${TRACES}/ctl-unconnected-send-size.pcap %INPUT > output-bad-size
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff output-bad-size
#
# @TEST-DOC: The message inside an Unconnected Send request raises its own cip_header, after the
# Unconnected Send's (Cervello addition). The trace is part of one real TCP connection: connected
# Read Tag and Write Tag exchanges, and a Read Tag and a Write Tag each routed through an
# Unconnected Send (service 0x52 on class 0x06), whose replies come back unwrapped. In
# ctl-unconnected-send-size.pcap the first Unconnected Send's message size is set past the end of
# the packet: its message is not raised, and it and everything after it are still seen.

@load icsnpp/enip

event cip_header(c: connection, is_orig: bool, packet_correlation_id: string,
                 cip_sequence_count: count, service: count, response: bool, status: count,
                 status_extended: count, class_id: count, instance_id: count, attribute_id: count,
                 occurrence_count: count)
    {
    # 0xffffffff: the path names no class (a tag addressed by symbol).
    print fmt("cip_header %s service=0x%02x class=0x%x", response ? "response" : "request ", service,
              class_id);
    }
