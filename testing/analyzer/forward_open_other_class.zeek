# @TEST-EXEC: zeek -C -r ${TRACES}/ctl-forward-open-other-class.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Service 0x54 is class-specific, so a 0xD4 reply is decoded as a Forward_Open reply
# only when it answers a Connection Manager (class 0x06) request (Cervello addition). The trace
# is forward_open.pcap with the Forward_Open request addressed to class 0x64 instead: its reply
# must raise no forward_open_response, and its cip_header and everything after it are still seen.

@load icsnpp/enip

event forward_open_response(c: connection, is_orig: bool, packet_correlation_id: string,
                            ot_connection_id: count, to_connection_id: count,
                            connection_serial: count, originator_vendor_id: count,
                            originator_serial: count)
    {
    print fmt("forward_open_response ot=0x%08x to=0x%08x", ot_connection_id, to_connection_id);
    }

event cip_header(c: connection, is_orig: bool, packet_correlation_id: string,
                 cip_sequence_count: count, service: count, response: bool, status: count,
                 status_extended: count, class_id: count, instance_id: count, attribute_id: count,
                 occurrence_count: count)
    {
    print fmt("cip_header service=0x%02x response=%s class=0x%x status=0x%x", service, response,
              class_id, status);
    }
