# @TEST-EXEC: zeek -r ${TRACES}/forward_open.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: forward_open_response on a successful Forward_Open reply (Cervello addition). The
# trace is one real TCP connection: RegisterSession, a failed Forward_Close, a Forward_Open and
# its reply, three connected Read Tag exchanges, a Forward_Close.

@load icsnpp/enip

event forward_open_response(c: connection, is_orig: bool, packet_correlation_id: string,
                            ot_connection_id: count, to_connection_id: count,
                            connection_serial: count, originator_vendor_id: count,
                            originator_serial: count)
    {
    print fmt("forward_open_response from=%s ot=0x%08x to=0x%08x serial=0x%04x vendor=%d originator_serial=0x%08x",
              is_orig ? "orig" : "resp", ot_connection_id, to_connection_id, connection_serial,
              originator_vendor_id, originator_serial);
    }
