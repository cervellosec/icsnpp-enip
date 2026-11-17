# @TEST-EXEC: zeek -C -r ${TRACES}/midstream_keepalive.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: A TCP connection first seen from mid-stream, whose server side starts with a 1-byte
# TCP keep-alive (Cervello addition). The stray byte must not misalign the PDU framing of that
# direction: every PDU after it, the Forward_Open reply among them, is still parsed.

@load icsnpp/enip

global pdus: table[bool] of count &default=0;

event enip_header(c: connection, is_orig: bool, packet_correlation_id: string, command: count,
                  length: count, session_handle: count, status: count, sender_context: string,
                  options: count)
    {
    ++pdus[is_orig];
    }

event forward_open_response(c: connection, is_orig: bool, packet_correlation_id: string,
                            ot_connection_id: count, to_connection_id: count,
                            connection_serial: count, originator_vendor_id: count,
                            originator_serial: count)
    {
    print fmt("forward_open_response from=%s ot=0x%08x to=0x%08x",
              is_orig ? "orig" : "resp", ot_connection_id, to_connection_id);
    }

event zeek_done()
    {
    print fmt("ENIP PDUs from orig=%d from resp=%d", pdus[T], pdus[F]);
    }
