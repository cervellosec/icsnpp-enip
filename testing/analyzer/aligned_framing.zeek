# @TEST-EXEC: zeek -C -r ${TRACES}/ctl-nonzero-options.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Once a direction's framing is aligned, the length field frames every PDU, whatever
# its header looks like (Cervello addition). The trace is forward_open.pcap with the options word
# of one Read Tag request set to 1, which the header-plausibility scan rejects: the PDU and the
# ones after it must still be parsed, as in forward_open.pcap.

@load icsnpp/enip

global pdus: table[bool] of count &default=0;

event enip_header(c: connection, is_orig: bool, packet_correlation_id: string, command: count,
                  length: count, session_handle: count, status: count, sender_context: string,
                  options: count)
    {
    ++pdus[is_orig];
    if ( options != 0 )
        print fmt("PDU with options=%d parsed: command=0x%02x", options, command);
    }

event zeek_done()
    {
    print fmt("ENIP PDUs from orig=%d from resp=%d", pdus[T], pdus[F]);
    }
