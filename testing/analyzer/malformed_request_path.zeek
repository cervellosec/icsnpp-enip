# @TEST-EXEC: zeek -C -r ${TRACES}/ctl-truncated-path.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Request paths that end inside a logical segment must not be read past their end
# (Cervello addition). The trace is forward_open.pcap with the Connection Manager requests' path
# "class 0x06, instance 1" (20 06 24 01) changed to "class 0x06, <16-bit class segment with no
# value>" (20 06 21 00): the parser used to read the value from the bytes after the path.

@load icsnpp/enip

event cip_header(c: connection, is_orig: bool, packet_correlation_id: string,
                 cip_sequence_count: count, service: count, response: bool, status: count,
                 status_extended: count, class_id: count, instance_id: count, attribute_id: count,
                 occurrence_count: count)
    {
    if ( response )
        return;

    print fmt("request service=0x%02x class=0x%x instance=0x%x attribute=0x%x",
              service, class_id, instance_id, attribute_id);
    }
