# @TEST-EXEC: zeek -C -r ${TRACES}/multiple_service_packet_cip.pcapng %INPUT > output
# @TEST-EXEC: zeek -r ${TRACES}/multiple_service_items.pcap %INPUT >> output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Per-item Multiple Service Packet events, in packet order (Cervello addition). The
# first trace is upstream's 11-item request; the second is a real request/reply pair whose six
# items include a Get_Attributes_All, so reply item i carries the data answering request item i.

@load icsnpp/enip

event multiple_service_request_item(c: connection, is_orig: bool, packet_correlation_id: string,
                                    cip_sequence_count: count, index: count, service: count,
                                    class_id: count, instance_id: count, attribute_id: count)
    {
    print fmt("request  item %d: service=0x%02x class=0x%x instance=0x%x attribute=0x%x seq=%d",
              index, service, class_id, instance_id, attribute_id, cip_sequence_count);
    }

event multiple_service_response_item(c: connection, is_orig: bool, packet_correlation_id: string,
                                     cip_sequence_count: count, index: count, service: count,
                                     status: count, data: string)
    {
    print fmt("response item %d: service=0x%02x status=0x%02x data=%s seq=%d",
              index, service, status, bytestring_to_hexstr(data), cip_sequence_count);
    }
