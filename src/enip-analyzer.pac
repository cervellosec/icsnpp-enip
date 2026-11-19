## enip-analyzer.pac
##
## Binpac Ethernet/IP (ENIP) Analyzer - Adds processing functions to ENIP_Flow to generate events.
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

%extern{
    #include <map>
    #include <sstream>
    #include <random>
    #include <tuple>
    #include <vector>
%}
%header{

    typedef struct CIP_Request_Path {
        uint32 class_id, instance_id, attribute_id;

        CIP_Request_Path(){
            class_id = UINT32_MAX;
            instance_id = UINT32_MAX;
            attribute_id = UINT32_MAX;
        }

    }CIP_Request_Path;


    uint32 get_unsigned(const_bytestring data);
    uint32 get_number(uint8 size, uint8 x, const_bytestring data);
    CIP_Request_Path parse_request_path(const_bytestring data);
    CIP_Request_Path parse_request_multiple_service_packet(const_bytestring data, uint16 starting_location);
%}

%code{

    // Get uint32 number from status_extended array
    // Cervello: the extended status is an array of little-endian 16-bit words; the first word is
    // the code Wireshark shows (e.g. 0x0107 "Connection not found"). Up to two words are packed,
    // first word in the high half.
    uint32 get_unsigned(const_bytestring data)
    {
        if(data.length() == 0)
        {
            return UINT32_MAX;
        }
        uint32 number = 0;
        for ( int32 i = 0; i + 1 < data.length() && i < 4; i += 2 ){
            number <<= 16;
            number |= data[i] | (data[i+1] << 8);
        }
        return number;
    }

    // Get uint32 number from data in request path
    // Cervello: bounds-checked, UINT32_MAX when the value does not fit in `data` (a truncated
    // or malformed path), and the 32-bit case shifts by 16, not 13.
    uint32 get_number(uint8 size, uint16 x, const_bytestring data)
    {
        int width = size == 0 ? 1 : size == 1 ? 2 : size == 2 ? 4 : 0;
        if(width == 0 || x + width > data.length())
            return UINT32_MAX;

        if(size == 0)
            return data[x];
        else if (size == 1)
            return (data[x+1] << 8) | data[x];
        else
            return (data[x+3] << 24) | (data[x+2] << 16) | (data[x+1] << 8) | data[x];
    }

    // Parse request path and return CIP_Request_Path struct
    CIP_Request_Path parse_request_path(const_bytestring data)
    {
        CIP_Request_Path request_path;

        uint16 x = 0;
        uint16 data_length = data.length();

        while( (x+1) < data_length )
        {
            if ((data[x] >> 5) == 1)
            {
                uint16 choice = (data[x] & 0x1c) >> 2;
                uint16 size = data[x] & 3;
                x += 1;
                if(size > 0)
                    x += 1;

                // Cervello: get_number returns UINT32_MAX when the value runs past the path.
                if(choice == 0)
                    request_path.class_id = get_number(size, x, data);
                else if(choice == 1)
                    request_path.instance_id = get_number(size, x, data);
                else if(choice == 4)
                    request_path.attribute_id = get_number(size, x, data);

                if(size == 0)
                    x += 1;
                else if(size == 1)
                    x += 2;
                else
                    x += 4;
            }
            else
            {
                return request_path;
            }
        }
        return request_path;
    }

    // Parse request path from multiple service packet and return CIP_Request_Path struct
    CIP_Request_Path parse_request_multiple_service_packet(const_bytestring data, uint16 starting_location)
    {
        CIP_Request_Path request_path;

        // Cervello: the path size byte must be inside `data`, and the path it announces is
        // clamped to `data`, so a malformed item cannot be read past the end.
        if(starting_location >= data.length())
            return request_path;

        uint16 x = starting_location;
        uint16 data_length = starting_location + (data[x] * 2) + 1;
        if(data_length > data.length())
            data_length = data.length();
        x += 1;

        while( (x + 1) < data_length )
        {
            if ((data[x] >> 5) == 1)
            {
                uint16 choice = (data[x] & 0x1c) >> 2;
                uint16 size = data[x] & 3;
                x += 1;
                if(size > 0)
                    x += 1;

                // Cervello: bounded by the path, not by `data`, so a value cannot be read from
                // the item's service data or the next item.
                const_bytestring path(data.begin(), data.begin() + data_length);
                if(choice == 0)
                    request_path.class_id = get_number(size, x, path);
                else if(choice == 1)
                    request_path.instance_id = get_number(size, x, path);
                else if(choice == 4)
                    request_path.attribute_id = get_number(size, x, path);

                if(size == 0)
                    x += 1;
                else if(size == 1)
                    x += 2;
                else
                    x += 4;
            }
            else
            {
                return request_path;
            }

        }
        return request_path;
    }

%}

## Cervello: Connection Manager Forward_Open / Large_Forward_Open requests awaiting their reply.
## Their reply's service code (0xD4 / 0xDB) is shared with other classes' services, so only a
## reply to one of these is decoded as a Forward_Open reply.
refine connection ENIP_Conn += {
    %member{
        uint32 pending_forward_opens_ = 0;
    %}

    function note_forward_open_request(): bool
        %{
        ++pending_forward_opens_;
        return true;
        %}

    function take_forward_open_request(): bool
        %{
        if ( pending_forward_opens_ == 0 )
            return false;

        --pending_forward_opens_;
        return true;
        %}
};

refine flow ENIP_Flow += {

    # Cervello: set while the message inside an Unconnected Send is parsed (see
    # process_unconnected_send), so that a nested one is not opened in turn.
    %member{
        bool in_unconnected_send_ = false;
    %}

    ###############################################################################################
    ############################  Process data for enip_header event  #############################
    ###############################################################################################
    function process_enip_header(enip_header: ENIP_Header): bool
        %{
            if ( ::enip_header )
            {
                zeek::BifEvent::enqueue_enip_header(connection()->zeek_analyzer(),
                                                    connection()->zeek_analyzer()->Conn(),
                                                    ${enip_header.is_originator},
                                                    zeek::make_intrusive<zeek::StringVal>(${enip_header.packet_correlation_id}),
                                                    ${enip_header.command},
                                                    ${enip_header.length},
                                                    ${enip_header.session_handle},
                                                    ${enip_header.status},
                                                    to_stringval(${enip_header.sender_context}),
                                                    ${enip_header.options});
            }
            return true;
        %}

    ###############################################################################################
    #############################  Process data for cip_header event  #############################
    ###############################################################################################
    function process_cip_header(cip_header: CIP_Header): bool
        %{
            // Cervello: remember a Connection Manager Forward_Open request (see
            // process_forward_open_response).
            if ( ${cip_header.request_or_response} == 0 &&
                 (${cip_header.service_code} == 0x54 || ${cip_header.service_code} == 0x5B) &&
                 parse_request_path(${cip_header.request_path.request_path}).class_id == 0x06 )
                connection()->note_forward_open_request();

            if ( ::cip_header )
            {
                // MULTIPLE_SERVICE CIP header data is parsed in process_multiple_service_request 
                // and process_multiple_service_response functions, so no need to duplicate
                // parsing here
                if(${cip_header.service_code} == MULTIPLE_SERVICE)
                    return true;

                uint32 status = UINT32_MAX;
                uint32 status_extended = UINT32_MAX;
                CIP_Request_Path request_path;

                if(${cip_header.request_or_response} == 1)
                {
                    status = ${cip_header.response_packet.status};
                    status_extended = get_unsigned(${cip_header.response_packet.status_extended});
                }else
                {
                    request_path = parse_request_path(${cip_header.request_path.request_path});
                }

                zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${cip_header.is_originator},
                                                   zeek::make_intrusive<zeek::StringVal>(${cip_header.packet_correlation_id}),
                                                   ${cip_header.cip_sequence_count},
                                                   ${cip_header.service_code},
                                                   (${cip_header.request_or_response} == 1),
                                                   status,
                                                   status_extended,
                                                   request_path.class_id,
                                                   request_path.instance_id,
                                                   request_path.attribute_id,
                                                   1);
            }

            // Cervello: the message an Unconnected Send routes, after the Unconnected Send's
            // own cip_header. 0x52 is class-specific (Read Tag Fragmented elsewhere).
            if ( ${cip_header.request_or_response} == 0 && ${cip_header.service_code} == 0x52 &&
                 parse_request_path(${cip_header.request_path.request_path}).class_id == 0x06 )
                process_unconnected_send(cip_header);

            return true;
        %}

    ###############################################################################################
    ##########  Cervello: parse the message inside an Unconnected Send request  ###################
    ###############################################################################################
    function process_unconnected_send(cip_header: CIP_Header): bool
        %{
            // Unconnected Send (CIP Vol.1 3-5.5.3) is how a client reaches a module behind the
            // one it talks to: priority/tick (1), timeout ticks (1), message size (2), the
            // message, a pad byte when the size is odd, then the route path. The reply comes
            // back unwrapped, as the reply of the message. The message is a whole CIP request,
            // so it is parsed as one and raises the events any request does. It cannot break the
            // packet around it: a size that does not fit is left alone, and a message that does
            // not parse is dropped.
            const_bytestring body = ${cip_header.other};
            if ( in_unconnected_send_ || body.length() < 4 )
                return true;

            int message_size = body[2] | (body[3] << 8);
            if ( message_size < 2 || 4 + message_size > body.length() )
                return true;

            in_unconnected_send_ = true;
            CIP_Header* message = new CIP_Header(${cip_header.is_originator},
                                                 ${cip_header.cip_sequence_count},
                                                 ${cip_header.packet_correlation_id});
            try
            {
                ContextENIP context(connection(), this);
                message->Parse(body.begin() + 4, body.begin() + 4 + message_size, &context);
            }
            catch ( const binpac::Exception& )
            {
            }
            delete message;
            in_unconnected_send_ = false;

            return true;
        %}

    ###############################################################################################
    ###############################  Process data for cip_io event  ###############################
    ###############################################################################################
    function process_cip_io(cip_io_item: CIP_IO): bool
        %{
            if ( ::cip_io )
            {
                zeek::BifEvent::enqueue_cip_io(connection()->zeek_analyzer(),
                                               connection()->zeek_analyzer()->Conn(),
                                               ${cip_io_item.is_originator},
                                               zeek::make_intrusive<zeek::StringVal>(${cip_io_item.packet_correlation_id}),
                                               ${cip_io_item.sequenced_address_item.connection_identifier},
                                               ${cip_io_item.sequenced_address_item.encap_sequence_number},
                                               ${cip_io_item.connected_data_length},
                                               to_stringval(${cip_io_item.connected_data_item}));
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cip_identity event  ############################
    ###############################################################################################
    function process_cip_identity_item(identity_item: CIP_Identity_Item): bool
        %{
            if ( ::cip_identity )
            {
                zeek::BifEvent::enqueue_cip_identity(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     ${identity_item.is_originator},
                                                     zeek::make_intrusive<zeek::StringVal>(${identity_item.packet_correlation_id}),
                                                     ${identity_item.encapsulation_version},
                                                     ${identity_item.socket_address.sin_addr},
                                                     ${identity_item.socket_address.sin_port},
                                                     ${identity_item.vendor_id},
                                                     ${identity_item.device_type},
                                                     ${identity_item.product_code},
                                                     ${identity_item.revision_major},
                                                     ${identity_item.revision_minor},
                                                     ${identity_item.status},
                                                     ${identity_item.serial_number},
                                                     to_stringval(${identity_item.product_name}),
                                                     ${identity_item.state});
            }
            return true;
        %}

    ###############################################################################################
    ##########################  Process data for register_session event  ##########################
    ###############################################################################################
    function process_register_session(message: Register_Session): bool
        %{
            if ( ::register_session )
            {
                zeek::BifEvent::enqueue_register_session(connection()->zeek_analyzer(),
                                                         connection()->zeek_analyzer()->Conn(),
                                                         ${message.is_originator},
                                                         ${message.protocol_version},
                                                         ${message.options_flags});
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cip_security event  ############################
    ###############################################################################################
    function process_cip_security_item(security_item: CIP_Security_Item): bool
        %{
            if ( ::cip_security )
            {
                zeek::BifEvent::enqueue_cip_security(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     ${security_item.is_originator},
                                                     ${security_item.security_profile},
                                                     ${security_item.cip_security_state},
                                                     ${security_item.enip_security_state},
                                                     ${security_item.iana_port_state});
            }
            return true;
        %}

    ###############################################################################################
    ##########################  Process data for enip_capability event  ###########################
    ###############################################################################################
    function process_enip_capability_item(enip_item: ENIP_Capability_Item): bool
        %{
            if ( ::enip_capability )
            {
                zeek::BifEvent::enqueue_enip_capability(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        ${enip_item.is_originator},
                                                        ${enip_item.enip_profile});
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for enip_service event  ############################
    ###############################################################################################
    function process_service_item(service_item: Service_Item): bool
        %{
            if ( ::enip_service )
            {
                zeek::BifEvent::enqueue_enip_service(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     ${service_item.is_originator},
                                                     ${service_item.protocol_version},
                                                     ${service_item.capability_flags},
                                                     to_stringval(${service_item.service_name}));
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for connected_address event  ##########################
    ###############################################################################################
    function process_connected_address_item(address_item: Connected_Address_Item): bool
        %{
            if ( ::connected_address )
            {
                zeek::BifEvent::enqueue_connected_address(connection()->zeek_analyzer(),
                                                          connection()->zeek_analyzer()->Conn(),
                                                          ${address_item.is_originator},
                                                          ${address_item.connection_identifier});
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for sequenced_address event  ##########################
    ###############################################################################################
    function process_sequenced_address_item(address_item: Sequenced_Address_Item): bool
        %{
            if ( ::sequenced_address )
            {
                zeek::BifEvent::enqueue_sequenced_address(connection()->zeek_analyzer(),
                                                          connection()->zeek_analyzer()->Conn(),
                                                          ${address_item.is_originator},
                                                          ${address_item.connection_identifier},
                                                          ${address_item.encap_sequence_number});
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for unconnected_message_dtls event  ######################
    ###############################################################################################
    function process_unconnected_message_dtls(message: Unconnected_Message_DTLS): bool
        %{
            if ( ::unconnected_message_dtls )
            {
                zeek::BifEvent::enqueue_unconnected_message_dtls(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 ${message.is_originator},
                                                                 ${message.unconn_message_type},
                                                                 ${message.transaction_number},
                                                                 ${message.status});
            }
            return true;
        %}

    ###############################################################################################
    ########################  Process data for socket_address_info event  #########################
    ###############################################################################################
    function process_socket_address_info(item: Socket_Address_Info_Item): bool
        %{
            if ( ::socket_address_info )
            {
                zeek::BifEvent::enqueue_socket_address_info(connection()->zeek_analyzer(),
                                                            connection()->zeek_analyzer()->Conn(),
                                                            ${item.is_originator},
                                                            ${item.sin_addr},
                                                            ${item.sin_port});
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for get_attribute_all_response event  #####################
    ###############################################################################################
    function process_get_attribute_all_response(data: Get_Attributes_All_Response): bool
        %{
            if ( ::get_attribute_all_response )
            {
                zeek::BifEvent::enqueue_get_attribute_all_response(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   ${data.is_originator},
                                                                   to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for set_attribute_all_request event  ######################
    ###############################################################################################
    function process_set_attribute_all_request(data: Set_Attributes_All_Request): bool
        %{
            if ( ::set_attribute_all_request )
            {
                zeek::BifEvent::enqueue_set_attribute_all_request(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  ${data.is_originator},
                                                                  to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for get_attribute_list_request event  #####################
    ###############################################################################################
    function process_get_attribute_list_request(data: Get_Attribute_List_Request): bool
        %{
            if ( ::get_attribute_list_request )
            {
                string attribute_ids = zeek::util::fmt("%d",${data.attribute_list[0]});

                for(uint8 i=1; i<${data.attribute_count};i++)
                    attribute_ids += zeek::util::fmt(",%d",${data.attribute_list[i]});

                zeek::BifEvent::enqueue_get_attribute_list_request(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   ${data.is_originator},
                                                                   ${data.attribute_count},
                                                                   zeek::make_intrusive<zeek::StringVal>(attribute_ids));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for get_attribute_list_response event  #####################
    ###############################################################################################
    function process_get_attribute_list_response(data: Get_Attribute_List_Response): bool
        %{
            if ( ::get_attribute_list_response )
            {
                zeek::BifEvent::enqueue_get_attribute_list_response(connection()->zeek_analyzer(),
                                                                    connection()->zeek_analyzer()->Conn(),
                                                                    ${data.is_originator},
                                                                    ${data.attribute_count},
                                                                    to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for set_attribute_list_request event  #####################
    ###############################################################################################
    function process_set_attribute_list_request(data: Set_Attribute_List_Request): bool
        %{
            if ( ::set_attribute_list_request )
            {
                zeek::BifEvent::enqueue_set_attribute_list_request(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   ${data.is_originator},
                                                                   ${data.attribute_count},
                                                                   to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for set_attribute_list_response event  #####################
    ###############################################################################################
    function process_set_attribute_list_response(data: Set_Attribute_List_Response): bool
        %{
            if ( ::set_attribute_list_response )
            {
                zeek::BifEvent::enqueue_set_attribute_list_response(connection()->zeek_analyzer(),
                                                                    connection()->zeek_analyzer()->Conn(),
                                                                    ${data.is_originator},
                                                                    ${data.attribute_count},
                                                                    to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ##########  Cervello: one event per item of a Multiple Service Packet, in packet order  ########
    ###############################################################################################
    ## The cip_header events for the items are aggregated by service and path (requests) or service
    ## and status (responses), which loses the order a reply item is matched to its request by: item
    ## i of the reply answers item i of the request. These keep the order and hand out the reply
    ## data. Item i spans services[offset_i - header : offset_i+1 - header), header being the count
    ## and offset list. Raised only when a handler exists.
    function emit_multiple_service_request_items(data: Multiple_Service_Packet_Request): bool
        %{
            if ( ! ::multiple_service_request_item )
                return true;

            const_bytestring services = ${data.services};
            uint16 service_count = ${data.service_count};
            int header_size = 2 * service_count + 2;

            for ( uint16 i = 0; i < service_count; i++ )
            {
                int start = ${data.service_offsets[i]} - header_size;
                int end = (i + 1 < service_count) ? ${data.service_offsets[i + 1]} - header_size : services.length();
                // Request item: service, path size, path, data. Offsets must be increasing.
                if ( start < 0 || start + 2 > end || end > services.length() )
                    break;

                uint8 service_code = services[start] & 0x7f;
                // The path is parsed within this item only, so a malformed path size cannot read
                // the next item's bytes as this one's class, instance or attribute.
                CIP_Request_Path path = parse_request_multiple_service_packet(
                    const_bytestring(services.begin(), services.begin() + end), start + 1);

                zeek::BifEvent::enqueue_multiple_service_request_item(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      ${data.is_originator},
                                                                      zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                                      ${data.cip_sequence_count},
                                                                      i,
                                                                      service_code,
                                                                      path.class_id,
                                                                      path.instance_id,
                                                                      path.attribute_id);
            }
            return true;
        %}

    function emit_multiple_service_response_items(data: Multiple_Service_Packet_Response): bool
        %{
            if ( ! ::multiple_service_response_item )
                return true;

            const_bytestring services = ${data.services};
            uint16 service_count = ${data.service_count};
            int header_size = 2 * service_count + 2;

            for ( uint16 i = 0; i < service_count; i++ )
            {
                int start = ${data.service_offsets[i]} - header_size;
                int end = (i + 1 < service_count) ? ${data.service_offsets[i + 1]} - header_size : services.length();
                // Reply item: service, reserved, general status, additional status size (in
                // words), additional status, data. Offsets must be increasing.
                if ( start < 0 || start + 4 > end || end > services.length() )
                    break;

                uint8 service_code = services[start] & 0x7f;
                uint8 status = services[start + 2];
                int data_start = start + 4 + 2 * services[start + 3];
                if ( data_start > end )
                    break;

                zeek::BifEvent::enqueue_multiple_service_response_item(connection()->zeek_analyzer(),
                                                                       connection()->zeek_analyzer()->Conn(),
                                                                       ${data.is_originator},
                                                                       zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                                       ${data.cip_sequence_count},
                                                                       i,
                                                                       service_code,
                                                                       status,
                                                                       to_stringval(const_bytestring(services.begin() + data_start, services.begin() + end)));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for multiple_service_request event  ######################
    ###############################################################################################
    function process_multiple_service_request(data: Multiple_Service_Packet_Request): bool
        %{
            emit_multiple_service_request_items(data);  // Cervello

            if ( ::cip_header )
            {
                uint16 service_packet_location;

                uint8 service_count = ${data.service_count};
                uint16 cip_sequence_count = ${data.cip_sequence_count};
                CIP_Request_Path request_path = parse_request_path(${data.request_path.request_path});

                struct Aggregated_Request {
                    uint8 service_code;
                    CIP_Request_Path request_path;
                    uint64 occurrence_count;
                };

                typedef std::tuple<uint8, uint32, uint32, uint32> Request_Key;
                std::map<Request_Key, size_t> seen_requests;
                std::vector<Aggregated_Request> unique_requests;

                // CIP Header event for multiple service packet
                zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${data.is_originator},
                                                   zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                   ${data.cip_sequence_count},
                                                   MULTIPLE_SERVICE,
                                                   false,
                                                   UINT32_MAX,
                                                   UINT32_MAX,
                                                   request_path.class_id,
                                                   request_path.instance_id,
                                                   request_path.attribute_id,
                                                   1);

                // Build comma-separated list of service codes and generate CIP Header events for each
                string service_list = "";
                for(uint8 i=0; i < service_count;i++)
                {
                    // Cervello: an offset before the item list or past the data is malformed.
                    int location = ${data.service_offsets[i]} - (2*service_count) - 2;
                    if ( location < 0 || location + 1 >= ${data.services}.length() )
                        break;
                    service_packet_location = location;
                    uint8 service_code = ${data.services[service_packet_location]} & 0x7f;

                    // append to list
                    if(i == 0)
                        service_list = zeek::util::fmt("%d", service_code);
                    else
                        service_list += zeek::util::fmt(",%d", service_code);

                    // Cervello: parse the path within this item only (it ends at the next offset).
                    int item_end = ${data.services}.length();
                    if ( i + 1 < service_count )
                    {
                        int next = ${data.service_offsets[i + 1]} - (2*service_count) - 2;
                        if ( next > location && next < item_end )
                            item_end = next;
                    }
                    request_path = parse_request_multiple_service_packet(
                        const_bytestring(${data.services}.begin(), ${data.services}.begin() + item_end),
                        service_packet_location+1);
                    Request_Key key = std::make_tuple(service_code,
                                                      request_path.class_id,
                                                      request_path.instance_id,
                                                      request_path.attribute_id);
                    std::map<Request_Key, size_t>::iterator existing = seen_requests.find(key);

                    if ( existing == seen_requests.end() )
                    {
                        seen_requests[key] = unique_requests.size();
                        Aggregated_Request request = {service_code, request_path, 1};
                        unique_requests.push_back(request);
                    }
                    else
                        ++unique_requests[existing->second].occurrence_count;
                }

                // Enqueue one CIP header per unique inner service, preserving first-seen order.
                for ( std::vector<Aggregated_Request>::const_iterator it = unique_requests.begin();
                      it != unique_requests.end(); ++it )
                {
                    zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       ${data.is_originator},
                                                       zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                       cip_sequence_count,
                                                       it->service_code,
                                                       false,
                                                       UINT32_MAX,
                                                       UINT32_MAX,
                                                       it->request_path.class_id,
                                                       it->request_path.instance_id,
                                                       it->request_path.attribute_id,
                                                       it->occurrence_count);
                }

                // Emit multiple_service_request event itself
                if ( ::multiple_service_request )
                {
                    zeek::BifEvent::enqueue_multiple_service_request(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      ${data.is_originator},
                                                                      service_count,
                                                                      zeek::make_intrusive<zeek::StringVal>(service_list));
                }
            }

            return true;
        %}

    ###############################################################################################
    #####################  Process data for multiple_service_response event  ######################
    ###############################################################################################
    function process_multiple_service_response(data: Multiple_Service_Packet_Response): bool
        %{
            emit_multiple_service_response_items(data);  // Cervello

            if ( ::cip_header )
            {
                CIP_Request_Path request_path;
                uint16 service_packet_location;
                
                uint8 service_count = ${data.service_count};
                uint16 cip_sequence_count = ${data.cip_sequence_count};

                struct Aggregated_Response {
                    uint8 service_code;
                    uint8 status;
                    uint64 occurrence_count;
                };

                typedef std::tuple<uint8, uint8> Response_Key;
                std::map<Response_Key, size_t> seen_responses;
                std::vector<Aggregated_Response> unique_responses;

                // CIP Header event for multiple service packet
                zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${data.is_originator},
                                                   zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                   ${data.cip_sequence_count},
                                                   MULTIPLE_SERVICE,
                                                   true,
                                                   ${data.status},
                                                   get_unsigned(${data.status_extended}),
                                                   request_path.class_id,
                                                   request_path.instance_id,
                                                   request_path.attribute_id,
                                                   1);

                // Build comma-separated list of service codes and generate CIP Header events for each
                string service_list = "";
                for(uint8 i=0; i < service_count;i++)
                {
                    // Cervello: an offset before the item list or past the status byte is malformed.
                    int location = ${data.service_offsets[i]} - (2*service_count) - 2;
                    if ( location < 0 || location + 2 >= ${data.services}.length() )
                        break;
                    service_packet_location = location;
                    uint8 service_code = ${data.services[service_packet_location]} & 0x7f;

                    // append to list
                    if(i == 0)
                        service_list = zeek::util::fmt("%d", service_code);
                    else
                        service_list += zeek::util::fmt(",%d", service_code);

                    uint8 status = ${data.services[service_packet_location + 2]};
                    Response_Key key = std::make_tuple(service_code, status);
                    std::map<Response_Key, size_t>::iterator existing = seen_responses.find(key);

                    if ( existing == seen_responses.end() )
                    {
                        seen_responses[key] = unique_responses.size();
                        Aggregated_Response response = {service_code, status, 1};
                        unique_responses.push_back(response);
                    }
                    else
                        ++unique_responses[existing->second].occurrence_count;
                }

                // Enqueue one CIP header per unique inner service, preserving first-seen order.
                for ( std::vector<Aggregated_Response>::const_iterator it = unique_responses.begin();
                      it != unique_responses.end(); ++it )
                {
                    zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       ${data.is_originator},
                                                       zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                       cip_sequence_count,
                                                       it->service_code,
                                                       true,
                                                       it->status,
                                                       UINT32_MAX,
                                                       request_path.class_id,
                                                       request_path.instance_id,
                                                       request_path.attribute_id,
                                                       it->occurrence_count);
                }

                // Emit multiple_service_response event itself
                if ( ::multiple_service_response )
                {
                    zeek::BifEvent::enqueue_multiple_service_response(connection()->zeek_analyzer(),
                                                                       connection()->zeek_analyzer()->Conn(),
                                                                       ${data.is_originator},
                                                                       service_count,
                                                                       zeek::make_intrusive<zeek::StringVal>(service_list));
                }
            }
            return true;
        %}

    ###############################################################################################
    ###################  Process data for get_attribute_single_response event  ####################
    ###############################################################################################
    function process_get_attribute_single_response(data: Get_Attribute_Single_Response): bool
        %{
            if ( ::get_attribute_single_response )
            {
                zeek::BifEvent::enqueue_get_attribute_single_response(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      ${data.is_originator},
                                                                      to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for set_attribute_single_request event  ####################
    ###############################################################################################
    function process_set_attribute_single_request(data: Set_Attribute_Single_Request): bool
        %{
            if ( ::set_attribute_single_request )
            {
                zeek::BifEvent::enqueue_set_attribute_single_request(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     ${data.is_originator},
                                                                     to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ##############  Cervello: process data for forward_open_response event  #######################
    ###############################################################################################
    function process_forward_open_response(data: Forward_Open_Response): bool
        %{
            // Every reply to 0x54 / 0x5B takes one pending Connection Manager request, decoded
            // or not, so a failed reply does not leave its request pending.
            if ( ! connection()->take_forward_open_request() )
                return true;

            // A successful reply's fixed part is 26 bytes (see Forward_Open_Response).
            const_bytestring reply = ${data.reply};
            if ( ${data.status} != 0 || reply.length() < 26 || ! ::forward_open_response )
                return true;

            auto u16 = [&](int o) -> uint32 { return reply[o] | (reply[o + 1] << 8); };
            auto u32 = [&](int o) -> uint32 { return u16(o) | (u16(o + 2) << 16); };

            zeek::BifEvent::enqueue_forward_open_response(connection()->zeek_analyzer(),
                                                          connection()->zeek_analyzer()->Conn(),
                                                          ${data.is_originator},
                                                          zeek::make_intrusive<zeek::StringVal>(${data.packet_correlation_id}),
                                                          u32(0),     // O->T connection ID
                                                          u32(4),     // T->O connection ID
                                                          u16(8),     // connection serial
                                                          u16(10),    // originator vendor ID
                                                          u32(12));   // originator serial
            return true;
        %}
};
