// ## Generated for each packet sent by a UDP flow's originator. This a potentially
// ## expensive event due to the volume of UDP traffic and should be used with
// ## care.
// ##
// ## u: The connection record for the corresponding UDP flow.
// ##
// ## .. zeek:see:: udp_contents udp_reply  udp_session_done
// event udp_request%(u: connection%);

// ## Generated for each packet sent by a UDP flow's responder. This a potentially
// ## expensive event due to the volume of UDP traffic and should be used with
// ## care.
// ##
// ## u: The connection record for the corresponding UDP flow.
// ##
// ## .. zeek:see:: udp_contents  udp_request udp_session_done
// event udp_reply%(u: connection%);

// TODO: support 'no-header' events
header udp_req_or_rep_event_h {
    z_bool _ignored;
}
