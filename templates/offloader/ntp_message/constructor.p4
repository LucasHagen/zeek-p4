hdr.ntp_message.setValid();

if (hdr.udp.src_port == NTP_PORT && hdr.udp.dst_port == NTP_PORT) {
    hdr.ntp_message.type = RNA_NTP_MESSAGE_CONN;
} else if(hdr.udp.dst_port == 21) {
    hdr.ntp_message.type = RNA_NTP_MESSAGE_REQUEST;
} else if(hdr.udp.src_port == 21) {
    hdr.ntp_message.type = RNA_NTP_MESSAGE_REPLY;
}

hdr.udp.setInvalid();
hdr.ipv4.setInvalid();
