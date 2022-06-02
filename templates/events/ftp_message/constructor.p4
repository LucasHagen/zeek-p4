hdr.ftp_message_event.setValid();

if (hdr.tcp.src_port == 21 && hdr.tcp.dst_port == 21) {
    hdr.ftp_message_event.type = RNA_FTP_MESSAGE_CONN;
} else if(hdr.tcp.dst_port == 21) {
    hdr.ftp_message_event.type = RNA_FTP_MESSAGE_REPLY;
} else if(hdr.tcp.src_port == 21) {
    hdr.ftp_message_event.type = RNA_FTP_MESSAGE_REQ;
}

hdr.tcp.setInvalid();
hdr.ipv4.setInvalid();
