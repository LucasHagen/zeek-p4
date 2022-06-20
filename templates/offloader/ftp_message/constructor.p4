hdr.ftp_message.setValid();

if (hdr.tcp.src_port == 21 && hdr.tcp.dst_port == 21) {
    hdr.ftp_message.type = RNA_FTP_MESSAGE_CONN;
} else if(hdr.tcp.dst_port == 21) {
    hdr.ftp_message.type = RNA_FTP_MESSAGE_REQUEST;
} else if(hdr.tcp.src_port == 21) {
    hdr.ftp_message.type = RNA_FTP_MESSAGE_REPLY;
}

hdr.tcp.setInvalid();
hdr.ipv4.setInvalid();
