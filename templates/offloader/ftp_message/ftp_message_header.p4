// ## Generated for client-side FTP commands.
// ##
// ## See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
// ## more information about the FTP protocol.
// ##
// ## c: The connection.
// ##
// ## command: The FTP command issued by the client (without any arguments).
// ##
// ## arg: The arguments going with the command.
// ##
// ## .. zeek:see:: ftp_reply fmt_ftp_port parse_eftp_port
// ##    parse_ftp_epsv parse_ftp_pasv parse_ftp_port
// event ftp_request%(c: connection, command: string, arg: string%);

// ## Generated for server-side FTP replies.
// ##
// ## See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
// ## more information about the FTP protocol.
// ##
// ## c: The connection.
// ##
// ## code: The numerical response code the server responded with.
// ##
// ## msg:  The textual message of the response.
// ##
// ## cont_resp: True if the reply line is tagged as being continued to the next
// ##            line. If so, further events will be raised and a handler may want
// ##            to reassemble the pieces before processing the response any
// ##            further.
// ##
// ## .. zeek:see:: ftp_request fmt_ftp_port parse_eftp_port
// ##    parse_ftp_epsv parse_ftp_pasv parse_ftp_port
// event ftp_reply%(c: connection, code: count, msg: string, cont_resp: bool%);

#define RNA_FTP_MESSAGE_REQUEST 0
#define RNA_FTP_MESSAGE_REPLY   1
#define RNA_FTP_MESSAGE_CONN  2 // both use port 21 - decide based on connection origin

header ftp_message_h {
    bit<8> type;
}
