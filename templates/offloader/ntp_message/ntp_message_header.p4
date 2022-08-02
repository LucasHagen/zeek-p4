#define NTP_PORT 123

#define RNA_NTP_MESSAGE_REQUEST 0
#define RNA_NTP_MESSAGE_REPLY   1
#define RNA_NTP_MESSAGE_CONN    2 // both use port 123 - decide based on connection origin

header ntp_message_h {
    bit<8> type;
}
