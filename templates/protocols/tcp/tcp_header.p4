#define IPPROTO_TCP 6

error {
    TCP_InvalidDataOffset
}

struct tcp_flags_t {
    bit<1> URG; // Urgent Pointer field significant
    bit<1> ACK; // Acknowledgment field significant
    bit<1> PSH; // Push Function
    bit<1> RST; // Reset the connection
    bit<1> SYN; // Synchronize sequence numbers
    bit<1> FIN; // No more data from sender
}

header tcp_base_h {
    bit<16>     src_port;
    bit<16>     dst_port;
    bit<32>     seq_no;
    bit<32>     ack_no;
    bit<4>      data_offset;
    bit<6>      res;
    tcp_flags_t flags;
    bit<16>     window;
    bit<16>     checksum;
    bit<16>     urgent_ptr;
}

header tcp_h {
    bit<16>     src_port;
    bit<16>     dst_port;
    bit<32>     seq_no;
    bit<32>     ack_no;
    bit<4>      data_offset;
    bit<6>      res;
    tcp_flags_t flags;
    bit<16>     window;
    bit<16>     checksum;
    bit<16>     urgent_ptr;
    varbit<320> options;
}
