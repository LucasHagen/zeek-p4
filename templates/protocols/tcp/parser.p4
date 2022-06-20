verify(packet.lookahead<tcp_base_h>().data_offset >= 5, error.TCP_InvalidDataOffset);
packet.extract(hdr.tcp, ((bit<32>)(packet.lookahead<tcp_base_h>().data_offset - 5)) << 5);
