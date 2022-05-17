meta.protocol_l4 = hdr.ipv4.protocol;

// Perform usual routing and forwarding.
ipv4_lpm.apply();
forward.apply();
