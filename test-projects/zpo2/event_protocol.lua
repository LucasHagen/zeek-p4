event_table = DissectorTable.new("zpo_ip_event", "ZPO Event", uint16, base.DEC)

-- ZPO IP EVENT

zpo_ip_event = Proto("zpo_ip_event","ZPO Event Protocol")
local data_dis = Dissector.get("data")

local pkt_num = ProtoField.uint32("zpo_ip_event.pkt_num", "Packet Number", base.DEC)
local src_port = ProtoField.uint16("zpo_ip_event.src_port", "Source Port", base.DEC)
local dst_port = ProtoField.uint16("zpo_ip_event.dst_port", "Destination Port", base.DEC)
local event_type = ProtoField.uint16("zpo_ip_event.event_type", "Event Type", base.DEC)
-- 4
local ip_version = ProtoField.uint8("zpo_ip_event.ipv4_version", "IPv4 Version", base.DEC, nil, 0xF0)
-- 4
local ip_ihl = ProtoField.uint8("zpo_ip_event.ipv4_ihl", "IPv4 IHL", base.DEC, nil, 0x0F)
local ip_diffserv = ProtoField.uint8("zpo_ip_event.ipv4_diffserv", "IPv4 Diffserv", base.DEC)
local ip_len = ProtoField.uint16("zpo_ip_event.ipv4_len", "IPv4 Len", base.DEC)
local ip_id = ProtoField.uint16("zpo_ip_event.ipv4_id", "IPv4 ID", base.DEC)
-- 3
local ip_flags = ProtoField.uint8("zpo_ip_event.ipv4_flags", "IPv4 Flags", base.DEC, nil, 0xE0)
-- 13
local ip_flags_offset = ProtoField.uint16("zpo_ip_event.ipv4_flags_offset", "IPv4 Flags Offset", base.DEC, nil, 0x1FFF)
local ip_ttl = ProtoField.uint8("zpo_ip_event.ipv4_ttl", "IPv4 TTL", base.DEC)
local ip_protocol = ProtoField.uint8("zpo_ip_event.ipv4_protocol", "IPv4 Protocol", base.DEC)
local ip_hdr_checksum = ProtoField.uint16("zpo_ip_event.ipv4_hdr_checksum", "IPv4 Hdr Checksum", base.DEC)
local src_addr = ProtoField.ipv4("zpo_ip_event.src_addr", "Source IP")
local dst_addr = ProtoField.ipv4("zpo_ip_event.dst_addr", "Destination IP")

zpo_ip_event.fields = {
    pkt_num,
    src_port,
    dst_port,
    event_type,
    ip_version,
    ip_ihl,
    ip_diffserv,
    ip_len,
    ip_id,
    ip_flags,
    ip_flags_offset,
    ip_ttl,
    ip_protocol,
    ip_hdr_checksum,
    src_addr,
    dst_addr
}

-- myproto dissector function
function zpo_ip_event.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = zpo_ip_event.name

  pkt.src = buf(22,4):ipv4()
  pkt.dst = buf(26,4):ipv4()

  -- create subtree for myproto
  subtree = root:add(zpo_ip_event, buf(0))
  -- add protocol fields to subtree
  subtree:add(pkt_num, buf(0,4))
  subtree:add(src_port, buf(4,2))
  subtree:add(dst_port, buf(6,2))
  subtree:add(event_type, buf(8,2))

  subtree:add(ip_version, buf(10,1)) -- 4 bits
  subtree:add(ip_ihl, buf(10,1)) -- 4 bits
  subtree:add(ip_diffserv, buf(11,1))
  subtree:add(ip_len, buf(12,2)) -- 16 bits
  subtree:add(ip_id, buf(14,2)) -- 16 bits
  subtree:add(ip_flags, buf(16,2)) -- 16 bits
  subtree:add(ip_flags_offset, buf(16,2)) -- 16 bits
  subtree:add(ip_ttl, buf(18,1)) -- 8 bits
  subtree:add(ip_protocol, buf(19,1))
  subtree:add(ip_hdr_checksum, buf(20,2))
  subtree:add(src_addr, buf(22,4))
  subtree:add(dst_addr, buf(26,4))

  local event_dis = event_table:get_dissector(buf(8,2):uint())

  if event_dis ~= nil then
    event_dis:call(buf(30):tvb(), pkt, root)
  else
    data_dis:call(buf(30):tvb(), pkt, root)
  end
end

-- Initialization routine
function zpo_ip_event.init()
end

-- subscribe for Ethernet packets on type 26114 (0x6602).
local eth_table = DissectorTable.get("ethertype")
eth_table:add(26114, zpo_ip_event)


-- ZPO ETH EVENT

zpo_eth_event = Proto("zpo_eth_event","ZPO Event Protocol (ETH)")

local pkt_num_eth = ProtoField.uint32("zpo_eth_event.pkt_num", "Packet Number", base.DEC)
local protocol_l3_eth = ProtoField.uint16("zpo_eth_event.protocol_l3", "Protocol L3", base.HEX)
local event_type_eth = ProtoField.uint16("zpo_eth_event.event_type", "Event Type", base.DEC)

zpo_eth_event.fields = {
    pkt_num_eth,
    protocol_l3_eth,
    event_type_eth
}

-- myproto dissector function
function zpo_eth_event.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = zpo_eth_event.name

  -- create subtree for myproto
  subtree = root:add(zpo_eth_event, buf(0))
  -- add protocol fields to subtree
  subtree:add(pkt_num_eth, buf(0,4))
  subtree:add(protocol_l3_eth, buf(4,2))
  subtree:add(event_type_eth, buf(6,2))

  local event_dis = event_table:get_dissector(buf(6,2):uint())

  if event_dis ~= nil then
    event_dis:call(buf(8):tvb(), pkt, root)
  else
    data_dis:call(buf(8):tvb(), pkt, root)
  end
end

-- Initialization routine
function zpo_eth_event.init()
end

-- subscribe for Ethernet packets on type 26113 (0x6601).
eth_table:add(26113, zpo_eth_event)

---- SUB EVENTS


-- ECHO REQ


icmp_echo_req = Proto("icmp_echo_req","ICMP Echo Request")

local id_req = ProtoField.uint64("icmp_echo_req.id", "Id", base.DEC)
local seq_req = ProtoField.uint64("icmp_echo_req.seq", "Seq", base.DEC)
local v6_req = ProtoField.uint8("icmp_echo_req.v6", "Is v6", base.DEC)
local itype_req = ProtoField.uint64("icmp_echo_req.itype", "itype", base.DEC)
local icode_req = ProtoField.uint64("icmp_echo_req.icode", "icode", base.DEC)
local len_req = ProtoField.uint64("icmp_echo_req.len", "len", base.DEC)
local ttl_req = ProtoField.uint64("icmp_echo_req.ttl", "ttl", base.DEC)

icmp_echo_req.fields = {
    id_req,
    seq_req,
    v6_req,
    itype_req,
    icode_req,
    len_req,
    ttl_req
}

-- myproto dissector function
function icmp_echo_req.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = icmp_echo_req.name
  pkt.cols.info = icmp_echo_req.description

  -- create subtree for myproto
  subtree = root:add(icmp_echo_req, buf(0))
  -- add protocol fields to subtree
  subtree:add(id_req,buf(0,8))
  subtree:add(seq_req,buf(8,8))
  subtree:add(v6_req,buf(16,1))
  subtree:add(itype_req,buf(17,8))
  subtree:add(icode_req,buf(25,8))
  subtree:add(len_req,buf(33,8))
  subtree:add(ttl_req,buf(41,8))

  -- description of payload
  data_dis:call(buf(49):tvb(), pkt, root)
end

function icmp_echo_req.init()
end

event_table:add(2, icmp_echo_req)



-- ECHO REPLY


icmp_echo_reply = Proto("icmp_echo_reply","ICMP Echo Reply")

local id_reply = ProtoField.uint64("icmp_echo_reply.id", "Id", base.DEC)
local seq_reply = ProtoField.uint64("icmp_echo_reply.seq", "Seq", base.DEC)
local v6_reply = ProtoField.uint8("icmp_echo_reply.v6", "Is v6", base.DEC)
local itype_reply = ProtoField.uint64("icmp_echo_reply.itype", "itype", base.DEC)
local icode_reply = ProtoField.uint64("icmp_echo_reply.icode", "icode", base.DEC)
local len_reply = ProtoField.uint64("icmp_echo_reply.len", "len", base.DEC)
local ttl_reply = ProtoField.uint64("icmp_echo_reply.ttl", "ttl", base.DEC)

icmp_echo_reply.fields = {
    id_reply,
    seq_reply,
    v6_reply,
    itype_reply,
    icode_reply,
    len_reply,
    ttl_reply
}

-- myproto dissector function
function icmp_echo_reply.dissector (buf, pkt, root)
    -- validate packet length is adequate, otherwise quit
    if buf:len() == 0 then return end
    pkt.cols.protocol = icmp_echo_reply.name
    pkt.cols.info = icmp_echo_reply.description

    -- create subtree for myproto
    subtree = root:add(icmp_echo_reply, buf(0))
    -- add protocol fields to subtree
    subtree:add(id_reply,buf(0,8))
    subtree:add(seq_reply,buf(8,8))
    subtree:add(v6_reply,buf(16,1))
    subtree:add(itype_reply,buf(17,8))
    subtree:add(icode_reply,buf(25,8))
    subtree:add(len_reply,buf(33,8))
    subtree:add(ttl_reply,buf(41,8))

    -- description of payload
    data_dis:call(buf(49):tvb(), pkt, root)
  end


function icmp_echo_reply.init()
end

event_table:add(1, icmp_echo_reply)

-- ARP REQUEST


arp_request = Proto("arp_request","ARP Request")

local mac_src = ProtoField.ether("arp_request.mac_src", "mac_src")
local mac_dst = ProtoField.ether("arp_request.mac_dst", "mac_dst")
local src_proto_addr = ProtoField.ipv4("arp_request.src_proto_addr", "src_proto_addr")
local src_hw_addr = ProtoField.ether("arp_request.src_hw_addr", "src_hw_addr")
local target_proto_addr = ProtoField.ipv4("arp_request.target_proto_addr", "target_proto_addr")
local target_hw_addr = ProtoField.ether("arp_request.target_hw_addr", "target_hw_addr")

arp_request.fields = {
    mac_src,
    mac_dst,
    src_proto_addr,
    src_hw_addr,
    target_proto_addr,
    target_hw_addr
}

-- myproto dissector function
function arp_request.dissector (buf, pkt, root)
    -- validate packet length is adequate, otherwise quit
    if buf:len() == 0 then return end
    pkt.cols.protocol = arp_request.name
    pkt.cols.info = arp_request.description

    -- create subtree for myproto
    subtree = root:add(arp_request, buf(0))
    -- add protocol fields to subtree
    subtree:add(mac_src,buf(0,6))
    subtree:add(mac_dst,buf(6,6))
    subtree:add(src_hw_addr,buf(12,6))
    subtree:add(src_proto_addr,buf(18,4))
    subtree:add(target_hw_addr,buf(22,6))
    subtree:add(target_proto_addr,buf(28,4))

    -- description of payload
    data_dis:call(buf(32):tvb(), pkt, root)
  end


function arp_request.init()
end

event_table:add(3, arp_request)
