local event_table = DissectorTable.new("rna_event", "RNA Event", uint16, base.DEC)
local rna_table = DissectorTable.get("rna_type")
local data_dis = Dissector.get("data")

-- RNA ETH EVENT -----------------------------------------------------------------------------------

rna_eth_event = Proto("rna_eth_event", "RNA Event Protocol (Ethernet-based event)")

local eth_event_type = ProtoField.uint16("rna_eth_event.event_type", "Event Type", base.DEC)
local eth_protocol_l3 = ProtoField.uint16("rna_eth_event.protocol_l3", "Protocol L3", base.HEX)

rna_eth_event.fields = {
    eth_event_type,
    eth_protocol_l3
}

-- rna_eth_event dissector function
function rna_eth_event.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = rna_eth_event.name
  pkt.cols.info = rna_eth_event.description

  -- create subtree for rna_eth_event
  subtree = root:add(rna_eth_event, buf(0))

  -- add protocol fields to subtree
  subtree:add(eth_event_type, buf(0,2))
  subtree:add(eth_protocol_l3, buf(2,2))

  local event_dis = event_table:get_dissector(buf(0,2):uint())

  if event_dis ~= nil then
    event_dis:call(buf(4):tvb(), pkt, root)
  else
    data_dis:call(buf(4):tvb(), pkt, root)
  end
end

-- Initialization routine
function rna_eth_event.init()
end

-- subscribe for RNA packets on type 1.
rna_table:add(1, rna_eth_event)

-- RNA IPv4 EVENT ----------------------------------------------------------------------------------

rna_ipv4_event = Proto("rna_ipv4_event","RNA Event Protocol (IPv4-based event)")

local ipv4_event_type = ProtoField.uint16("rna_ipv4_event.event_type", "Event Type", base.DEC)
local ipv4_src_port = ProtoField.uint16("rna_ipv4_event.src_port", "Source Port", base.DEC)
local ipv4_dst_port = ProtoField.uint16("rna_ipv4_event.dst_port", "Destination Port", base.DEC)
-- 4
local ipv4_ip_version = ProtoField.uint8("rna_ipv4_event.ipv4_version", "IPv4 Version", base.DEC, nil, 0xF0)
-- 4
local ipv4_ip_ihl = ProtoField.uint8("rna_ipv4_event.ipv4_ihl", "IPv4 IHL", base.DEC, nil, 0x0F)
local ipv4_ip_diffserv = ProtoField.uint8("rna_ipv4_event.ipv4_diffserv", "IPv4 Diffserv", base.DEC)
local ipv4_ip_len = ProtoField.uint16("rna_ipv4_event.ipv4_len", "IPv4 Len", base.DEC)
local ipv4_ip_id = ProtoField.uint16("rna_ipv4_event.ipv4_id", "IPv4 ID", base.DEC)
-- 3
local ipv4_ip_flags = ProtoField.uint8("rna_ipv4_event.ipv4_flags", "IPv4 Flags", base.DEC, nil, 0xE0)
-- 13
local ipv4_ip_flags_offset = ProtoField.uint16("rna_ipv4_event.ipv4_flags_offset", "IPv4 Flags Offset", base.DEC, nil, 0x1FFF)
local ipv4_ip_ttl = ProtoField.uint8("rna_ipv4_event.ipv4_ttl", "IPv4 TTL", base.DEC)
local ipv4_ip_protocol = ProtoField.uint8("rna_ipv4_event.ipv4_protocol", "IPv4 Protocol", base.DEC)
local ipv4_ip_hdr_checksum = ProtoField.uint16("rna_ipv4_event.ipv4_hdr_checksum", "IPv4 Hdr Checksum", base.DEC)
local ipv4_src_addr = ProtoField.ipv4("rna_ipv4_event.src_addr", "Source IP")
local ipv4_dst_addr = ProtoField.ipv4("rna_ipv4_event.dst_addr", "Destination IP")

rna_ipv4_event.fields = {
    ipv4_event_type,
    ipv4_src_port,
    ipv4_dst_port,
    ipv4_ip_version,
    ipv4_ip_ihl,
    ipv4_ip_diffserv,
    ipv4_ip_len,
    ipv4_ip_id,
    ipv4_ip_flags,
    ipv4_ip_flags_offset,
    ipv4_ip_ttl,
    ipv4_ip_protocol,
    ipv4_ip_hdr_checksum,
    ipv4_src_addr,
    ipv4_dst_addr
}

-- rna_ipv4_event dissector function
function rna_ipv4_event.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = rna_ipv4_event.name
  pkt.cols.info = rna_ipv4_event.description

  pkt.src = buf(18,4):ipv4()
  pkt.dst = buf(22,4):ipv4()

  -- create subtree for myproto
  subtree = root:add(rna_ipv4_event, buf(0))

  -- add protocol fields to subtree
  subtree:add(ipv4_event_type, buf(0,2))
  subtree:add(ipv4_src_port, buf(2,2))
  subtree:add(ipv4_dst_port, buf(4,2))

  subtree:add(ipv4_ip_version, buf(6,1)) -- 4 bits
  subtree:add(ipv4_ip_ihl, buf(6,1)) -- 4 bits
  subtree:add(ipv4_ip_diffserv, buf(7,1)) -- 8 bits
  subtree:add(ipv4_ip_len, buf(8,2)) -- 16 bits
  subtree:add(ipv4_ip_id, buf(10,2)) -- 16 bits
  subtree:add(ipv4_ip_flags, buf(12,2)) -- 3 bits
  subtree:add(ipv4_ip_flags_offset, buf(12,2)) -- 13 bits
  subtree:add(ipv4_ip_ttl, buf(14,1)) -- 8 bits
  subtree:add(ipv4_ip_protocol, buf(15,1)) -- 8 bits
  subtree:add(ipv4_ip_hdr_checksum, buf(16,2)) -- 16 bits
  subtree:add(ipv4_src_addr, buf(18,4)) -- 32 bits
  subtree:add(ipv4_dst_addr, buf(22,4)) -- 32 bits

  local event_dis = event_table:get_dissector(buf(0,2):uint())

  if event_dis ~= nil then
    event_dis:call(buf(26):tvb(), pkt, root)
  else
    data_dis:call(buf(26):tvb(), pkt, root)
  end
end

-- Initialization routine
function rna_ipv4_event.init()
end

-- subscribe for RNA packets on type 2.
rna_table:add(2, rna_ipv4_event)


-- TODO: IPV6-based events
