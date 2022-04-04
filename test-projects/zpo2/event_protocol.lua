zpo_event = Proto("zpo_event","ZPO Event Protocol")
event_table = DissectorTable.new("zpo_event", "ZPO Event", uint16, base.DEC, zpo_event)

local pkt_num = ProtoField.uint32("zpo_event.pkt_num", "Packet Number", base.DEC)
local protocol_l3 = ProtoField.uint16("zpo_event.protocol_l3", "L3 Protocol", base.HEX)
local protocol_l4 = ProtoField.uint8("zpo_event.protocol_l4", "L4 Protocol", base.HEX)
local src_addr = ProtoField.ipv4("zpo_event.src_addr", "Source IP")
local dst_addr = ProtoField.ipv4("zpo_event.dst_addr", "Destination IP")
local src_port = ProtoField.uint16("zpo_event.src_port", "Source Port", base.DEC)
local dst_port = ProtoField.uint16("zpo_event.dst_port", "Destination Port", base.DEC)
local event_type = ProtoField.uint16("zpo_event.event_type", "Event Type", base.DEC)

zpo_event.fields = {pkt_num,
                    protocol_l3,
                    protocol_l4,
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                    event_type}

-- myproto dissector function
function zpo_event.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = zpo_event.name


  -- create subtree for myproto
  subtree = root:add(zpo_event, buf(0))
  -- add protocol fields to subtree
  subtree:add(pkt_num,buf(0,4))
  subtree:add(protocol_l3,buf(4,2))
  subtree:add(protocol_l4,buf(6,1))
  subtree:add(src_addr,buf(7,4))
  pkt.src = buf(7,4):ipv4()

  subtree:add(dst_addr,buf(11,4))
  pkt.dst = buf(11,4):ipv4()

  subtree:add(src_port,buf(15,2))
  subtree:add(dst_port,buf(17,2))
  subtree:add(event_type,buf(19,2))

  local event_dis = event_table:get_dissector(buf(19,2):uint())

  if event_dis ~= nil then
    event_dis:call(buf(21):tvb(), pkt, root)
  else
    data_dis:call(buf(21):tvb(), pkt, root)
  end
end

-- Initialization routine
function zpo_event.init()
end

-- subscribe for Ethernet packets on type 5212 (0x145c).
local eth_table = DissectorTable.get("ethertype")
eth_table:add(26118, zpo_event)




---- SUB EVENTS

local data_dis = Dissector.get("data")

icmp_echo_req = Proto("icmp_echo_req","ICMP Echo Request")
icmp_echo_reply = Proto("icmp_echo_reply","ICMP Echo Reply")

local id_req = ProtoField.uint64("icmp_echo_req.id", "Id", base.DEC)
local seq_req = ProtoField.uint64("icmp_echo_req.seq", "Seq", base.DEC)
local v6_req = ProtoField.uint8("icmp_echo_req.v6", "Is v6", base.DEC)
local itype_req = ProtoField.uint64("icmp_echo_req.itype", "itype", base.DEC)
local icode_req = ProtoField.uint64("icmp_echo_req.icode", "icode", base.DEC)
local len_req = ProtoField.uint64("icmp_echo_req.len", "len", base.DEC)
local ttl_req = ProtoField.uint64("icmp_echo_req.ttl", "ttl", base.DEC)

local id_reply = ProtoField.uint64("icmp_echo_reply.id", "Id", base.DEC)
local seq_reply = ProtoField.uint64("icmp_echo_reply.seq", "Seq", base.DEC)
local v6_reply = ProtoField.uint8("icmp_echo_reply.v6", "Is v6", base.DEC)
local itype_reply = ProtoField.uint64("icmp_echo_reply.itype", "itype", base.DEC)
local icode_reply = ProtoField.uint64("icmp_echo_reply.icode", "icode", base.DEC)
local len_reply = ProtoField.uint64("icmp_echo_reply.len", "len", base.DEC)
local ttl_reply = ProtoField.uint64("icmp_echo_reply.ttl", "ttl", base.DEC)

icmp_echo_req.fields = {
    id_req,
    seq_req,
    v6_req,
    itype_req,
    icode_req,
    len_req,
    ttl_req
}
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
function icmp_echo_req.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = icmp_echo_req.name

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

-- myproto dissector function
function icmp_echo_reply.dissector (buf, pkt, root)
    -- validate packet length is adequate, otherwise quit
    if buf:len() == 0 then return end
    pkt.cols.protocol = icmp_echo_reply.name

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
event_table:add(2, icmp_echo_req)
