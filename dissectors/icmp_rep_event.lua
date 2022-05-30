-- ECHO REPLY
local data_dis = Dissector.get("data")

icmp_echo_reply = Proto("icmp_echo_reply","ICMP Echo Reply Event")

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

event_table = DissectorTable.get("rna_event")
-- Event ID may change depending on the execution... UPDATE HERE:
event_table:add(3, icmp_echo_reply)
