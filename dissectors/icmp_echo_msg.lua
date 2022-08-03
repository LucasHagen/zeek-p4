-- ICMP ECHO MESSAGE
local data_dis = Dissector.get("data")

icmp_echo_msg = Proto("icmp_echo_msg","ICMP Echo Message")

local id = ProtoField.uint64("icmp_echo_msg.id", "Id", base.DEC)
local seq = ProtoField.uint64("icmp_echo_msg.seq", "Seq", base.DEC)
local itype = ProtoField.uint64("icmp_echo_msg.itype", "itype", base.DEC)
local icode = ProtoField.uint64("icmp_echo_msg.icode", "icode", base.DEC)
local len = ProtoField.uint64("icmp_echo_msg.len", "len", base.DEC)
local ttl = ProtoField.uint64("icmp_echo_msg.ttl", "ttl", base.DEC)

icmp_echo_msg.fields = {
    id,
    seq,
    itype,
    icode,
    len,
    ttl
}

-- myproto dissector function
function icmp_echo_msg.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = icmp_echo_msg.name
  pkt.cols.info = icmp_echo_msg.description

  -- create subtree for myproto
  subtree = root:add(icmp_echo_msg, buf(0))
  -- add protocol fields to subtree
  subtree:add(id,buf(0,8))
  subtree:add(seq,buf(8,8))
  subtree:add(itype,buf(16,8))
  subtree:add(icode,buf(24,8))
  subtree:add(len,buf(32,8))
  subtree:add(ttl,buf(40,8))

  -- description of payload
  data_dis:call(buf(49):tvb(), pkt, root)
end

function icmp_echo_msg.init()
end

event_table = DissectorTable.get("rna_event")
-- Event ID may change depending on the execution... UPDATE HERE:
event_table:add(3, icmp_echo_msg)
