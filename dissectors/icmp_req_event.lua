-- ECHO REQ
local data_dis = Dissector.get("data")

icmp_echo_req = Proto("icmp_echo_req","ICMP Echo Request Event")

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

event_table = DissectorTable.get("rna_event")
-- Event ID may change depending on the execution... UPDATE HERE:
event_table:add(4, icmp_echo_req)
