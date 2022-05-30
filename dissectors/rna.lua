rna_table = DissectorTable.new("rna_type", "RNA Type", uint16, base.DEC)

-- RNA PROTOCOL
local data_dis = Dissector.get("data")

rna = Proto("rna", "RNA Protocol")

local rna_version = ProtoField.uint16("rna.version", "RNA Protocol Version/Hash", base.DEC)
local rna_type = ProtoField.uint16("rna.type", "RNA Protocol Type (Subtype/next header)", base.DEC)

rna.fields = {
    rna_version,
    rna_type
}

-- rna dissector function
function rna.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = rna.name
  pkt.cols.info = rna.description

  -- create subtree for myproto
  subtree = root:add(rna, buf(0))

  -- add protocol fields to subtree
  subtree:add(rna_version, buf(0,2))
  subtree:add(rna_type, buf(2,2))

  local rna_subproto_dis = rna_table:get_dissector(buf(2,2):uint())

  if rna_subproto_dis ~= nil then
    rna_subproto_dis:call(buf(4):tvb(), pkt, root)
  else
    data_dis:call(buf(4):tvb(), pkt, root)
  end
end

-- Initialization routine
function rna.init()
end

-- subscribe for Ethernet packets on type 26 118 (0x6606).
local eth_table = DissectorTable.get("ethertype")
eth_table:add(26118, rna)
