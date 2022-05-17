from zpo.protocol_template import ProtocolTemplate
from zpo.utils import indent


class IngressProcessor:

    def __init__(self, protocol: ProtocolTemplate):
        self.struct_accessor = protocol.struct_accessor
        self.processor_path = protocol.ingress_processor_file_path

    def _read_processor(self):
        with open(self.processor_path, 'r') as file:
            return file.read().strip()

    def __str__(self):
        return indent("""
if (%s.isValid()) {
%s
}
""".strip() % (self.struct_accessor, indent(self._read_processor())), spaces=12)
