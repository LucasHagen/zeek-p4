

from typing import List
from ..file_gen_stats import FileGenerationStats
from zpo.model.protocol import ProtocolComponent
from zpo.model.offloader import OffloaderComponent
from zpo.utils import indent


class OffloaderTriggers:

    def __init__(self, protocol_templates: List[ProtocolComponent], stats: FileGenerationStats = None):
        self.protocols: List[ProtocolComponent] = []

        for protocol in protocol_templates:
            if len(protocol.offloaders) <= 0:
                continue

            offloader_triggers = " else ".join(map(
                _get_offloader_trigger,
                protocol.offloaders.values()
            ))
            final_code = _protocol_guard(protocol, offloader_triggers)

            trigger_lines = map(lambda o: o.read_p4_trigger(), protocol.offloaders.values())
            stats.auto_increament_generated(final_code)
            stats.auto_increament_offloader_template(trigger_lines)
            stats.auto_increament_generated(trigger_lines, mult=-1) # subtract offloader lines

            self.protocols.append(final_code)

    def __str__(self):
        return indent("\n".join(self.protocols), spaces=12)


def _get_offloader_trigger(offloader: OffloaderComponent):
    return """
if(%s) {
    meta.offloader_type = %s;
}
""".strip() % (offloader.read_p4_trigger(), offloader.uid_constant)


def _protocol_guard(protocol: ProtocolComponent, content: str):
    return """
if (%s.isValid()) {
%s
}
""".strip() % (protocol.struct_accessor, indent(content))
