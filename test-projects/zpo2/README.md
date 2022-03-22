# ZPO 2

This prototype aims to offload ICMP echo reply and request.

## Findings during the development

- Analyse how to duplicate multiple times the packet to trigger multiple events.
- Check how to properly construct the connection structure from zeek.
    - This seems to be a big problem...
- All zeek-like structures are now prefixed with `z_`.

