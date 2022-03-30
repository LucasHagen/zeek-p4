# ZPO 2

This prototype aims to offload ICMP echo reply and request.

## Findings during the development

- Analyse how to duplicate multiple times the packet to trigger multiple events.
    - Consider using 1 message for multiple events: TLV (Type Length Value), ASN1 (Abstract syntax notation)
- Check how to properly construct the `Connection` structure from zeek.
    - This seems to be a big problem...
- All zeek-like structures are now prefixed with `z_`.

