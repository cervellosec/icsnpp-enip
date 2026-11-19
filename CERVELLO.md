# Cervello changes to icsnpp-enip

Fork of [cisagov/icsnpp-enip](https://github.com/cisagov/icsnpp-enip), used by the Cervello Zeek
sensor as `plugins/icsnpp-enip`. Every change is in a block that starts with a `Cervello`
comment, and each is a separate commit so it can be offered upstream on its own.

## What is added

| Change | Where | Why |
|---|---|---|
| `forward_open_response` event: both connection IDs and the connection triad of a successful Forward_Open / Large_Forward_Open reply | `consts.pac`, `enip-protocol.pac` (`Forward_Open_Response`), `enip-analyzer.pac` (`process_forward_open_response`, `ENIP_Conn` pending requests), `events.bif` | The reply is the only CIP message carrying both IDs; it was opaque bytes. The sensor pairs a connection's two directions with it. 0x54 / 0x5B are class-specific, so only a reply to a Connection Manager (class 0x06) request seen on the connection is decoded, and the decode cannot throw. |
| `multiple_service_request_item` / `multiple_service_response_item` events, one per item in packet order with the reply data | `enip-analyzer.pac` (`emit_multiple_service_*_items`), `events.bif` | The aggregated `cip_header` events lose the order reply item *i* answers request item *i* by, and never hand out a reply item's bytes. |
| The message inside an Unconnected Send request (service 0x52 on class 0x06) is parsed as the CIP request it is, after the Unconnected Send's own `cip_header` | `enip-analyzer.pac` (`process_unconnected_send`, called from `process_cip_header`) | Unconnected Send is how a client reaches a module behind the one it talks to (a CPU behind a bridge). Its reply comes back unwrapped, so replies were seen and requests were not: a routed Write Tag, Reset or Forward_Open never raised an event. The parse cannot break the packet around it: a size that does not fit is left alone, a message that does not parse is dropped, and 0x52 on another class (Read Tag Fragmented) is not touched. |
| Extended status read as `status_extra` little-endian words | `enip-protocol.pac` (`CIP_Status`), `enip-analyzer.pac` (`get_unsigned`) | Upstream reads bytes, big-endian: `0x0107` logged as `0x0007`. |
| CIP message bounded by its CPF item length | `enip-protocol.pac` (`Unconnected_Data_Item`, `Connected_Data_Item`) | A service parsed with `&restofdata` swallowed every following item (Sockaddr Info after a Forward_Open reply) and the next item then failed. |
| Bounds checks in the request path helpers and the Multiple Service Packet loops, each item's path parsed within the item | `enip-analyzer.pac` (`get_number`, `parse_request_*`) | Reads past a truncated path or a bad offset list, or a path read from the next item's bytes. |
| TCP framing scans for a plausible encapsulation header until aligned | `ENIP.cc`, `ENIP.h` (`PlausibleENIPHeader`, `orig_aligned` / `resp_aligned`) | Upstream's reassembly (#46) trusts the length of whatever the direction starts with; a connection seen mid-stream whose first server bytes are a TCP keep-alive loses that direction until 64 KB have passed. Only at stream start and after a gap or a parse error; once aligned, the length field frames every PDU, whatever its command or options. |

The new events are not logged by default, like upstream's `connected_address`. The one change to
the logs is `cip.log`: a request routed through an Unconnected Send now has a row of its own,
after the Unconnected Send's, as its reply always had. Tests for each change are in `testing/analyzer/`; the traces are
real captures (one TCP connection each), and `ctl-truncated-path.pcap` is `forward_open.pcap`
with its request paths cut short; `midstream_keepalive.pcap` is a connection captured from mid-stream.
`unconnected_send.pcap` is part of a real connection that starts mid-stream.
The other `ctl-*.pcap` traces are real traces with one field edited, named for the case they test.

## Keeping up with upstream

The fork's `main` carries upstream `main` plus the commits above. To take new upstream commits:

```bash
git fetch upstream                       # git@github.com:cisagov/icsnpp-enip.git
git checkout -b sync/<ticket> main
git merge upstream/main                  # resolve inside the Cervello blocks only
cd testing && btest -c btest.cfg         # from a build: ./configure && make
```

Open a PR to `main`, then bump the submodule pointer in the sensor repo with a `[Sync]` commit.
The sensor's `cip_header` handlers follow upstream's signature, so a signature change there means
a matching change in `zeek-src/protocol-handlers/` of the sensor repo.
