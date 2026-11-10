# Cervello changes to icsnpp-enip

Fork of [cisagov/icsnpp-enip](https://github.com/cisagov/icsnpp-enip), used by the Cervello Zeek
sensor as `plugins/icsnpp-enip`. Every change is in a block that starts with a `Cervello`
comment, and each is a separate commit so it can be offered upstream on its own.

## What is added

| Change | Where | Why |
|---|---|---|
| `forward_open_response` event: both connection IDs and the connection triad of a successful Forward_Open / Large_Forward_Open reply | `consts.pac`, `enip-protocol.pac` (`Forward_Open_Response`), `enip-analyzer.pac`, `events.bif` | The reply is the only CIP message carrying both IDs; it was opaque bytes. The sensor pairs a connection's two directions with it. |
| `multiple_service_request_item` / `multiple_service_response_item` events, one per item in packet order with the reply data | `enip-analyzer.pac` (`emit_multiple_service_*_items`), `events.bif` | The aggregated `cip_header` events lose the order reply item *i* answers request item *i* by, and never hand out a reply item's bytes. |
| Extended status read as `status_extra` little-endian words | `enip-protocol.pac` (`CIP_Status`), `enip-analyzer.pac` (`get_unsigned`) | Upstream reads bytes, big-endian: `0x0107` logged as `0x0007`. |
| CIP message bounded by its CPF item length | `enip-protocol.pac` (`Unconnected_Data_Item`, `Connected_Data_Item`) | A service parsed with `&restofdata` swallowed every following item (Sockaddr Info after a Forward_Open reply) and the next item then failed. |
| Bounds checks in the request path helpers and the Multiple Service Packet loops | `enip-analyzer.pac` (`get_number`, `parse_request_*`) | Reads past a truncated path or a bad offset list. |
| TCP framing resyncs on an implausible encapsulation header | `ENIP.cc` (`PlausibleENIPHeader`) | Upstream's reassembly (#46) trusts the length of whatever the direction starts with; a connection seen mid-stream whose first server bytes are a TCP keep-alive loses that direction until 64 KB have passed. |

`cip.log` and the other logs are unchanged: the new events are not logged by default, like
upstream's `connected_address`. Tests for each change are in `testing/analyzer/`; the traces are
real captures (one TCP connection each), and `ctl-truncated-path.pcap` is `forward_open.pcap`
with its request paths cut short; `midstream_keepalive.pcap` is a connection captured from mid-stream.

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
