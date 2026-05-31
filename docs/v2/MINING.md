# Mining Noso v2

NosoX = Argon2id with memory=64 MiB, time=1, threads=1. Memory-hard,
ARM-friendly, ASIC-hostile.

Per locked spec: block time 120 s, halving every 210,000 blocks
(~292 days), 10 halvings, initial reward 50 NOSO, max supply ≈24 M NOSO
(≈3 M legacy + ≈20.98 M emission). No premine. No dev fund.

## Hardware targets

| Device                          | Expected H/s per core | Notes                          |
| ------------------------------- | --------------------- | ------------------------------ |
| Raspberry Pi 4 (4–8 GB)         | 5–15                  | Sweet spot. Quiet, low power.  |
| Raspberry Pi 5                  | 12–25                 | Larger DDR4 bandwidth helps.   |
| Modern laptop (M-series ARM)    | 50–120                | High memory bandwidth wins.    |
| Desktop x86 (Ryzen 5/7, i5/i7)  | 80–200                | More cores, more threads.      |
| GPU                             | (not supported)       | No memory bandwidth advantage. |

## Run a miner

```bash
go build -o ./bin/nosoxd ./cmd/nosoxd
./bin/nosoxd \
    -data ./nosox \
    -mine \
    -threads 2 \
    -reward your-reward-id \
    -genesis-summary /path/to/sumary.psk    # only first start
```

Threads should not exceed your CPU's physical core count — Argon2id is
memory-bound, hyperthreads add little.

## Verify it's working

```bash
./bin/nosox-cli mine stats http://127.0.0.1:7780
```

Sample output:

```json
{
  "state": 1,
  "hashes": 4218,
  "elapsed": 372.4,
  "hashesps": 11.32
}
```

## Tuning for a Pi

Edit `/etc/sysctl.d/99-nosox.conf`:

```
vm.swappiness = 1
vm.overcommit_memory = 0
```

Reboot. This prevents the kernel from swapping NosoX's working set, which
murders throughput.

For best results on a Pi 4 8 GB, run `-threads 3`. Leave one core for the
P2P node and RPC server.

## Solo vs. pool

The initial release has no pool protocol. The community is expected to
fork StratumX-style overlays; the RPC method `startmining` is the
extension point.

## What hash rate do I need to find a block?

At launch the network difficulty is set so a Pi 4 finds a block roughly
once per day. As the network hashrate climbs, LWMA-3 raises the target
and difficulty until the 120 s block time is preserved. Solo miners with
a single Pi may find blocks once every several days at typical network
load.
