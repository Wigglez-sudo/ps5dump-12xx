# ps5dump-12xx

Dumps PS5 kernel and hypervisor memory to a USB stick. Firmware 12.00 to 12.70,
Phat, Slim and Pro. The hypervisor payload it needs is included.

## Files

| path | what |
|---|---|
| `bin/ps5dump-12xx.elf` | dumper, one run writes kernel and hypervisor |
| `bin/byepervisor-12xx.elf` | hypervisor payload, send this first |
| `src/ps5dump-12xx.c` | dumper source |
| `src/`, `include/` | payload sources and offset tables |
| `CREDITS.md` | who wrote what |

## Support

12.00 to 12.70 on Phat, Slim and Pro. All six releases tested on hardware.

Anything outside 12.xx is refused, and the payload only carries tables for those
six releases.

## What you get

Two files and a log.

`kimg2-<fw>.bin`, 64 MiB on every console. A straight copy of kernel memory
starting at the kernel code base. The exact start address changes per boot and is
printed in the log. It covers the kernel's own code and data plus whatever else
lives in the 64 MiB above it.

`hv-<fw>.bin`, 34 MiB on Phat and Slim, 256 MiB on Pro. The hypervisor's reserved
memory window, read through the kernel's direct map. That window starts at
0x62800000 on regular consoles and 0x8E0000000 on Pro. The Pro file is bigger
because the console reserves 256 MiB there instead of 34.

`/data/ps5dump-pro.txt` on the console, the log. It records the firmware, the
kernel base, the pmap anchors, the direct map base, progress every 1 MiB, how many
chunks were refused, a checksum of the kernel dump, and where the SVM instructions
(vmrun, vmmcall, vmload, vmsave, skinit) turned up in the hypervisor window.

Not in there: physical RAM in general, other processes, game data, savedata, flash
or NAND, the A53, or anything outside those two windows.

## Build

You need the PS5 payload SDK (https://github.com/ps5-payload-dev/sdk). The
hypervisor stub is assembled with the host gcc, so gcc, binutils and xxd have to
be installed too.

```
make PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
```

That assembles the stub from `src/break_hv_payload/`, turns it into a header, then
links both payloads. With the same toolchain, a fresh clone builds the same
binaries as the ones in `bin/`.

`make clean` removes the built payloads and the generated stub header.

## Use

1. Jailbreak the console.
2. Send `bin/byepervisor-12xx.elf`. The console drops into rest mode, wake it.
3. Plug in an exFAT or FAT32 USB stick.
4. Send `bin/ps5dump-12xx.elf` and wait for `done`.

You end up with `kimg2-<fw>.bin` and `hv-<fw>.bin` on the stick. The log is at
`/data/ps5dump-pro.txt`.
