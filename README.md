# ps5dump-12xx

Dumps PS5 kernel and hypervisor memory to a USB stick. Firmware 12.00 to 12.70,
Phat, Slim and Pro.

## Files

| path | what |
|---|---|
| `bin/ps5dump-12xx.elf` | dumper, writes kernel and hypervisor in one run |
| `bin/byepervisor-12xx.elf` | hypervisor payload, send this first |
| `src/ps5dump-12xx.c` | dumper source |
| `src/`, `include/` | payload sources and offset tables |
| `CREDITS.md` | who wrote what |

## Support

12.00 to 12.70 on Phat, Slim and Pro. All six releases tested on hardware.
Anything outside 12.xx is refused.

## What you get

`kimg2-<fw>.bin`, 64 MiB on every console. Kernel memory from the kernel code base
upward. The address moves per boot and is in the log.

`hv-<fw>.bin`, 34 MiB on Phat and Slim, 256 MiB on Pro. The hypervisor's reserved
window, 0x62800000 on regular consoles and 0x8E0000000 on Pro.

`/data/ps5dump-pro.txt` on the console, the log. Firmware, kernel base, pmap
anchors, direct map base, progress, refused chunk counts, a kernel checksum, and
where the SVM instructions sit in the hypervisor window.

Not a full RAM dump. Other processes, game data, savedata and flash are not in it.

## Build

Needs the PS5 payload SDK (https://github.com/ps5-payload-dev/sdk), plus gcc,
binutils and xxd for the hypervisor stub.

```
make PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
```

## Use

1. Jailbreak the console.
2. Send `bin/byepervisor-12xx.elf`. The console drops into rest mode, wake it.
3. Plug in an exFAT or FAT32 USB stick.
4. Send `bin/ps5dump-12xx.elf` and wait for `done`.

Both files land on the stick.
