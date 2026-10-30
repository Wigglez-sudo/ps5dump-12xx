#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <ps5/kernel.h>

extern int sceKernelGetMainSocId(void);

#define OFF_PML4  0x20
#define OFF_CR3   0x28
#define CHUNK     0x10000

#define KSPAN_12  0x04000000ULL

#define BASE_REG  0x62800000ULL
#define SPAN_REG  0x02200000ULL

#define BASE_PRO  0x8E0000000ULL
#define SPAN_PRO  0x10000000ULL

static uint64_t pmap_store_kdata(uint32_t ver)
{
  switch (ver) {
    case 0x1200:
    case 0x1202:
    case 0x1220:
    case 0x1240:
    case 0x1260:
    case 0x1270:
      return 0x2E1CFB8ULL;
    default:
      return 0;
  }
}

static int g_log = -1;

static void emit(const char *l)
{
  if (g_log >= 0) {
    write(g_log, l, strlen(l));
    fsync(g_log);
  }
  write(1, l, strlen(l));
}

static void logf_(const char *f, ...)
{
  char b[320];
  va_list a;
  int n;

  va_start(a, f);
  n = vsnprintf(b, sizeof(b) - 2, f, a);
  va_end(a);

  if (n < 0) {
    return;
  }

  b[n] = '\n';
  b[n + 1] = 0;
  emit(b);
}

static const struct {
  const char *name;
  unsigned char c;
} OPS[] = {
  {"vmrun",   0xd8},
  {"vmmcall", 0xd9},
  {"vmload",  0xda},
  {"vmsave",  0xdb},
  {"skinit",  0xde},
};

#define NOPS (sizeof(OPS) / sizeof(OPS[0]))

static void report_ops(const unsigned char *p, unsigned long n, uint64_t pa, int budget[NOPS])
{
  for (unsigned long i = 0; i + 2 < n; i++) {
    if (p[i] != 0x0f || p[i + 1] != 0x01) {
      continue;
    }
    for (unsigned k = 0; k < NOPS; k++) {
      if (p[i + 2] != OPS[k].c) {
        continue;
      }
      if (budget[k] > 0) {
        logf_("    %-8s @ 0x%09llx", OPS[k].name, (unsigned long long)(pa + i));
        budget[k]--;
      }
    }
  }
}

static const char *pick_out(const char *const *cand, unsigned n, char *buf, size_t len)
{
  for (unsigned i = 0; i < n; i++) {
    int fd = open(cand[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      close(fd);
      snprintf(buf, len, "%s", cand[i]);
      return buf;
    }
  }
  return NULL;
}

int main(void)
{
  unsigned char *buf = NULL;
  uint64_t ktext, kdata = 0, pmap_store = 0, kspan = 0, pml4 = 0, cr3 = 0, dmap = 0;
  uint64_t base, span, off, fnv = 1469598103934665603ULL;
  uint32_t fw;
  unsigned ver;
  int rc, kok, kbad, okc, badc, soc = 0, budget[NOPS];
  const char *model = "regular";
  char kpath[96], hpath[96], fwtag[8];

  g_log = open("/data/ps5dump-pro.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  emit("=== ps5dump v4: kernel + hypervisor, 12.xx ===\n");

  fw = kernel_get_fw_version();
  ver = (fw >> 16) & 0xffff;
  ktext = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  kdata = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  pmap_store = (kdata && kdata > ktext) ? (kdata - ktext) + pmap_store_kdata(ver) : 0;
  kspan = KSPAN_12;

  logf_("fw=%08x ver=%04x ktext=%016llx", fw, ver, (unsigned long long)ktext);
  logf_("pmap_store=%#llx (kdata-relative %#llx, kdata-ktext %#llx)",
        (unsigned long long)pmap_store,
        (unsigned long long)pmap_store_kdata(ver),
        (unsigned long long)(kdata > ktext ? kdata - ktext : 0));

  if ((ver >> 8) != 0x12 || !pmap_store) {
    logf_("REFUSED: firmware %04x - this build is 12.xx only", ver);
    goto done;
  }

  soc = sceKernelGetMainSocId();
  if (soc == 0x840fd0) {
    model = "pro";
    base = BASE_PRO;
    span = SPAN_PRO;
  } else {
    model = "regular";
    base = BASE_REG;
    span = SPAN_REG;
  }

  logf_("soc=0x%x model=%s hv_base=0x%llx hv_span=0x%llx", soc, model,
        (unsigned long long)base, (unsigned long long)span);

  buf = malloc(CHUNK);
  if (!buf) {
    logf_("REFUSED: no memory");
    goto done;
  }

  rc = kernel_copyout((intptr_t)(ktext + pmap_store + OFF_PML4), &pml4, 8);
  if (rc) {
    logf_("pm_pml4 REFUSED rc=%d - run byepervisor first", rc);
    goto done;
  }

  rc = kernel_copyout((intptr_t)(ktext + pmap_store + OFF_CR3), &cr3, 8);
  if (rc) {
    logf_("pm_cr3 REFUSED rc=%d - run byepervisor first", rc);
    goto done;
  }

  if (!pml4 || !cr3) {
    logf_("REFUSED: pmap anchors zero - .text not readable");
    goto done;
  }

  dmap = pml4 - cr3;
  logf_("  pm_pml4=%016llx pm_cr3=%016llx dmap=%016llx",
        (unsigned long long)pml4, (unsigned long long)cr3, (unsigned long long)dmap);

  snprintf(fwtag, sizeof fwtag, "%04x", ver);

  {
    char c0[64], c1[64], c2[64], c3[64], cd[64];

    snprintf(c0, sizeof c0, "/mnt/usb0/kimg2-%s.bin", fwtag);
    snprintf(c1, sizeof c1, "/mnt/usb1/kimg2-%s.bin", fwtag);
    snprintf(c2, sizeof c2, "/mnt/usb2/kimg2-%s.bin", fwtag);
    snprintf(c3, sizeof c3, "/mnt/usb3/kimg2-%s.bin", fwtag);
    snprintf(cd, sizeof cd, "/data/kimg2-%s.bin", fwtag);

    const char *cand[] = { c0, c1, c2, c3, cd };

    if (!pick_out(cand, sizeof cand / sizeof cand[0], kpath, sizeof kpath)) {
      logf_("REFUSED: no writable path for the kernel image");
      goto done;
    }
  }

  logf_("kernel -> %s (%llu MiB)", kpath, (unsigned long long)(kspan >> 20));

  int fd = open(kpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    logf_("REFUSED: cannot open %s", kpath);
    goto done;
  }

  kok = kbad = 0;
  for (off = 0; off < kspan; off += CHUNK) {
    if (kernel_copyout((intptr_t)(ktext + off), buf, CHUNK) != 0) {
      memset(buf, 0xcc, CHUNK);
      kbad++;
    } else {
      kok++;
      for (unsigned long i = 0; i < CHUNK; i++) {
        fnv = (fnv ^ buf[i]) * 1099511628211ULL;
      }
    }

    if (write(fd, buf, CHUNK) != (ssize_t)CHUNK) {
      logf_("WRITE FAILED at +%#llx", (unsigned long long)off);
      break;
    }

    if ((off & 0x007fffffULL) == 0) {
      logf_("   +%#010llx ok=%d bad=%d", (unsigned long long)off, kok, kbad);
    }
  }

  fsync(fd);
  close(fd);
  logf_("kernel done: ok=%d refused=%d fnv1a=%016llx", kok, kbad, (unsigned long long)fnv);

  if (kok == 0) {
    logf_("ALL KERNEL CHUNKS REFUSED - run byepervisor first");
    goto done;
  }

  {
    char c0[64], c1[64], c2[64], c3[64], cd[64];

    snprintf(c0, sizeof c0, "/mnt/usb0/hv-%s.bin", fwtag);
    snprintf(c1, sizeof c1, "/mnt/usb1/hv-%s.bin", fwtag);
    snprintf(c2, sizeof c2, "/mnt/usb2/hv-%s.bin", fwtag);
    snprintf(c3, sizeof c3, "/mnt/usb3/hv-%s.bin", fwtag);
    snprintf(cd, sizeof cd, "/data/hv-%s.bin", fwtag);

    const char *cand[] = { c0, c1, c2, c3, cd };

    if (!pick_out(cand, sizeof cand / sizeof cand[0], hpath, sizeof hpath)) {
      logf_("REFUSED: no writable path for the hypervisor image");
      goto done;
    }
  }

  fd = open(hpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    logf_("REFUSED: cannot open %s", hpath);
    goto done;
  }

  logf_("hv -> %s (%llu MiB from 0x%llx)", hpath, (unsigned long long)(span >> 20),
        (unsigned long long)base);

  for (unsigned k = 0; k < NOPS; k++) {
    budget[k] = 12;
  }

  okc = badc = 0;
  for (off = 0; off < span; off += CHUNK) {
    if (kernel_copyout((intptr_t)(dmap + base + off), buf, CHUNK) != 0) {
      memset(buf, 0xcc, CHUNK);
      badc++;
    } else {
      okc++;
      report_ops(buf, CHUNK, base + off, budget);
    }

    if (write(fd, buf, CHUNK) != (ssize_t)CHUNK) {
      logf_("WRITE FAILED at +%#llx", (unsigned long long)off);
      break;
    }

    if ((off & 0x007fffffULL) == 0) {
      logf_("   +%#010llx ok=%d bad=%d", (unsigned long long)off, okc, badc);
    }
  }

  fsync(fd);
  close(fd);
  logf_("hv done: base=0x%09llx ok=%d refused=%d", (unsigned long long)base, okc, badc);

  if (okc == 0) {
    logf_("ALL HV CHUNKS REFUSED");
  }
  logf_("--- files: %s %s", kpath, hpath);

done:
  if (buf) {
    free(buf);
  }
  if (g_log >= 0) {
    close(g_log);
  }
  write(1, "=== done ===\n", 12);
  return 0;
}
