#include <stdio.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "kdlsym.h"
#include "util.h"
#include "paging.h"

uint64_t get_proc_pmap()
{
  pid_t pid;
  uint64_t proc;
  uint64_t p_vmspace;
  uint64_t vm_pmap;

  pid = getpid();

  proc = kernel_get_proc(pid);
  if (proc == 0) {
    return 0;
  }

  p_vmspace = kread64(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
  if (p_vmspace == 0) {
    return 0;
  }

  vm_pmap = kread64(p_vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP);
  if (vm_pmap == 0) {
    return 0;
  }

  return vm_pmap;
}

uint64_t pmap_kextract(uint64_t va)
{
  uint64_t DMPML4I;
  uint64_t DMPDPI;
  uint64_t PML4PML4I;
  uint64_t dmap;
  uint64_t dmap_end;
  uint64_t pde_addr;
  uint64_t pte_addr;
  uint64_t pde;
  uint64_t pte;

  DMPML4I   = (uint64_t) kread32(kdlsym(KERNEL_SYM_DMPML4I));
  DMPDPI    = (uint64_t) kread32(kdlsym(KERNEL_SYM_DMPDPI));
  PML4PML4I = (uint64_t) kread32(kdlsym(KERNEL_SYM_PML4PML4I));

  dmap     = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;
  dmap_end = ((DMPML4I +1 ) << 39) | 0xFFFF800000000000;

  if (dmap <= va && dmap_end > va) {
    return va - dmap;
  }

  pde_addr = ((PML4PML4I << 39) | (PML4PML4I << 30) | 0xFFFF800000000000) + 8 * ((va >> 21) & 0x7FFFFFF);
  pde = kread64(pde_addr);
  if (pde & 0x80) {
    return (pde & 0xFFFFFFFE00000) | (va & 0x1FFFFF);
  }

  pte_addr = ((va >> 9) & 0xFE0) + dmap + (pde & 0xFFFFFFFFFF000);
  pte = kread64(pte_addr);

  return (pte & 0xFFFFFFFFFF000) | (va & 0x3FFF);
}

uint64_t find_pml4e(uint64_t pmap, uint64_t va, uint64_t *out_pml4e)
{
  uint64_t pml4e_addr;
  uint64_t pm_pml4;

  pm_pml4 = kread64(pmap + KERNEL_OFFSET_PMAP_PM_PML4);
  if (pm_pml4 == 0) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  pml4e_addr = pm_pml4 + (((va >> 39) & 0x1FF) * 8);

  *out_pml4e = kread64(pml4e_addr);

  return pml4e_addr;
}

uint64_t find_pdpe(uint64_t pmap, uint64_t va, uint64_t *out_pdpe)
{
  uint64_t pdpe_addr;
  uint64_t pdp_table_pml4_entry;
  uint64_t pdp_table_dmap_addr;

  if (find_pml4e(pmap, va, &pdp_table_pml4_entry) == 0xFFFFFFFFFFFFFFFFull) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  pdp_table_dmap_addr     = kdldmap(PDE_ADDR(pdp_table_pml4_entry));
  pdpe_addr               = pdp_table_dmap_addr + (((va >> 30) & 0x1FF) * 8);

  *out_pdpe = kread64(pdpe_addr);

  return pdpe_addr;
}

uint64_t find_pde(uint64_t pmap, uint64_t va, uint64_t *out_pde)
{
  uint64_t pde_addr;
  uint64_t pd_table_pdp_entry;
  uint64_t pd_table_dmap_addr;

  if (find_pdpe(pmap, va, &pd_table_pdp_entry) == 0xFFFFFFFFFFFFFFFFull) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  pd_table_dmap_addr      = kdldmap(PDE_ADDR(pd_table_pdp_entry));
  pde_addr                = pd_table_dmap_addr + (((va >> 21) & 0x1FF) * 8);

  *out_pde = kread64(pde_addr);

  return pde_addr;
}

uint64_t find_pte(uint64_t pmap, uint64_t va, uint64_t *out_pte)
{
  uint64_t pte_addr;
  uint64_t page_table_pde_entry;
  uint64_t page_table_dmap_addr;

  if (find_pde(pmap, va, &page_table_pde_entry) == 0xFFFFFFFFFFFFFFFFull) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  page_table_dmap_addr    = kdldmap(PDE_ADDR(page_table_pde_entry));
  pte_addr                = page_table_dmap_addr + (((va >> 12) & 0x1FF) * 8);

  *out_pte = kread64(pte_addr);

  return pte_addr;
}
