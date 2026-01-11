#include <linux/version.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif
#include <linux/printk.h>
#include <linux/preempt.h>
#include <asm/current.h>

#include "kernel_compat.h"
#include "kp_util.h"

/*
 * Compatibility macros for mmap locking API.
 * mmap_read_trylock/mmap_read_unlock were introduced in kernel 5.8.
 * For older kernels, use the semaphore-based API.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_trylock(mm) down_read_trylock(&(mm)->mmap_sem)
#define mmap_read_unlock(mm) up_read(&(mm)->mmap_sem)
#endif

/*
 * untagged_addr is ARM64-specific for address tagging (TBI).
 * For ARM 32-bit and other architectures, just return the address unchanged.
 */
#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

static bool try_set_access_flag(unsigned long addr)
{
  #if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
	
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	pgd_t *pgd;
#if defined(CONFIG_ARM64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	p4d_t *p4d;
#endif
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	bool ret = false;

	if (!mm)
		return false;

	if (!mmap_read_trylock(mm))
		return false;

	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start)
		goto out_unlock;

	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd))
		goto out_unlock;

#if defined(CONFIG_ARM64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d))
		goto out_unlock;

	pud = pud_offset(p4d, addr);

#else
	/*
	 * ARM 32-bit and older kernels don't have p4d level (5-level page tables).
	 * The pud is folded into pgd, so pud_offset takes pgd directly.
	 * On systems with folded page tables, pud_offset expects pgd_t*.
	 */
	pud = pud_offset(pgd, addr);
#endif
	
	if (!pud_present(*pud))
		goto out_unlock;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		goto out_unlock;

	if (pmd_trans_huge(*pmd))
		goto out_unlock;

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!ptep)
		goto out_unlock;

	pte = *ptep;

	if (!pte_present(pte))
		goto out_pte_unlock;

	if (pte_young(pte)) {
		ret = true;
		goto out_pte_unlock;
	}

	ptep_set_access_flags(vma, addr, ptep, pte_mkyoung(pte), 0);
	pr_info("set AF for addr %lx\n", addr);
	ret = true;

out_pte_unlock:
	pte_unmap_unlock(ptep, ptl);
out_unlock:
	mmap_read_unlock(mm);
	return ret;
#else
	return false;
#endif
}

bool ksu_retry_filename_access(const char __user **char_usr_ptr, char *dest,
			       size_t dest_len, bool exit_atomic_ctx)
{
	unsigned long addr;
	const char __user *fn;
	long ret;

	if (!char_usr_ptr)
		return false;

	addr = untagged_addr((unsigned long)*char_usr_ptr);
#ifdef CONFIG_KSU_DEBUG
	pr_info("got addr: %lu\n", addr);
#endif
	fn = (const char __user *)addr;
	memset(dest, 0, dest_len);
	ret = ksu_strncpy_from_user_nofault(dest, fn, dest_len);

	if (ret < 0 && try_set_access_flag(addr)) {
		ret = ksu_strncpy_from_user_nofault(dest, fn, dest_len);
	}

	/*
	 * This is crazy, but we know what we are doing:
         * Temporarily exit atomic context to handle page faults, then restore it.
         */
	if (exit_atomic_ctx) {
		if (ret < 0 && preempt_count()) {
#ifdef CONFIG_KSU_DEBUG
			pr_info("access to pointer failed, attempting to rescue..\n");
#endif
			preempt_enable_no_resched_notrace();
			ret = strncpy_from_user(dest, fn, dest_len);
			preempt_disable_notrace();
		}
	}

	if (ret < 0) {
		pr_err("all fallback were tried. err: %lu\n", ret);
		return false;
	}

	return true;
}
