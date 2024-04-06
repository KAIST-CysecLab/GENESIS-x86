#include <linux/nk.h>
#include <linux/rbtree.h>
#include <linux/pgtable.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <asm/msr-index.h>

extern unsigned long __force_order;

extern void __nk_write_cr0 (unsigned long val);
extern void __nk_write_cr4 (unsigned long val);
extern void __nk_write_cr3 (unsigned long val);

extern unsigned long __nk_copy_user_generic_unrolled (unsigned long val1, unsigned long val2, unsigned long val3);
extern unsigned long __nk_copy_user_generic_string (unsigned long val1, unsigned long val2, unsigned long val3);
extern unsigned long __nk_copy_user_enhanced_fast_string (unsigned long val1, unsigned long val2, unsigned long val3);
extern unsigned long __nk__copy_user_nocache (unsigned long val1, unsigned long val2, unsigned long val3);

struct root_pgtbl nk_root_pgtbl_list[NK_ROOT_PGTBL_LIST] = {};
unsigned root_pgtbl_list_index = 0;
static DEFINE_SPINLOCK(nk_root_pgtbl_list_lock);

DEFINE_HASHTABLE(nk_root_pgtbl_hash, NK_ROOT_PGTBL_HASH_BITS);
static DEFINE_SPINLOCK(nk_root_pgtbl_hash_lock); // TODO: RCU?

struct root_pgtbl *get_pgd_elem(unsigned long pgtbl)
{
	struct root_pgtbl *root_pgtbl;
	unsigned index;

	spin_lock(&nk_root_pgtbl_list_lock);

	index = root_pgtbl_list_index;
	root_pgtbl = &nk_root_pgtbl_list[index];

	while (root_pgtbl->in_use) {
		index = (index + 1) % NK_ROOT_PGTBL_LIST;
		if (index == root_pgtbl_list_index) // full
			BUG();
		root_pgtbl = &nk_root_pgtbl_list[index];
	}

	root_pgtbl->in_use = 1;
	root_pgtbl_list_index = (index + 1) % NK_ROOT_PGTBL_LIST;

	spin_unlock(&nk_root_pgtbl_list_lock);

	root_pgtbl->addr = __pa(pgtbl);

	return root_pgtbl;
}

static void nk_verify_pgtbl(unsigned long orig_pgtbl)
{
	struct root_pgtbl *root_pgtbl;
	int is_valid = 0;
	unsigned long pgtbl;

	pgtbl = orig_pgtbl & CR3_ADDR_MASK;

	spin_lock(&nk_root_pgtbl_hash_lock);
	hash_for_each_possible(nk_root_pgtbl_hash,
			       root_pgtbl,
			       hnode,
			       pgtbl) {
		if (root_pgtbl->addr == (unsigned long)pgtbl) {
			is_valid = 1;
			break;
		}
	}
	spin_unlock(&nk_root_pgtbl_hash_lock);

	if (!is_valid) {
		BUG();
#if (0) // Useful for debugging
		pr_alert("[NK] err pa: %lx va: %lx\n", orig_pgtbl, __va(pgtbl));

		int bkt;
		hash_for_each(nk_root_pgtbl_hash, bkt, root_pgtbl, hnode) {
			pr_alert("[NK] addr %lx\n", root_pgtbl->addr);
		}
#endif
	}
}

pte_t *nk_lookup_address(unsigned long address, unsigned int *level)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*level = PG_LEVEL_NONE;
	pgd = pgd_offset_k(address);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		return NULL;

	*level = PG_LEVEL_512G;
	if (p4d_large(*p4d) || !p4d_present(*p4d))
		return (pte_t *)p4d;

	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return NULL;

	*level = PG_LEVEL_1G;
	if (pud_large(*pud) || !pud_present(*pud))
		return (pte_t *)pud;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	*level = PG_LEVEL_2M;
	if (pmd_large(*pmd) || !pmd_present(*pmd))
		return (pte_t *)pmd;

	*level = PG_LEVEL_4K;

	return pte_offset_kernel(pmd, address);
}

static void nk_clone_pgd_range(pgd_t *dst, pgd_t *src, int count)
{
	pgd_t *dst_saddr;

	if (likely(nk_enabled))
		dst_saddr = (pgd_t *)__virt_to_shadow(dst);
	else
		dst_saddr = dst;

	memcpy(dst_saddr, src, count * sizeof(pgd_t));
#ifdef CONFIG_PAGE_TABLE_ISOLATION
	if (!static_cpu_has(X86_FEATURE_PTI))
		return;
	/* Clone the user space pgd as well */
	memcpy(kernel_to_user_pgdp(dst_saddr), kernel_to_user_pgdp(src),
	       count * sizeof(pgd_t));
#endif
}

/* DECLARE */
static void __nk __nk_declare_pgtbl(void *pgtbl, int order)
{
	pte_t *ptep;
	unsigned int level;
	void *saddr;

	struct root_pgtbl *root_pgtbl;

	// TODO: Check the range (ZONE_PTP)

	// zero out pgtbl
	if (likely(nk_enabled))
		saddr = (void *)__virt_to_shadow(pgtbl);
	else
		saddr = pgtbl;
	memset(saddr, 0, PAGE_SIZE << order);

	// special case: handle PGD
	// XXX: it assumes that KPTI is enabled and PAE is not enabled
	if (order == 1) {
		if (CONFIG_PGTABLE_LEVELS == 2 ||
		    (CONFIG_PGTABLE_LEVELS == 3 && SHARED_KERNEL_PMD) ||
		    CONFIG_PGTABLE_LEVELS >= 4) {
			pgd_t *pgd = (pgd_t *)pgtbl;
			nk_clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
					   swapper_pg_dir + KERNEL_PGD_BOUNDARY,
					   KERNEL_PGD_PTRS);
		}

#if (VERIFY_ROOT_PGTBL)
		// Declare the page table
		root_pgtbl = get_pgd_elem((unsigned long)pgtbl);

		spin_lock(&nk_root_pgtbl_hash_lock);
		hash_add(nk_root_pgtbl_hash, &root_pgtbl->hnode, __pa(pgtbl));
		spin_unlock(&nk_root_pgtbl_hash_lock);
#endif
	}
}

/* Cloned pgd_t pti_set_user_pgtbl */
pgd_t __nk_pti_set_user_pgtbl(pgd_t *pgdp, pgd_t pgd)
{
	if (!pgdp_maps_userspace(pgdp))
		return pgd;

	kernel_to_user_pgdp(pgdp)->pgd = pgd.pgd;

	if ((pgd.pgd & (_PAGE_USER|_PAGE_PRESENT)) == (_PAGE_USER|_PAGE_PRESENT) &&
	    (__supported_pte_mask & _PAGE_NX))
		pgd.pgd |= _PAGE_NX;

	return pgd;
}

pgd_t nk_pti_set_user_pgtbl(pgd_t *pgdp, pgd_t pgd)
{
  if (!static_cpu_has(X86_FEATURE_PTI))
    return pgd;
  return __nk_pti_set_user_pgtbl(pgdp, pgd);
}

/* PGD */
static void __nk __nk_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	pgd_t *saddr;

	if (likely(nk_enabled))
		saddr = (pgd_t *)__virt_to_shadow(pgdp);
	else
		saddr = pgdp;


	WRITE_ONCE(*saddr, nk_pti_set_user_pgtbl((pgd_t *)saddr, pgd));
}

/* pgd_clear is a empty function in no4pd */
static void __nk __nk_pgd_clear(pgd_t *pgd)
{
	__nk_set_pgd(pgd, native_make_pgd(0));
}

static void __nk_pgd_free(pgd_t *pgdp, int order)
{
	// NOTE: Do not zero out page table, instread do it at declaration
	// TODO: manage pgtbl list
#if (VERIFY_ROOT_PGTBL)
	if (order == 1) { // PGD
		struct root_pgtbl *root_pgtbl;
		spin_lock(&nk_root_pgtbl_hash_lock);
		hash_for_each_possible(nk_root_pgtbl_hash,
				       root_pgtbl,
				       hnode,
				       __pa((unsigned long)pgdp)) {
			if (root_pgtbl->addr == __pa((unsigned long)pgdp))
				break;
		}
		hash_del(&root_pgtbl->hnode);
		spin_unlock(&nk_root_pgtbl_hash_lock);

		spin_lock(&nk_root_pgtbl_list_lock);
		root_pgtbl->in_use = 0;
		spin_unlock(&nk_root_pgtbl_list_lock);
	}
#endif
}

/* P4D */
static void __nk __nk_set_p4d(p4d_t *p4dp, p4d_t p4d)
{
	pgd_t pgd;
	p4d_t *saddr;

	if (likely(nk_enabled))
		saddr = (p4d_t *)__virt_to_shadow(p4dp);
	else
		saddr = p4dp;

	if (pgtable_l5_enabled() || !IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION)) {
		WRITE_ONCE(*saddr, p4d);
		return;
	}

	pgd = native_make_pgd(native_p4d_val(p4d));
	pgd = nk_pti_set_user_pgtbl((pgd_t *)saddr, pgd);
	WRITE_ONCE(*saddr, native_make_p4d(native_pgd_val(pgd)));
}

static void __nk __nk_p4d_clear(p4d_t *p4d)
{
	__nk_set_p4d(p4d, native_make_p4d(0));
}

/* PUD */
static void __nk __nk_set_pud(pud_t *pudp, pud_t pud)
{
	pud_t *saddr;

	if (likely(nk_enabled))
		saddr = (pud_t *)__virt_to_shadow(pudp);
	else
		saddr = pudp;

	WRITE_ONCE(*saddr, pud);
}

static void __nk __nk_pud_clear(pud_t *pud)
{
	__nk_set_pud(pud, native_make_pud(0));
}

/* PMD */
static void __nk __nk_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	pmd_t *saddr;

	if (likely(nk_enabled))
		saddr = (pmd_t *)__virt_to_shadow(pmdp);
	else
		saddr = pmdp;

	WRITE_ONCE(*saddr, pmd);
}

static void __nk __nk_pmd_clear(pmd_t *pmd)
{
	__nk_set_pmd(pmd, native_make_pmd(0));
}

/* PTE */
static void __nk __nk_set_pte(pte_t *ptep, pte_t pte)
{
	pte_t *saddr;

	//pr_info("nk_set_pte(%lx, %lx)\n", ptep, pte);

	if (likely(nk_enabled))
		saddr = (pte_t *)__virt_to_shadow(ptep);
	else
		saddr = ptep;

	WRITE_ONCE(*saddr, pte);
}

static void __nk __nk_pte_clear(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep)
{
	__nk_set_pte(ptep, native_make_pte(0));
}

/* GET AND CLEAR */
static pud_t __nk_pudp_get_and_clear(pud_t *xp)
{
	pud_t *xsaddr;

	if (likely(nk_enabled))
		xsaddr = (pud_t *)__virt_to_shadow(xp);
	else
		xsaddr = xp;

#ifdef CONFIG_SMP
	return native_make_pud(xchg(&xsaddr->pud, 0));
#else
	pud_t ret = *xsaddr;
	__nk_pud_clear(xsaddr);
	return ret;
#endif
}

static pmd_t __nk_pmdp_get_and_clear(pmd_t *xp)
{
	pmd_t *xsaddr;

	if (likely(nk_enabled))
		xsaddr = (pmd_t *)__virt_to_shadow(xp);
	else
		xsaddr = xp;

#ifdef CONFIG_SMP
	return native_make_pmd(xchg(&xsaddr->pmd, 0));
#else
	pmd_t ret = *xsaddr;
	__nk_pmd_clear(xsaddr);
	return ret;
#endif
}

static pte_t __nk_ptep_get_and_clear(pte_t *xp)
{
	pte_t *xsaddr;

	if (likely(nk_enabled))
		xsaddr = (pte_t *)__virt_to_shadow(xp);
	else
		xsaddr = xp;

#ifdef CONFIG_SMP
	return native_make_pte(xchg(&xsaddr->pte, 0));
#else
	pte_t ret = *xsaddr;
	__nk_pte_clear(NULL, 0, xsaddr);
	return ret;
#endif
}

static void __nk_ptep_set_wrprotect(pte_t *ptep)
{
	pte_t *saddr;

	if (likely(nk_enabled))
		saddr = (pte_t *)__virt_to_shadow(ptep);
	else
		saddr = ptep;

	clear_bit(_PAGE_BIT_RW, (unsigned long *)&saddr->pte);
}

static void __nk_pmdp_set_wrprotect(pmd_t *pmdp)
{
	pmd_t *saddr;

	if (likely(nk_enabled))
		saddr = (pmd_t *)__virt_to_shadow(pmdp);
	else
		saddr = pmdp;

	clear_bit(_PAGE_BIT_RW, (unsigned long *)pmdp);
}

static int __nk_pudp_test_and_clear_young(struct vm_area_struct *vma,
					  unsigned long addr, pud_t *pudp)
{
	int ret = 0;
	pud_t *saddr;

	if (likely(nk_enabled))
		saddr = (pud_t *)__virt_to_shadow(pudp);
	else
		saddr = pudp;

	if (pud_young(*saddr))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *)saddr);

	return ret;
}

static int __nk_pmdp_test_and_clear_young(struct vm_area_struct *vma,
					  unsigned long addr, pmd_t *pmdp)
{
	int ret = 0;
	pmd_t *saddr;

	if (likely(nk_enabled))
		saddr = (pmd_t *)__virt_to_shadow(pmdp);
	else
		saddr = pmdp;

	if (pmd_young(*saddr))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *)saddr);

	return ret;
}

static int __nk_ptep_test_and_clear_young(struct vm_area_struct *vma,
					  unsigned long addr, pte_t *ptep)
{
	int ret = 0;
	pte_t *saddr;

	if (likely(nk_enabled))
		saddr = (pte_t *)__virt_to_shadow(ptep);
	else
		saddr = ptep;

	if (pte_young(*saddr))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *) &saddr->pte);

	return ret;
}

static inline pmd_t __nk_pmdp_establish(struct vm_area_struct *vma,
					unsigned long address,
					pmd_t *pmdp, pmd_t pmd)
{
	pmd_t *saddr;

	if (likely(nk_enabled))
		saddr = (pmd_t *)__virt_to_shadow(pmdp);
	else
		saddr = pmdp;

	if (IS_ENABLED(CONFIG_SMP)) {
		return xchg(saddr, pmd);
	} else {
		pmd_t old = *saddr;
		WRITE_ONCE(*saddr, pmd);
		return old;
	}
}

static void __nk_efi_pgtbl_memcpy(void *to, const void *from, size_t n)
{
	void *saddr;

	if (likely(nk_enabled))
		saddr = (void  *)__virt_to_shadow(to);
	else
		saddr = to;

	memcpy(saddr, from, n);
}

static void __privinst notrace __nk_write_msr(unsigned int msr, u32 low, u32 high)
{
	// Prevent further changes to these MSRs after initialization
	switch (msr) {
	case MSR_EFER:		// EFER_NX
	case MSR_LSTAR:		// SYSCALL entry point
	case MSR_SYSCALL_MASK:	// X86_EFLAGS_AC
		if (nk_enabled)
			BUG();
	}

	asm volatile("wrmsr\n" :: "c" (msr), "a"(low), "d" (high) : "memory");
}

unsigned long notrace __nk __nk_handler(unsigned svc_num,
				unsigned long val1, unsigned long val2,
				unsigned long val3, unsigned long val4) {
	switch(svc_num) {
	case NK_WRITE_CR0:
		__nk_write_cr0(val1);
		break;
	case NK_WRITE_CR3:
#if (VERIFY_ROOT_PGTBL)
		if (likely(nk_enabled))
			nk_verify_pgtbl(val1);
#endif
		__nk_write_cr3(val1);
		break;
	case NK_WRITE_CR4:
		__nk_write_cr4(val1);
		break;
	case NK_COPY_USER_GENERIC_UNROLLED:
		return __nk_copy_user_generic_unrolled(val1, val2, val3);
	case NK_COPY_USER_GENERIC_STRING:
		return __nk_copy_user_generic_string(val1, val2, val3);
	case NK_COPY_USER_ENHANCED_FAST_STRING:
		return __nk_copy_user_enhanced_fast_string(val1, val2, val3);
	case NK_COPY_USER_NOCACHE:
		return __nk__copy_user_nocache(val1, val2, val3);

	case NK_WRITE_MSR:
		__nk_write_msr((unsigned int)val1, (u32)val2, (u32)val3);
		break;

	/* PGD */
	case NK_DECLARE_PGD:
		__nk_declare_pgtbl((void *)val1, (int)val2);
		break;
	case NK_SET_PGD:
		__nk_set_pgd((pgd_t *)val1, __pgd(val2));
		break;
	case NK_PGD_CLEAR:
		__nk_pgd_clear((pgd_t *)val1);
		break;
	case NK_PGD_FREE:
		__nk_pgd_free((pgd_t *)val1, (int)val2);
		break;

	/* P4D */
	case NK_SET_P4D:
		__nk_set_p4d((p4d_t *)val1, __p4d(val2));
		break;
	case NK_P4D_CLEAR:
		__nk_p4d_clear((p4d_t *)val1);
		break;

	/* PUD */
	case NK_SET_PUD:
		__nk_set_pud((pud_t *)val1, __pud(val2));
		break;
	case NK_PUD_CLEAR:
		__nk_pud_clear((pud_t *)val1);
		break;

	/* PMD */
	case NK_SET_PMD:
		__nk_set_pmd((pmd_t *)val1, __pmd(val2));
		break;
	case NK_PMD_CLEAR:
		__nk_pmd_clear((pmd_t *)val1);
		break;

	/* PTE */
	case NK_SET_PTE:
		__nk_set_pte((pte_t *)val1, __pte(val2));
		break;
	case NK_SET_PTE_AT:
		__nk_set_pte((pte_t *)val3, __pte(val4));
		break;
	case NK_PTE_CLEAR:
		__nk_pte_clear((struct mm_struct *)val1,
			       (unsigned long)val2,
			       (pte_t *)val3);
		break;

	/* GET AND CLEAR */
	case NK_PUDP_GET_AND_CLEAR:
		return pud_val(__nk_pudp_get_and_clear((pud_t *)val1));
	case NK_PMDP_GET_AND_CLEAR:
		return pmd_val(__nk_pmdp_get_and_clear((pmd_t *)val1));
	case NK_PTEP_GET_AND_CLEAR:
		return pte_val(__nk_ptep_get_and_clear((pte_t *)val1));

	/* WRPROTECT */
	case NK_PTEP_SET_WRPROTECT:
		__nk_ptep_set_wrprotect((pte_t *)val3);
		break;
	case NK_PMDP_SET_WRPROTECT:
		__nk_pmdp_set_wrprotect((pmd_t *)val3);
		break;


	/* TEST AND CLEAR */
	case NK_PUDP_TEST_AND_CLEAR_YOUNG:
		return __nk_pudp_test_and_clear_young((struct vm_area_struct *)val1,
						      (unsigned long)val2,
						      (pud_t *)val3);
	case NK_PMDP_TEST_AND_CLEAR_YOUNG:
		return __nk_pmdp_test_and_clear_young((struct vm_area_struct *)val1,
						      (unsigned long)val2,
						      (pmd_t *)val3);
	case NK_PTEP_TEST_AND_CLEAR_YOUNG:
		return __nk_ptep_test_and_clear_young((struct vm_area_struct *)val1,
						      (unsigned long)val2,
						      (pte_t *)val3);

	/* PMDP ESTABLISH */
	case NK_PMDP_ESTABLISH:
		return pmd_val(__nk_pmdp_establish((struct vm_area_struct *)val1,
					   (unsigned long)val2,
					   (pmd_t *)val3,
					   __pmd(val4)));

	/* EFI PUD MEMCPY*/
	case NK_EFI_PGTBL_MEMCPY:
		__nk_efi_pgtbl_memcpy((void *)val1, (void *)val2, (size_t)val3);
		break;

	default:
		pr_alert("NK: cannot handle (%lx)\n", svc_num);
	}

	return 0;
}
