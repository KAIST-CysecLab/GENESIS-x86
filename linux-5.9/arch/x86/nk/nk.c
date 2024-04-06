#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable_types.h>

#include <linux/printk.h>
#include <linux/export.h>
#include <linux/bug.h>
#include <linux/set_memory.h>
#include <linux/mm.h>

#include <linux/nk.h>

#include <linux/percpu.h>
#include <asm/alternative.h>

extern void __nk_handler(unsigned, unsigned long,
			 unsigned long, unsigned long,
			 unsigned long, unsigned long);

unsigned long __naked __nk_gateway __nk_entry(unsigned long val1,
					      unsigned long val2,
					      unsigned long val3,
					      unsigned long val4)
{
	__asm volatile("pushfq\n"
		       "cli\n"
		       "stac\n"
		       ALTERNATIVE("",
			       "movq %%rsp, %%r9\n"
			       "movq %0, %%rsp\n"
			       "push %%r9\n",
			       X86_FEATURE_SMAP)
		       "call __nk_handler"
		      : : "r" (&get_cpu_var(inner_stacks + NK_INNER_STK_PGSZ)));
}
EXPORT_SYMBOL(__nk_entry);

void __naked __nk_gateway __noalign __nk_exit(void)
{
	__asm volatile(ALTERNATIVE("", "movq (%rsp), %rsp\n", X86_FEATURE_SMAP)
		       "popf\n"
		       "clac\n"
		       "ret"
		      );
}

unsigned long __naked __nk_gateway __nk_priv_entry(unsigned long val1,
						   unsigned long val2,
						   unsigned long val3,
						   unsigned long val4)
{
	__asm volatile("pushfq\n\t"
		       "cli\n\t"
		       "mov %cr4, %rax\n\t"
		       "and $" XSTR((~CR4_SMEP_SMAP)) ", %eax\n\t"
		       "mov %rax, %cr4\n\t"
		       "call __nk_handler\n\t"
		      );
}
EXPORT_SYMBOL(__nk_priv_entry);

void __naked __nk_gateway __noalign __nk_priv_exit(void)
{
	__asm volatile("mov %cr4, %rax\n\t"
		       "1: or $" XSTR(CR4_SMEP_SMAP) ", %eax\n\t"
		       "mov %rax, %cr4\n\t"
		       "and $" XSTR(CR4_SMEP_SMAP) ", %eax\n\t"
		       "cmp $" XSTR(CR4_SMEP_SMAP) ", %eax\n\t"
		       "jnz 1b\n\t"
		       "popf\n\t"
		       "clac\n\t"
		       "ret\n\t"
		      );
}

static void nk_protect_pgtbl(void *pgtbl, int order, enum nk_pgtbl_level lvl)
{
#ifdef DEBUG_PGTBL
	pr_info("nk_protect_pgtbl(%lx, %lx) [%s]\n",
		pgtbl, order, pgtbl_type_names[lvl]);
#endif
	__nk_entry(NK_DECLARE_PGD, (unsigned long)pgtbl, order, lvl);
}


/* Page Table Allocation */
pgd_t __ref *nk_pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;

	pgd = pgd_alloc(mm);

	if (likely(nk_pgtbl_enabled))
		nk_protect_pgtbl(pgd, PGD_ALLOCATION_ORDER, NK_PTP_PGD);
	else
		nk_protect_pgtbl_init(pgd, PGD_ALLOCATION_ORDER, NK_PTP_PGD);

	return pgd;
}

 p4d_t __ref *nk_p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	p4d_t *p4d;
	gfp_t gfp = GFP_PGTABLE_USER;

	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;
	p4d = (p4d_t *)__get_free_pages(gfp, 0);

	if (likely(nk_pgtbl_enabled))
		nk_protect_pgtbl(p4d, 0, NK_PTP_P4D);
	else
		nk_protect_pgtbl_init(p4d, 0, NK_PTP_P4D);

	return p4d;
}

pud_t __ref *nk_pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	pud_t *pud;
	gfp_t gfp = GFP_PGTABLE_USER;

	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;
	pud = (pud_t *)__get_free_pages(gfp, 0);

	if (likely(nk_pgtbl_enabled))
		nk_protect_pgtbl(pud, 0, NK_PTP_PUD);
	else
		nk_protect_pgtbl_init(pud, 0, NK_PTP_PUD);

	return pud;
}

pmd_t __ref *nk_pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	pmd_t *pmd;
	gfp_t gfp = GFP_PGTABLE_USER;

	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;
	pmd = (pmd_t *)__get_free_pages(gfp, 0);

	if (likely(nk_pgtbl_enabled))
		nk_protect_pgtbl(pmd, 0, NK_PTP_PMD);
	else
		nk_protect_pgtbl_init(pmd, 0, NK_PTP_PMD);

	return pmd;
}

/* Page Table Deallocation */
static void nk_remove_pgtbl(unsigned long pgtbl, int order,
			    enum nk_pgtbl_level lvl)
{
#ifdef DEBUG_PGTBL_REMOVE
	pr_info("nk_remove_pgtbl(%lx, %lx) [%s]\n",
		pgtbl, order, pgtbl_type_names[lvl]);
#endif
	if (likely(nk_pgtbl_enabled)) {
		// FIXME: __nk_entry is called by compiler
		__nk_entry(NK_PGD_FREE, pgtbl, order, 0);
	}
}

extern bool __tlb_remove_page_size(struct mmu_gather *tlb, struct page *page,
				   int page_size);

/*
 * p*d_free_tlb() macro carries out page table releases in batches later
 * when __tbl_remove_page_size() is executed.
 */
bool nk__tlb_remove_page_size(struct mmu_gather *tlb, struct page *page, int page_size)
{
	nk_remove_pgtbl((unsigned long)page_to_virt(page),
			page_size >> (PAGE_SHIFT + 1), NK_PTP_NONE);
	return __tlb_remove_page_size(tlb, page, page_size);
}

void nk_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	nk_remove_pgtbl((unsigned long)pgd, PGD_ALLOCATION_ORDER, NK_PTP_PGD);
	pgd_free(mm, pgd);
}

void nk_p4d_free(struct mm_struct *mm, p4d_t *p4d)
{
	nk_remove_pgtbl((unsigned long)p4d, 0, NK_PTP_P4D);
	p4d_free(mm, p4d);
}

void nk_pud_free(struct mm_struct *mm, pud_t *pud)
{
	nk_remove_pgtbl((unsigned long)pud, 0, NK_PTP_PUD);
	pud_free(mm, pud);
}

int nk_pud_free_pmd_page(pud_t *pud, unsigned long addr)
{
	nk_remove_pgtbl((unsigned long)pud, 0, NK_PTP_PUD);
	return pud_free_pmd_page(pud, addr);
}

void nk_pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	nk_remove_pgtbl((unsigned long)pmd, 0, NK_PTP_PMD);
	pmd_free(mm, pmd);
}

int nk_pmd_free_pte_page(pmd_t *pmd, unsigned long addr)
{
	nk_remove_pgtbl((unsigned long)pmd, 0, NK_PTP_PMD);
	return pmd_free_pte_page(pmd, addr);
}

/* Nested Kernel PTE Helpers used in LLVM compiler */
void __ref *nk_protect_pte_one(pgtable_t page)
{
	pte_t *ptep = page_to_virt(page);

	if (likely(nk_pgtbl_enabled))
		nk_protect_pgtbl(ptep, 0, NK_PTP_UPTE);
	else
		nk_protect_pgtbl_init(ptep, 0, NK_PTP_UPTE);

	return ptep;
}

void __ref *nk_protect_pte_one_kernel(pte_t *ptep)
{
	if (likely(nk_pgtbl_enabled))
		nk_protect_pgtbl(ptep, 0, NK_PTP_KPTE);
	else
		nk_protect_pgtbl_init(ptep, 0, NK_PTP_KPTE);

	return ptep;
}

void nk_unprotect_pte_one(pgtable_t page)
{
	// XXX: Right?
	if (likely(nk_pgtbl_enabled))
		nk_remove_pgtbl((unsigned long)page_to_virt(page), 0, NK_PTP_UPTE);
}

void nk_unprotect_pte_one_kernel(pte_t *pte)
{
	// XXX: Right?
	if (likely(nk_pgtbl_enabled))
		nk_remove_pgtbl((unsigned long)pte, 0, NK_PTP_UPTE);
}

/***************************************************************/
/* quirk FIXME later                                           */
/***************************************************************/
static void nk_pgd_set_mm(pgd_t *pgd, struct mm_struct *mm)
{
        virt_to_page(pgd)->pt_mm = mm;
}

static inline void nk_pgd_list_add(pgd_t *pgd)
{
        struct page *page = virt_to_page(pgd);

        list_add(&page->lru, &pgd_list);
}
void nk_pgd_ctor(struct mm_struct *mm, pgd_t *pgd)
{
	if (!nk_enabled) {
		/* If the pgd points to a shared pagetable level (either the
		   ptes in non-PAE, or shared PMD in PAE), then just copy the
		   references from swapper_pg_dir. */
		if (CONFIG_PGTABLE_LEVELS == 2 ||
		   (CONFIG_PGTABLE_LEVELS == 3 && SHARED_KERNEL_PMD) ||
		    CONFIG_PGTABLE_LEVELS >= 4) {
			clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
					swapper_pg_dir + KERNEL_PGD_BOUNDARY,
					KERNEL_PGD_PTRS);
		}
	}

	if (!SHARED_KERNEL_PMD) {
		nk_pgd_set_mm(pgd, mm);
		nk_pgd_list_add(pgd);
	}
}

/***********************************/
/*   USER COPY FUNCTIONS           */
/***********************************/
void prepare_one_page_fault(unsigned long addr, int is_write);
void prepare_page_fault(void *to, const void *from, unsigned len);

unsigned long
nk_copy_user_generic_unrolled(void *to, const void *from, unsigned len)
{
	prepare_page_fault(to, from, len);
	return __nk_entry(NK_COPY_USER_GENERIC_UNROLLED,
		   (unsigned long)to, (unsigned long)from, len);
}
EXPORT_SYMBOL(nk_copy_user_generic_unrolled);

unsigned long
nk_copy_user_generic_string(void *to, const void *from, unsigned len)
{
	prepare_page_fault(to, from, len);
	return __nk_entry(NK_COPY_USER_GENERIC_STRING,
		   (unsigned long)to, (unsigned long)from, len);
}
EXPORT_SYMBOL(nk_copy_user_generic_string);

unsigned long
nk_copy_user_enhanced_fast_string(void *to, const void *from, unsigned len)
{
	prepare_page_fault(to, from, len);
	return __nk_entry(NK_COPY_USER_ENHANCED_FAST_STRING,
		   (unsigned long)to, (unsigned long)from, len);
}
EXPORT_SYMBOL(nk_copy_user_enhanced_fast_string);

unsigned long
nk__copy_user_nocache(void *dst, const void *src, unsigned size)
{
	prepare_page_fault(dst, src, size);
	return __nk_entry(NK_COPY_USER_NOCACHE,
		   (unsigned long)dst, (unsigned long)src, size);
}
EXPORT_SYMBOL(nk__copy_user_nocache);
