#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <asm/pgalloc.h>
#include <asm/cpu_entry_area.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/set_memory.h>

#include <linux/nk.h>

int nk_enabled = 0;
int nk_pgtbl_enabled = 0;

static void nk_protect_zone_ptp(void);
static void nk_create_shadow_mapping(phys_addr_t, phys_addr_t);
static void nk_shadow_populate_pgd(pgd_t *, unsigned long, unsigned long);
static void nk_shadow_populate_p4d(p4d_t *, unsigned long, unsigned long);
static void nk_shadow_populate_pud(pud_t *, unsigned long, unsigned long);
static void nk_protect_shadow_stacks(void);
static void __nk_protect_all_init_pgtbl(void);
static void set_privinst_page_user_bits(unsigned long va);
static void page_set_user_bit(unsigned long va);
static void nk_init_iret_stack(void);
static void nk_init_inner_stack(void);

/* ZONE_PTP (base, end) address */
unsigned long ptp_start_pfn;
unsigned long ptp_end_pfn;

/* IRET Stack */
DEFINE_PER_CPU_PAGE_ALIGNED(struct inner_stack, inner_stacks);
DEFINE_PER_CPU_PAGE_ALIGNED(struct iret_stack, iret_stacks);

/* Temporal variable */
DEFINE_PER_CPU(unsigned long, nk_temp);

/* Lock */
static DEFINE_SPINLOCK(nk_root_pgtbl_hash_lock);

/*
 * Unused hole
 * refer: Documentation/x86/x86_64/mm.rst
 */
unsigned long shadow_offset_base __ro_after_init = _AC(0xffffeb0000000000, UL);

/***************************************************************/
/* Create shadow mapping                                       */
/***************************************************************/

/* Create shadow mapping */
int __init nk_init(void)
{
	struct memblock_region *r;
	unsigned long start_pfn, end_pfn;
	phys_addr_t start_paddr, end_paddr;
	uint64_t nr_pages = 0;

	for_each_memblock(memory, r) {
		start_pfn = memblock_region_memory_base_pfn(r);
		end_pfn = memblock_region_memory_end_pfn(r);

		start_paddr = PFN_PHYS(start_pfn);
		end_paddr = PFN_PHYS(end_pfn);

		nr_pages += end_pfn - start_pfn;

		pr_info("NK: mapping shadow mapping [mem %#010lx-%#010lx]\n",
			start_paddr, end_paddr);

		nk_create_shadow_mapping(start_paddr, end_paddr);
	}

	nk_init_inner_stack();

	/* TODO: protect "swapper_pg_dir" */
	__nk_protect_all_init_pgtbl();

	nk_pgtbl_enabled = 1;

	return 0;
}

int nk_finalize(void)
{
#ifdef CONFIG_GENESIS_SHADOW_STACK
	nk_protect_shadow_stacks();
#endif

	nk_init_iret_stack();

	// FIXME: currently assume that privinst consists of one PMD page.
	set_privinst_page_user_bits((unsigned long)__privinst_text_start);

	nk_protect_zone_ptp();

	nk_enabled = 1;

	pr_info("NK: Nested Kernel Protection Enabled!\n");

	return 0;
}

static void __used __init nk_create_shadow_mapping(phys_addr_t start_paddr,
						   phys_addr_t end_paddr)
{
	unsigned long addr = __phys_to_shadow(start_paddr);
	unsigned long end = __phys_to_shadow(end_paddr);
	unsigned long pgd_next;


	pgd_t *pgd = pgd_offset_k(addr);
	spin_lock(&pgd_lock);
	do {
		pgd_next = pgd_addr_end(addr, end);
		nk_shadow_populate_pgd(pgd, addr, pgd_next);
		pr_info("NK: nk_shadow_populate_pgd"
			"(%#010lx, %#010lx)\n", addr, pgd_next);
	} while (pgd++, addr = pgd_next, addr != end);
	spin_unlock(&pgd_lock);
}

static void __init nk_shadow_populate_pgd(pgd_t *pgd, unsigned long addr,
					  unsigned long end)
{
	void *p;
	p4d_t *p4d;
	unsigned long p4d_next;

	if (pgd_none(*pgd)) {
		p = nk_alloc_low_pages(1);
		pgd_populate(&init_mm, pgd, p);
	}

	p4d = p4d_offset(pgd, addr);
	do {
		p4d_next = p4d_addr_end(addr, end);
		pr_info("NK: nk_shadow_populate_p4d"
			"(%#010lx, %#010lx)\n", addr, p4d_next);
		nk_shadow_populate_p4d(p4d, addr, p4d_next);
	} while (p4d++, addr = p4d_next, addr != end);
}

static void __init nk_shadow_populate_p4d(p4d_t *p4d, unsigned long addr,
					  unsigned long end)
{
	void *p;
	pud_t *pud;
	unsigned long pud_next;

	if (p4d_none(*p4d)) {
		p = nk_alloc_low_pages(1);
		p4d_populate(&init_mm, p4d, p);
	}

	pud = pud_offset(p4d, addr);
	do {
		pud_next = pud_addr_end(addr, end);
		pr_info("NK: nk_shadow_populate_pud"
			"(%#010lx, %#010lx)\n", addr, pud_next);
		nk_shadow_populate_pud(pud, addr, pud_next);
	} while (pud++, addr = pud_next, addr != end);
}

static void __init nk_shadow_populate_pud(pud_t *pud, unsigned long addr,
					  unsigned long end)
{
	void *p;
	pmd_t *pmd;
	unsigned long pmd_next;
	phys_addr_t phys;
	pgprot_t pgprot_shadow_pmd;

	addr = ALIGN_DOWN(addr, PMD_PAGE_SIZE);
	phys = __shadow_to_phys(addr);

	pgprot_shadow_pmd = __pgprot(pgprot_val(PAGE_KERNEL_LARGE)
				     & ~_PAGE_GLOBAL | _PAGE_USER);

	if (pud_none(*pud)) {
		p = nk_alloc_low_pages(1);
		pud_populate(&init_mm, pud, p);
	}

	pmd = pmd_offset(pud, addr);
	do {
		pmd_next = pmd_addr_end(addr, end);
		set_pmd(pmd, __pmd(phys | pgprot_val(pgprot_shadow_pmd)));
		phys += pmd_next - addr;
	} while(pmd++, addr = pmd_next, addr != end);
}

/***************************************************************/
/* Protect early-generated page tables                         */
/***************************************************************/

/* Protect the page tables created in the initialization phase */
#define NK_INIT_PGTBL_LIST 4096
struct nk_init_pgtbl_item {
	void *addr;
	int order;
};

static struct nk_init_pgtbl_item __initdata
nk_init_pgtbl_list[NK_INIT_PGTBL_LIST] = {};
unsigned int nk_init_pgtbl_list_head = 0;

void __init nk_protect_pgtbl_init(void *addr, int order, enum nk_pgtbl_level lvl)
{
	if (unlikely(nk_init_pgtbl_list_head >= NK_INIT_PGTBL_LIST)) {
		pr_err("NK: init list size is too small: %ld\n",
		       nk_init_pgtbl_list_head++);
		return;
	}

#ifdef DEBUG_PGTBL
	pr_info("nk_protect_pgtbl_init(%lx, %lx) [%s]\n", addr, order,
		pgtbl_type_names[lvl]);
#endif

	nk_init_pgtbl_list[nk_init_pgtbl_list_head].addr = addr;
	nk_init_pgtbl_list[nk_init_pgtbl_list_head].order = order;
	nk_init_pgtbl_list_head++;
}

static void __init __nk_protect_all_init_pgtbl(void)
{
	int i;
	unsigned long pgtbl;

	/*
	pr_info("NK: Protect %ld page tables\n", nk_init_pgtbl_list_head);
	for (i = 0; i < nk_init_pgtbl_list_head; i++) {
		set_memory_ro((unsigned long)nk_init_pgtbl_list[i].addr,
			      nk_init_pgtbl_list[i].order << 1);
	}
	*/
	nk_protect_pgtbl_init(swapper_pg_dir, PGD_ALLOCATION_ORDER, NK_PTP_PGD);

#if (VERIFY_ROOT_PGTBL)
	struct root_pgtbl *root_pgtbl;
	for (i = 0; i < nk_init_pgtbl_list_head; i++) {
		if (nk_init_pgtbl_list[i].order == 1) {
			pgtbl = (unsigned long)nk_init_pgtbl_list[i].addr;
			root_pgtbl = get_pgd_elem(pgtbl);

			spin_lock(&nk_root_pgtbl_hash_lock);
			hash_add(nk_root_pgtbl_hash,
				 &root_pgtbl->hnode,
				 __pa(pgtbl)
				 );
			spin_unlock(&nk_root_pgtbl_hash_lock);
		}
	}
#endif
}

unsigned long __initdata nk_pgt_buf_start;
unsigned long __initdata nk_pgt_buf_end;
unsigned long __initdata nk_pgt_buf_top;

extern unsigned long max_pfn;

/* To enable nk_alloc_low_pages, we have to initialize its data structures.
 * init_mem_mapping() (in arch/x86/mm/init.c) function will create
 * initial page tables at first by using nk_alloc_low_pages().
 * Thus, we intercept this function and inserts the initialization function,
 * i.e., nk_early_alloc_pgt_buf().
 */
/* FIXME: nk_early_alloc_pgt_buf() should be inserted after
 * exexcuting e820__memblock_setup().
 */
void __init nk_early_alloc_pgt_buf(void)
{
	unsigned long start_pfn, end_pfn;
	unsigned long reserved_size;
	unsigned long ret;

	end_pfn = max_pfn;
	start_pfn = end_pfn - NK_INIT_PGTBL_COUNT;

	/* Reserve the early ZONE_PTP */
	ret = memblock_find_in_range(
			       start_pfn << PAGE_SHIFT,
			       end_pfn << PAGE_SHIFT,
			       NK_INIT_PGTBL_COUNT * PAGE_SIZE, PAGE_SIZE);

	if (ret)
		memblock_reserve(ret, NK_INIT_PGTBL_COUNT * PAGE_SIZE);
	else
		panic("NK: cannot reserve early pgt_buf memory");

	nk_pgt_buf_start = start_pfn;
	nk_pgt_buf_end = nk_pgt_buf_start;
	nk_pgt_buf_top = nk_pgt_buf_start + NK_INIT_PGTBL_COUNT;

	/* Reserve the after_bootmem ZONE_PTP */
	end_pfn = max_pfn - NK_INIT_PGTBL_COUNT;
	start_pfn = max_pfn - ZONE_PTP_PFN;
	reserved_size = (end_pfn - start_pfn) * PAGE_SIZE;

	ret = memblock_find_in_range(start_pfn << PAGE_SHIFT,
				     end_pfn << PAGE_SHIFT,
				     reserved_size,
				     PAGE_SIZE);

	if (ret)
		memblock_reserve(ret, reserved_size);
	else
		panic("NK: cannot reserve ZONE_PTP memory");
}

extern int after_bootmem;
__ref void* nk_alloc_low_pages(unsigned int num)
{
	unsigned long pfn;
	void *pgtbl;
	int i;

	if (after_bootmem) {
		pgtbl = (void *)__get_free_pages(GFP_PGTABLE_KERNEL, 0);
		goto done;
	}

	if ((nk_pgt_buf_end + num) > nk_pgt_buf_top) {
		panic("nk_allow_low_pages: cannot alloc memory");
	}

	pfn = nk_pgt_buf_end;
	nk_pgt_buf_end += num;

	for (i = 0; i < num; i++) {
		void *adr;
		adr = __va((pfn + i) << PAGE_SHIFT);
		clear_page(adr);
	}

	pgtbl = __va(pfn << PAGE_SHIFT);

done:
	if(unlikely(nk_pgtbl_enabled))
		panic("nk_alloc_low_pages: cannot run after nk enabled");

	nk_protect_pgtbl_init(pgtbl, 0, NK_PTP_NONE);
	return pgtbl;
}

void *nk_spp_getpage(void)
{
	return nk_alloc_low_pages(1);
}

/***************************************************************/
/* Map ZONE_PTP with read-only permission                      */
/***************************************************************/

static void nk_protect_zone_ptp(void)
{
	unsigned long start, end;
	int ret;

	ptp_end_pfn = max_pfn;
	ptp_start_pfn = ptp_end_pfn - ZONE_PTP_PFN;

	start = (unsigned long)__va(ptp_start_pfn << PAGE_SHIFT);
	end = (unsigned long)__va(ptp_end_pfn << PAGE_SHIFT);

	pr_info("nk_protect_zone_ptp() -> (%lx, %lx)\n", start, end);
	ret = set_memory_ro(start, (end - start) >> PAGE_SHIFT);

	if (ret)
		panic("nk_protect_zone_ptp: fail to set ZONE_PTP as readonly");
}

#ifdef CONFIG_GENESIS_SHADOW_STACK
/***************************************************************/
/* Configure the parallel shadow stack as User memory          */
/***************************************************************/
void set_shadow_stack_user_bits(unsigned long va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(va);
	set_pgd(pgd, __pgd(pgd_val(*pgd) | _PAGE_USER));
	p4d = p4d_offset(pgd, va);
#if CONFIG_PGTABLE_LEVELS >= 5
	set_p4d(p4d, __p4d(p4d_val(*p4d) | _PAGE_USER));
#endif
	pud = pud_offset(p4d, va);
	set_pud(pud, __pud(pud_val(*pud) | _PAGE_USER));
	pmd = pmd_offset(pud, va);
	set_pmd(pmd, __pmd(pmd_val(*pmd) | _PAGE_USER));
	pte = pte_offset_kernel(pmd, va);
	set_pte(pte, __pte(pte_val(*pte) | _PAGE_USER));
}

static void nk_protect_shadow_stacks(void)
{
	int cpu;
	unsigned long offset;

	for_each_possible_cpu(cpu) {
		struct cpu_entry_area *cea = get_cpu_entry_area(cpu);

		for (offset = 0; offset < GENESIS_STKSZ / 2; offset += PAGE_SIZE)
		{
			unsigned long va;

			// Per-cpu stack
			va = (unsigned long)&cea->entry_stack_page.stack;
			//pr_info("NK: CPU STACK %#010lx\n", va);
			set_shadow_stack_user_bits(va + offset);

			// Per-cpu Exception stack
			va = (unsigned long)cea->estacks.DF_stack;
			set_shadow_stack_user_bits(va + offset);
			//pr_info("NK: DF STACK %#010lx\n", va);
			va = (unsigned long)cea->estacks.NMI_stack;
			set_shadow_stack_user_bits(va + offset);
			//pr_info("NK: NMI STACK %#010lx\n", va);
			va = (unsigned long)cea->estacks.DB_stack;
			set_shadow_stack_user_bits(va + offset);
			//pr_info("NK: DB STACK %#010lx\n", va);
			va = (unsigned long)cea->estacks.MCE_stack;
			set_shadow_stack_user_bits(va + offset);
			//pr_info("NK: MCE STACK %#010lx\n", va);

			// IRQ stack
			va = per_cpu(hardirq_stack_ptr, cpu);
			va = va - IRQ_STACK_SIZE;
			set_shadow_stack_user_bits(va + offset);
			//pr_info("NK: IRQ STACK %#010lx\n", va);
		}
	}

	return;
}

#endif

/*****************************************************************/
/* Configure the code page that contains privinst as User memory */
/*****************************************************************/

void set_privinst_page_user_bits(unsigned long va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(va);
	set_pgd(pgd, __pgd(pgd_val(*pgd) | _PAGE_USER));
	p4d = p4d_offset(pgd, va);
#if CONFIG_PGTABLE_LEVELS >= 5
	set_p4d(p4d, __p4d(p4d_val(*p4d) | _PAGE_USER));
#endif
	pud = pud_offset(p4d, va);
	set_pud(pud, __pud(pud_val(*pud) | _PAGE_USER));
	pmd = pmd_offset(pud, va);

	BUG_ON(!pmd_large(*pmd));
	set_pmd(pmd, __pmd(pmd_val(*pmd) | _PAGE_USER));
}

/*****************************************************************/
/* Configure the IRET stack as User memory */
/*****************************************************************/
void page_set_user_bit(unsigned long va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(va);
	set_pgd(pgd, __pgd(pgd_val(*pgd) | _PAGE_USER));
	p4d = p4d_offset(pgd, va);
#if CONFIG_PGTABLE_LEVELS >= 5
	set_p4d(p4d, __p4d(p4d_val(*p4d) | _PAGE_USER));
#endif
	pud = pud_offset(p4d, va);
	set_pud(pud, __pud(pud_val(*pud) | _PAGE_USER));
	pmd = pmd_offset(pud, va);
	set_pmd(pmd, __pmd(pmd_val(*pmd) | _PAGE_USER));
	pte = pte_offset_kernel(pmd, va);
	set_pte(pte, __pte(pte_val(*pte) | _PAGE_USER));
}

static void nk_init_iret_stack(void)
{
	int cpu;
	struct iret_stack *iret_stack;

	local_irq_disable();
	for_each_possible_cpu(cpu) {
		iret_stack = per_cpu_ptr(&iret_stacks, cpu);
		iret_stack->stack_bottom = (unsigned long)&iret_stack->stack;
		iret_stack->stack_bottom_shdw =
			__virt_to_shadow(&iret_stack->stack);
		pr_info("NK: iret_stack->stack_bottom #%d: %lx\n",
			cpu, iret_stack->stack_bottom);
		pr_info("NK: iret_stack->stack_bottom_shdw #%d: %lx\n",
			cpu, iret_stack->stack_bottom_shdw);

	}
	local_irq_enable();

	for_each_possible_cpu(cpu) {
		int num_pages;

		iret_stack = per_cpu_ptr(&iret_stacks, cpu);
		num_pages = PAGE_ALIGN(sizeof(iret_stacks)) >> PAGE_SHIFT;

		pr_info("IRET_STACK #%d: %lx (pages: %d)\n",
			cpu, iret_stack, num_pages);

		set_memory_4k((unsigned long)iret_stack, num_pages);
		set_memory_ro((unsigned long)iret_stack, num_pages);

		page_set_user_bit((unsigned long)iret_stack);
	}
}

static __init void nk_init_inner_stack(void)
{
	int cpu;
	struct inner_stack *inner_stack;

	for_each_possible_cpu(cpu) {
		int num_pages;

		inner_stack = per_cpu_ptr(&inner_stacks, cpu);
		num_pages = PAGE_ALIGN(sizeof(*inner_stack)) >> PAGE_SHIFT;

		pr_info("INNER_STACK #%d: %lx ~ %lx (pages: %d)\n",
			cpu, &inner_stack->stack,
			(void *)&inner_stack->stack + PAGE_SIZE,
			num_pages);

		set_memory_4k((unsigned long)inner_stack, num_pages);

#if (0) // FIXME
		page_set_user_bit((unsigned long)inner_stack);
#endif
	}
}
