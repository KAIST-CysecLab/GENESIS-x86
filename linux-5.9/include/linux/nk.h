#ifndef __NK_H__
#define __NK_H__

#ifdef CONFIG_GENESIS_LABEL_CFI
#define CFI_LABEL_VALUE 0x1337beef
#define CFI_LABEL_OFFSET 0x4
#define CFI_LABEL nopl CFI_LABEL_VALUE
#define CFI_ALIGN_VALUE 5
#define CFI_ALIGN .p2align CFI_ALIGN_VALUE
#endif

#define CR4_SMEP_SMAP	0x300000	// SMAP (21-bit) and SMEP (20-bit)
#define CR4_SMEP	0x100000	// SMEP (20-bit)
#define CR4_SMEP_BIT	20		// SMEP (20-bit in %cr4)

#define STR(x) #x
#define XSTR(s) STR(s)

#ifndef __ASSEMBLY__

#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/hashtable.h>

#if (0)
#define DEBUG_PGTBL
#define DEBUG_PGTBL_REMOVE
#endif

#define VERIFY_ROOT_PGTBL	1
#ifdef CONFIG_GENESIS_LABEL_CFI
#undef VERIFY_ROOT_PGTBL
#define VERIFY_ROOT_PGTBL	0
#endif

enum nk_pgtbl_level {
	NK_PTP_NONE,
	NK_PTP_PGD,
	NK_PTP_P4D,
	NK_PTP_PUD,
	NK_PTP_PMD,
	NK_PTP_UPTE,
	NK_PTP_KPTE,
	NK_PTP_NUM
};

static char * const pgtbl_type_names[NK_PTP_NUM] = {
	"unknown",
	"PGD",
	"P4D",
	"PUD",
	"PMD",
	"UPTE",
	"KPTE",
};

extern int nk_enabled;
extern int nk_pgtbl_enabled;

/* PGD LIST */
#define NK_ROOT_PGTBL_LIST	4096
struct root_pgtbl {
	unsigned long addr;
	unsigned in_use;

	struct hlist_node hnode;
};

// TODO: resizable array in Linux
extern struct root_pgtbl nk_root_pgtbl_list[NK_ROOT_PGTBL_LIST];
extern unsigned root_pgtbl_list_index;

struct root_pgtbl *get_pgd_elem(unsigned long);

#define NK_ROOT_PGTBL_HASH_BITS	10
extern DECLARE_HASHTABLE(nk_root_pgtbl_hash, NK_ROOT_PGTBL_HASH_BITS);

/*
 * Shadow Mapping
 */
extern unsigned long shadow_offset_base;
#define NK_SHADOW_OFFSET shadow_offset_base

#define __phys_to_shadow(x) ((unsigned long)(x) + NK_SHADOW_OFFSET)
#define __virt_to_shadow(x) ((unsigned long)(x) - PAGE_OFFSET + NK_SHADOW_OFFSET)

#define __shadow_to_virt(x) ((unsigned long)(x) - NK_SHADOW_OFFSET + PAGE_OFFSET)
#define __shadow_to_phys(x) ((unsigned long)(x) - NK_SHADOW_OFFSET)

/*
 * NK sections
 */
// TODO: locate nk code/data region
extern char __nk_text_start[], __nk_text_end[];
extern char __nk_data_start[], __nk_data_end[];

#define __nk      //__section(.nk.text)
#define __nk_data //__section(.nk.data)
#define __nk_gateway	__section(.text.nk.gateway)	// Global
#define __noalign	__attribute__((aligned(1)))	// No-align

#define __privinst __section(.text.nk.privinst)

/*
 * Service number
 */
#define NK_WRITE_CR0 0
#define NK_WRITE_CR3 1
#define NK_WRITE_CR4 2
#define NK_COPY_USER_GENERIC_UNROLLED     3
#define NK_COPY_USER_GENERIC_STRING       4
#define NK_COPY_USER_ENHANCED_FAST_STRING 5
#define NK_COPY_USER_NOCACHE              6
#define NK_WRITE_MSR 7

#define NK_DECLARE_PGD 100
#define NK_DECLARE_P4D 101
#define NK_DECLARE_PUD 102
#define NK_DECLARE_PMD 103
#define NK_DECLARE_PTE 104

#define NK_PGD_FREE 105
#define NK_P4D_FREE 106
#define NK_PUD_FREE 107
#define NK_PMD_FREE 108
#define NK_PTE_FREE 109

#define NK_SET_PGD 110
#define NK_SET_P4D 111
#define NK_SET_PUD 112
#define NK_SET_PMD 113
#define NK_SET_PTE 114

#define NK_PGD_CLEAR 115
#define NK_P4D_CLEAR 116
#define NK_PUD_CLEAR 117
#define NK_PMD_CLEAR 118
#define NK_PTE_CLEAR 119

// speicial case
#define NK_SET_PTE_AT 120
#define NK_PUDP_GET_AND_CLEAR 121
#define NK_PMDP_GET_AND_CLEAR 122
#define NK_PTEP_GET_AND_CLEAR 123
#define NK_PTEP_SET_WRPROTECT 124

#define NK_PMDP_SET_WRPROTECT 125
#define NK_PUDP_TEST_AND_CLEAR_YOUNG 126
#define NK_PMDP_TEST_AND_CLEAR_YOUNG 127
#define NK_PTEP_TEST_AND_CLEAR_YOUNG 128
#define NK_PMDP_ESTABLISH 129

#define NK_EFI_PGTBL_MEMCPY 130

/*
 * ZONE_PTP (base, end) address
 */
extern unsigned long ptp_start_pfn;
extern unsigned long ptp_end_pfn;
#define ZONE_PTP_PFN 0x40000 // 1 GiB

/*
 * 1) PRIVINST PAGE
 * 2) GATEWAY PAGE
 */
extern char __privinst_text_start[], __privinst_text_end[];
extern char __nk_gateway_text_start[], __nk_gateway_text_end[];

/*
 * INNER KERNEL STACK
 */
#define NK_INNER_STKSZ PAGE_SIZE
#define NK_INNER_STK_PGSZ (NK_INNER_STKSZ / PAGE_SIZE)

struct inner_stack {
	unsigned char stack[NK_INNER_STKSZ];
} __attribute__((aligned(PAGE_SIZE)));

DECLARE_PER_CPU_PAGE_ALIGNED(struct inner_stack, inner_stacks);

/*
 * IRET STACK
 */
struct iret_stack {
	unsigned long stack_bottom;
	unsigned long stack_bottom_shdw;
	unsigned long stack[5];
} __attribute__((aligned(PAGE_SIZE)));

DECLARE_PER_CPU_PAGE_ALIGNED(struct iret_stack, iret_stacks);

/*
 * In NK, It uses RET instead of IRET when returning to kernel.
 * The following nk_temp variable is used for such purpose.
 */
DECLARE_PER_CPU(unsigned long, nk_temp);

/* INIT PAGE TABLES */
#define NK_INIT_PGTBL_COUNT 4096

/*
 * Exported functions
 */
int __init nk_init(void);
int nk_finalize(void);

void nk_protect_pgtbl_init(void *addr, int order, enum nk_pgtbl_level lvl);

void nk_early_alloc_pgt_buf(void);
void *nk_alloc_low_pages(unsigned int);

unsigned long
__nk_entry(unsigned long, unsigned long, unsigned long, unsigned long);

#endif /* __ASSEMBLY__  */

#endif /* __NK_H__ */
