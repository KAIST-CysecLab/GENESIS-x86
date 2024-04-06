#include <linux/linkage.h>

/**************************************/
/*  PRIVINST TEXT SECTION             */
/**************************************/
.code64
.section .text.nk.privinst, "ax"

SYM_FUNC_START_NOALIGN(__nk_write_cr0)
	mov	%rdi, %cr0
	ret
SYM_FUNC_END(__nk_write_cr0)

SYM_FUNC_START_NOALIGN(__nk_write_cr4)
	btc	$20, %edi		// clear SMEP bit
	mov	%rdi, %cr4
	ret
SYM_FUNC_END(__nk_write_cr4)

SYM_FUNC_START_NOALIGN(__nk_write_cr3)
	mov	%rdi, %cr3
	ret
SYM_FUNC_END(__nk_write_cr3)
