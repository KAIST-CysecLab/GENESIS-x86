/* SPDX-License-Identifier: GPL-2.0 */
/*
 * __get_user functions.
 *
 * (C) Copyright 1998 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */

/*
 * __get_user_X
 *
 * Inputs:	%[r|e]ax contains the address.
 *
 * Outputs:	%[r|e]ax is error code (0 or -EFAULT)
 *		%[r|e]dx contains zero-extended value
 *		%ecx contains the high half for 32-bit __get_user_8
 *
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#include <linux/linkage.h>
#include <asm/page_types.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/export.h>

.macro PROLOGUE
	push %rax
	mov %rax, %rdi
	mov $0, %rsi
	call prepare_one_page_fault
	nopl 0x1337beef
	pop %rax
	pushfq
	cli
	stac
.endm

.macro EPILOGUE
	popf
	clac
.endm
	.text
SYM_FUNC_START(__nk_get_user_1)
	PROLOGUE
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
	sbb %_ASM_DX, %_ASM_DX		/* array_index_mask_nospec() */
	and %_ASM_DX, %_ASM_AX
1:	movzbl (%_ASM_AX),%edx
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_get_user_1)
EXPORT_SYMBOL(__nk_get_user_1)

SYM_FUNC_START(__nk_get_user_2)
	PROLOGUE
	add $1,%_ASM_AX
	jc bad_get_user
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
	sbb %_ASM_DX, %_ASM_DX		/* array_index_mask_nospec() */
	and %_ASM_DX, %_ASM_AX
2:	movzwl -1(%_ASM_AX),%edx
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_get_user_2)
EXPORT_SYMBOL(__nk_get_user_2)

SYM_FUNC_START(__nk_get_user_4)
	PROLOGUE
	add $3,%_ASM_AX
	jc bad_get_user
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
	sbb %_ASM_DX, %_ASM_DX		/* array_index_mask_nospec() */
	and %_ASM_DX, %_ASM_AX
3:	movl -3(%_ASM_AX),%edx
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_get_user_4)
EXPORT_SYMBOL(__nk_get_user_4)

SYM_FUNC_START(__nk_get_user_8)
	PROLOGUE
	add $7,%_ASM_AX
	jc bad_get_user
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
	sbb %_ASM_DX, %_ASM_DX		/* array_index_mask_nospec() */
	and %_ASM_DX, %_ASM_AX
4:	movq -7(%_ASM_AX),%rdx
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_get_user_8)
EXPORT_SYMBOL(__nk_get_user_8)


SYM_CODE_START_LOCAL(.Lbad_get_user_clac)
bad_get_user:
	xor %edx,%edx
	mov $(-EFAULT),%_ASM_AX
	EPILOGUE
	ret
SYM_CODE_END(.Lbad_get_user_clac)

	_ASM_EXTABLE_UA(1b, .Lbad_get_user_clac)
	_ASM_EXTABLE_UA(2b, .Lbad_get_user_clac)
	_ASM_EXTABLE_UA(3b, .Lbad_get_user_clac)
#ifdef CONFIG_X86_64
	_ASM_EXTABLE_UA(4b, .Lbad_get_user_clac)
#else
	_ASM_EXTABLE_UA(4b, .Lbad_get_user_8_clac)
	_ASM_EXTABLE_UA(5b, .Lbad_get_user_8_clac)
#endif
