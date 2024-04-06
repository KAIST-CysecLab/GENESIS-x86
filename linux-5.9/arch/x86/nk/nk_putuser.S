/* SPDX-License-Identifier: GPL-2.0 */
/*
 * __put_user functions.
 *
 * (C) Copyright 2005 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/export.h>

.macro PROLOGUE
	push %rax
	push %rcx
	mov %rcx, %rdi
	mov $1, %rsi
	call prepare_one_page_fault
	nopl 0x1337beef
	pop %rcx
	pop %rax
	pushfq
	cli
	stac
.endm

.macro EPILOGUE
	popf
	clac
.endm

/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#define ENTER	mov PER_CPU_VAR(current_task), %_ASM_BX

.text
SYM_FUNC_START(__nk_put_user_1)
	PROLOGUE
	ENTER
	cmp TASK_addr_limit(%_ASM_BX),%_ASM_CX
	jae .Lbad_put_user
1:	movb %al,(%_ASM_CX)
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_put_user_1)
EXPORT_SYMBOL(__nk_put_user_1)

SYM_FUNC_START(__nk_put_user_2)
	PROLOGUE
	ENTER
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $1,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae .Lbad_put_user
2:	movw %ax,(%_ASM_CX)
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_put_user_2)
EXPORT_SYMBOL(__nk_put_user_2)

SYM_FUNC_START(__nk_put_user_4)
	PROLOGUE
	ENTER
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $3,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae .Lbad_put_user
3:	movl %eax,(%_ASM_CX)
	xor %eax,%eax
	EPILOGUE
	ret
SYM_FUNC_END(__nk_put_user_4)
EXPORT_SYMBOL(__nk_put_user_4)

SYM_FUNC_START(__nk_put_user_8)
	PROLOGUE
	ENTER
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $7,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae .Lbad_put_user
4:	mov %_ASM_AX,(%_ASM_CX)
#ifdef CONFIG_X86_32
5:	movl %edx,4(%_ASM_CX)
#endif
	xor %eax,%eax
	EPILOGUE
	RET
SYM_FUNC_END(__nk_put_user_8)
EXPORT_SYMBOL(__nk_put_user_8)

SYM_CODE_START_LOCAL(.Lbad_put_user_clac)
.Lbad_put_user:
	movl $-EFAULT,%eax
	EPILOGUE
	RET
SYM_CODE_END(.Lbad_put_user_clac)

	_ASM_EXTABLE_UA(1b, .Lbad_put_user_clac)
	_ASM_EXTABLE_UA(2b, .Lbad_put_user_clac)
	_ASM_EXTABLE_UA(3b, .Lbad_put_user_clac)
	_ASM_EXTABLE_UA(4b, .Lbad_put_user_clac)
#ifdef CONFIG_X86_32
	_ASM_EXTABLE_UA(5b, .Lbad_put_user_clac)
#endif
