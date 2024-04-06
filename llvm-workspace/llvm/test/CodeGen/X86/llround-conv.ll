; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-unknown             | FileCheck %s --check-prefix=X86
; RUN: llc < %s -mtriple=i686-unknown -mattr=sse2 | FileCheck %s --check-prefix=SSE2
; RUN: llc < %s -mtriple=x86_64-unknown | FileCheck %s --check-prefix=X64

define i64 @testmsxs(float %x) {
; X86-LABEL: testmsxs:
; X86:       # %bb.0: # %entry
; X86-NEXT:    pushl %eax
; X86-NEXT:    .cfi_def_cfa_offset 8
; X86-NEXT:    flds {{[0-9]+}}(%esp)
; X86-NEXT:    fstps (%esp)
; X86-NEXT:    calll llroundf
; X86-NEXT:    popl %ecx
; X86-NEXT:    .cfi_def_cfa_offset 4
; X86-NEXT:    retl
;
; SSE2-LABEL: testmsxs:
; SSE2:       # %bb.0: # %entry
; SSE2-NEXT:    pushl %eax
; SSE2-NEXT:    .cfi_def_cfa_offset 8
; SSE2-NEXT:    movss {{.*#+}} xmm0 = mem[0],zero,zero,zero
; SSE2-NEXT:    movss %xmm0, (%esp)
; SSE2-NEXT:    calll llroundf
; SSE2-NEXT:    popl %ecx
; SSE2-NEXT:    .cfi_def_cfa_offset 4
; SSE2-NEXT:    retl
;
; X64-LABEL: testmsxs:
; X64:       # %bb.0: # %entry
; X64-NEXT:    jmp llroundf # TAILCALL
entry:
  %0 = tail call i64 @llvm.llround.f32(float %x)
  ret i64 %0
}

define i64 @testmsxd(double %x) {
; X86-LABEL: testmsxd:
; X86:       # %bb.0: # %entry
; X86-NEXT:    subl $8, %esp
; X86-NEXT:    .cfi_def_cfa_offset 12
; X86-NEXT:    fldl {{[0-9]+}}(%esp)
; X86-NEXT:    fstpl (%esp)
; X86-NEXT:    calll llround
; X86-NEXT:    addl $8, %esp
; X86-NEXT:    .cfi_def_cfa_offset 4
; X86-NEXT:    retl
;
; SSE2-LABEL: testmsxd:
; SSE2:       # %bb.0: # %entry
; SSE2-NEXT:    subl $8, %esp
; SSE2-NEXT:    .cfi_def_cfa_offset 12
; SSE2-NEXT:    movsd {{.*#+}} xmm0 = mem[0],zero
; SSE2-NEXT:    movsd %xmm0, (%esp)
; SSE2-NEXT:    calll llround
; SSE2-NEXT:    addl $8, %esp
; SSE2-NEXT:    .cfi_def_cfa_offset 4
; SSE2-NEXT:    retl
;
; X64-LABEL: testmsxd:
; X64:       # %bb.0: # %entry
; X64-NEXT:    jmp llround # TAILCALL
entry:
  %0 = tail call i64 @llvm.llround.f64(double %x)
  ret i64 %0
}

define i64 @testmsll(x86_fp80 %x) {
; X86-LABEL: testmsll:
; X86:       # %bb.0: # %entry
; X86-NEXT:    subl $12, %esp
; X86-NEXT:    .cfi_def_cfa_offset 16
; X86-NEXT:    fldt {{[0-9]+}}(%esp)
; X86-NEXT:    fstpt (%esp)
; X86-NEXT:    calll llroundl
; X86-NEXT:    addl $12, %esp
; X86-NEXT:    .cfi_def_cfa_offset 4
; X86-NEXT:    retl
;
; SSE2-LABEL: testmsll:
; SSE2:       # %bb.0: # %entry
; SSE2-NEXT:    subl $12, %esp
; SSE2-NEXT:    .cfi_def_cfa_offset 16
; SSE2-NEXT:    fldt {{[0-9]+}}(%esp)
; SSE2-NEXT:    fstpt (%esp)
; SSE2-NEXT:    calll llroundl
; SSE2-NEXT:    addl $12, %esp
; SSE2-NEXT:    .cfi_def_cfa_offset 4
; SSE2-NEXT:    retl
;
; X64-LABEL: testmsll:
; X64:       # %bb.0: # %entry
; X64-NEXT:    jmp llroundl # TAILCALL
entry:
  %0 = tail call i64 @llvm.llround.f80(x86_fp80 %x)
  ret i64 %0
}

declare i64 @llvm.llround.f32(float) nounwind readnone
declare i64 @llvm.llround.f64(double) nounwind readnone
declare i64 @llvm.llround.f80(x86_fp80) nounwind readnone