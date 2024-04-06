#ifndef LLVM_LIB_TARGET_X86_X86GENESISSHADOWSTACK_H
#define LLVM_LIB_TARGET_X86_X86GENESISSHADOWSTACK_H

#include "llvm/CodeGen/MachineFunctionPass.h"

namespace llvm {
  class X86GenesisShadowStack : public MachineFunctionPass {
    static char ID;
    static const int PARALLEL_OFFSET = -(4 * 4096);

    bool instrumentCallInstr(MachineInstr *MI, unsigned ScratchReg);
    bool instrumentRetInstr(MachineInstr *MI, unsigned ScratchReg);

  public:
    X86GenesisShadowStack() : MachineFunctionPass(ID) {}
    StringRef getPassName() const override;
    bool runOnMachineFunction(MachineFunction &MF) override;
  };

  FunctionPass *createX86GenesisShadowStack(void);
}
#endif

