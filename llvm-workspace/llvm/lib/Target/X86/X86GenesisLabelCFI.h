#ifndef LLVM_LIB_TARGET_X86_X86GENESISLABELCFI_H
#define LLVM_LIB_TARGET_X86_X86GENESISLABELCFI_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstr.h"

namespace llvm {
  typedef std::vector<MachineInstr *> CallInstrs;
  typedef std::vector<std::pair<MachineInstr *, unsigned>> ReturnInstrs;
  typedef std::vector<std::tuple<MachineInstr *, unsigned, bool>> IndirectBranches;

  class X86GenesisLabelCFI : public MachineFunctionPass {
    static char ID;

  private:
    static const unsigned CFILabel = 0x1337BEEF;
    static const unsigned CFILabelOffset = 4;
    MachineBasicBlock *CFIErrorMBB = nullptr;

    void getInterestingInsts(MachineFunction &MF,
                             CallInstrs &CallInstrs,
                             ReturnInstrs &ReturnInstrs,
                             IndirectBranches &IndirectBranches);

    bool insertCFILabelInFunction(MachineFunction &MF);
    bool insertCFILabelInJumpTarget(MachineBasicBlock &MBB);
    bool insertCFILabel(MachineInstr *MI);
    bool insertCFILabel(MachineFunction &MF, MachineBasicBlock &MBB);

    bool insertForwardCheck(MachineInstr &MI,
                             unsigned UsableReg,
                             bool isMemOp);
    bool insertBackwardCheck(MachineInstr &MI, unsigned UsableReg);

    MachineBasicBlock *getOrInsertCFIErrorMBB(MachineFunction &MF);

    bool enforceForwardLabelCFI(IndirectBranches &IndirectBranches);
    bool enforceBackwardLabelCFI(CallInstrs &CallInstrs,
                                 ReturnInstrs &ReturnInstrs);

  public:
    X86GenesisLabelCFI() : MachineFunctionPass(ID) {}
    StringRef getPassName() const override;
    bool runOnMachineFunction(MachineFunction &MF) override;
  };

  FunctionPass *createX86GenesisLabelCFI(void);
}

#endif
