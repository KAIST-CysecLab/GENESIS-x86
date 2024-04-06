#include "X86GenesisLabelCFI.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86RegisterInfo.h"
#include "X86InstrBuilder.h"

#include "llvm/ADT/SmallSet.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"

#include "llvm/IR/CallingConv.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SpecialCaseList.h"

#include <vector>
#include <iostream>

using namespace llvm;
using namespace std;

// TODO: Refactor blacklist functions
cl::opt<string> option_no_instrument_blacklist(
    "genesis-cfi-blacklist",
    cl::desc("Do not enforce CFI in the functions/modules"
             "specified in the given blacklist"), cl::init("-"));

extern cl::opt<bool> EnableGenesisShadowStack;

/*
 * Blacklist checking.
 */
static bool isBlacklisted(SpecialCaseList *SCL, const Module *M)
{
  if (SCL == nullptr)
    return false;
  if (SCL->inSection("", "src", M->getModuleIdentifier()))
    return true;
  return false;
}

static bool isBlacklisted(SpecialCaseList *SCL, const Function *F)
{
  if (SCL == nullptr)
    return false;
  return SCL->inSection("", "fun", F->getName());
}

static bool isBlacklistedSection(const Function &F)
{
  if (F.hasSection()) {
    StringRef Section(F.getSection());
    if (//Section.startswith(".init.text") ||
        //Section.startswith(".meminit.text") ||
        Section.startswith(".head.text"))
      return true;
  }

  return false;
}

StringRef X86GenesisLabelCFI::getPassName() const {
  return "X86 Genesis Label CFI Pass";
}

void X86GenesisLabelCFI::getInterestingInsts(MachineFunction &MF,
                                             CallInstrs &CallInstrs,
                                             ReturnInstrs &ReturnInstrs,
                                             IndirectBranches &IndirectBranches)
{
  for (MachineBasicBlock &MBB : MF) {
    RegScavenger RS;
    RS.enterBasicBlock(MBB);

    for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); I++) {
      MachineInstr *MI = &*I;

      if (!MI->isCall() && !MI->isBranch() && !MI->isReturn())
        continue;

      // This instruction was a RETQ instruction.
      if (MI->getCFIFlag(MachineInstr::ShdwStkRet)) {
        continue;
      }

      switch (MI->getOpcode()) {
        // Register-based indirect call
        case X86::CALL16r:
        case X86::CALL32r:
        case X86::CALL64r:
        case X86::CALL16r_NT:
        case X86::CALL32r_NT:
        case X86::CALL64r_NT:
        {
          CallInstrs.push_back(MI);
          [[fallthrough]];
        }

        // Register-based indirect jump
        case X86::JMP16r:
        case X86::JMP32r:
        case X86::JMP64r:
        case X86::JMP64r_REX:
        case X86::JMP16r_NT:
        case X86::JMP32r_NT:
        case X86::JMP64r_NT:

        // Register-based indirect tail-call
        case X86::TAILJMPr:
        case X86::TAILJMPr64:
        case X86::TAILJMPr64_REX:
        {
          unsigned DstReg = MI->getOperand(0).getReg();
          IndirectBranches.push_back(make_tuple(MI, DstReg, false));
          break;
        }

        // Memory-based indirect call
        case X86::CALL16m:
        case X86::CALL32m:
        case X86::CALL64m:
        case X86::CALL16m_NT:
        case X86::CALL32m_NT:
        case X86::CALL64m_NT:
        {
          CallInstrs.push_back(MI);
          [[fallthrough]];
        }

        // Memory-based indirect jump
        case X86::JMP16m:
        case X86::JMP32m:
        case X86::JMP64m:
        case X86::JMP64m_REX:
        case X86::JMP16m_NT:
        case X86::JMP32m_NT:
        case X86::JMP64m_NT:

        // Memory-based indirect tail call
        case X86::TAILJMPm:
        case X86::TAILJMPm64:
        case X86::TAILJMPm64_REX:
        {
          if (I != MBB.begin())
            RS.forward(std::prev(I));

          unsigned UsableReg = RS.FindUnusedReg(&X86::GR64RegClass);
          IndirectBranches.push_back(make_tuple(MI, UsableReg, true));
          break;
        }

        // direct call
        case X86::CALLpcrel32:
        case X86::CALLpcrel16:
        case X86::CALL64pcrel32:
        {
          CallInstrs.push_back(MI);
          break;
        }

        // direct tail-call
        case X86::TAILJMPd:
        case X86::TAILJMPd_CC:
        case X86::TAILJMPd64:
        case X86::TAILJMPd64_CC:
        {
          break;
        }

        // direct jump
        case X86::JMP_1:
        case X86::JMP_2:
        case X86::JMP_4:
        case X86::JCC_1:
        case X86::JCC_2:
        case X86::JCC_4:
        case X86::JCXZ:
        case X86::JECXZ:
        case X86::JRCXZ:
        {
          break;
        }

        // Return instruction
        case X86::RETQ:
        {
          if (I != MBB.begin())
            RS.forward(std::prev(I));

          unsigned UsableReg = RS.FindUnusedReg(&X86::GR64RegClass);
          assert(UsableReg && "No UsableReg before instrumenting RETQ");
          ReturnInstrs.push_back(make_pair(MI, UsableReg));
          break;
        }

        default:
        {
          if (MI->isCall() || MI->isIndirectBranch() || MI->isReturn())
            llvm_unreachable("[-] MI is not a CALL/JMP/RET");
        }
      }
    }
  } /* for (MachineBasicBlock &MBB : MF) */

  return;
}

bool X86GenesisLabelCFI::insertCFILabelInFunction(MachineFunction &MF) {
  MachineBasicBlock &MBB = *MF.begin();

  return insertCFILabel(MF, MBB);
}

bool X86GenesisLabelCFI::insertCFILabelInJumpTarget(MachineBasicBlock &MBB) {
  MachineFunction &MF = *MBB.getParent();

  return insertCFILabel(MF, MBB);
}

// Insert a CFI Label /after/ MI
bool X86GenesisLabelCFI::insertCFILabel(MachineInstr *MI) {
  MachineBasicBlock &MBB = *MI->getParent();
  MachineFunction &MF = *MBB.getParent();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  MachineBasicBlock::iterator MBBI(MI);

  // Reference: lib/Target/X86/X86MCInstLower.cpp
  unsigned BaseReg, ScaleVal, IndexReg, SegmentReg;
  BaseReg = X86::RAX; ScaleVal = 1;
  IndexReg = 0; SegmentReg = X86::CS;

  ++MBBI;
  BuildMI(MBB, MBBI, MI->getDebugLoc(), TII->get(X86::NOOPL))
    .addReg(BaseReg)
    .addImm(ScaleVal)
    .addReg(IndexReg)
    .addImm(CFILabel)
    .addReg(SegmentReg);

  return true;
}

// Insert a CFI Label as a first instruction in the MBB
bool X86GenesisLabelCFI::insertCFILabel(MachineFunction &MF, MachineBasicBlock &MBB) {
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  // Reference: lib/Target/X86/X86MCInstLower.cpp
  unsigned BaseReg, ScaleVal, IndexReg, SegmentReg;
  BaseReg = X86::RAX; ScaleVal = 1;
  IndexReg = 0; SegmentReg = X86::CS;

  BuildMI(MBB, MBB.begin(), DebugLoc(), TII->get(X86::NOOPL))
    .addReg(BaseReg)
    .addImm(ScaleVal)
    .addReg(IndexReg)
    .addImm(CFILabel)
    .addReg(SegmentReg);

  return true;
}

bool X86GenesisLabelCFI::insertForwardCheck(MachineInstr &MI,
                                             unsigned UsableReg,
                                             bool isMemOp)
{
  MachineBasicBlock &MBB = *MI.getParent();
  MachineFunction &MF = *MI.getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  const DebugLoc &DL = MI.getDebugLoc();

  // STEP #1: Split the current basic block into two
  MachineBasicBlock* NewMBB = MF.CreateMachineBasicBlock();
  MF.push_back(NewMBB);
  NewMBB->moveAfter(&MBB);
  NewMBB->transferSuccessors(&MBB);
  MBB.addSuccessor(NewMBB);
  NewMBB->splice(NewMBB->begin(), &MBB,
                 MachineBasicBlock::iterator(MI), MBB.end());

  // STEP #2: Retrieves the target address
  if (isMemOp) {
    // Case #1: memory-based indirect call
    //
    // Before Instrumentation
    // 1:    callq *0x4(%rbp)            MBB
    // -------------------------------------
    //
    // After Instrumentation
    // 1:    movq 0x4(%rbp), %tmp
    // 2:    cmpl $LABEL, OFFSET(%tmp)
    // 3:    jne .LFail                  MBB
    // -------------------------------------
    // 4:    callq %tmp
    //       ...                      NewMBB
    // -------------------------------------
    //   .LFail:
    //       ud2                 CFIErrorMBB
    // -------------------------------------
    // STEP #2-1: Find killable register
    assert(MI.getNumOperands() >= 5 && "Not Memory Op?");
    if (UsableReg == 0) {
      for (unsigned i = 0; i < MI.getNumOperands() && i < 5; i++) {
        const MachineOperand &MO = MI.getOperand(i);
        if (MO.isReg() && MO.isKill()) {
          UsableReg = MO.getReg();
          break;
        }
      }
    }

    // TODO: spill register
    if (UsableReg == 0) {
      errs() << "[-] " << MF.getName()
             << " There is no usable register\n";
      return true;
    }

    MachineInstrBuilder MBI;
    MBI = BuildMI(&MBB, DL, TII->get(X86::MOV64rm), UsableReg);
    for (unsigned i = 0; i < MI.getNumOperands() && i < 5; i++) {
      MBI.add(MI.getOperand(i));
    }
    MBI.cloneMemRefs(MI);
  } else {
    // Case #2: register-based indirect call
    //
    // Before Instrumentation
    // 1:    callq *%rax                 MBB
    // -------------------------------------
    //
    // After Instrumentation
    // 1:    cmpl $LABEL, OFFSET(%rax)
    // 2:    jne .Lfail                  MBB
    // -------------------------------------
    // 3:    callq *%rax              NewMBB
    //       ...
    // -------------------------------------
    //   .Lfail:
    //       ud2                 CFIErrorMBB
    // -------------------------------------
  }

  // STEP #3: Create a error handling basic block
  addRegOffset(BuildMI(&MBB, DL, TII->get(X86::CMP32mi)),
      UsableReg, false, CFILabelOffset).addImm(CFILabel);

  MachineBasicBlock *CFIErrorMBB = getOrInsertCFIErrorMBB(MF);
  MBB.addSuccessor(CFIErrorMBB);

  BuildMI(&MBB, DL, TII->get(X86::JCC_1))
    .addMBB(CFIErrorMBB)
    .addImm(X86::COND_NE);

  // STEP #4: Replace Mem-Op with Reg-Op
  if (isMemOp) {
    unsigned NewOpcode;
    switch (MI.getOpcode()) {
      case X86::CALL16m: NewOpcode = X86::CALL16r; break;
      case X86::CALL32m: NewOpcode = X86::CALL32r; break;
      case X86::CALL64m: NewOpcode = X86::CALL64r; break;
      case X86::CALL16m_NT: NewOpcode = X86::CALL16r_NT; break;
      case X86::CALL32m_NT: NewOpcode = X86::CALL32r_NT; break;
      case X86::CALL64m_NT: NewOpcode = X86::CALL64r_NT; break;
      case X86::JMP16m: NewOpcode = X86::JMP16r; break;
      case X86::JMP32m: NewOpcode = X86::JMP32r; break;
      case X86::JMP64m: NewOpcode = X86::JMP64r; break;
      case X86::JMP64m_REX: NewOpcode = X86::JMP64r_REX; break;
      case X86::JMP16m_NT: NewOpcode = X86::JMP16r_NT; break;
      case X86::JMP32m_NT: NewOpcode = X86::JMP32r_NT; break;
      case X86::JMP64m_NT: NewOpcode = X86::JMP64r_NT; break;
      case X86::TAILJMPm: NewOpcode = X86::TAILJMPr; break;
      case X86::TAILJMPm64: NewOpcode = X86::TAILJMPr64; break;
      case X86::TAILJMPm64_REX: NewOpcode = X86::TAILJMPr64_REX; break;

      default:
        llvm_unreachable("[-] Unexpected opcode");
    }

    MCSymbol *RetSymbol = MI.getPostInstrSymbol();
    MachineInstr *NewMI = BuildMI(*NewMBB, MI, DL, TII->get(NewOpcode))
                            .addReg(UsableReg, RegState::Kill);
    if (RetSymbol != nullptr)
      NewMI->setPostInstrSymbol(MF, RetSymbol);

    if (MI.isCandidateForCallSiteEntry())
      MF.moveCallSiteInfo(&MI, NewMI);

    for (unsigned i = MI.getDesc().getNumOperands(), e = MI.getNumOperands();
        i != e; ++i) {
      const MachineOperand &MO = MI.getOperand(i);
      if ((MO.isReg() && MO.isImplicit() && MO.isDef())
          || MO.isRegMask())
        NewMI->addOperand(MF, MO);
    }
    //NewMI->copyImplicitOps(MF, MI);

    MI.eraseFromParent();
  }

  return true;
}

bool X86GenesisLabelCFI::insertBackwardCheck(MachineInstr &MI,
                                             unsigned UsableReg)
{
  MachineBasicBlock &MBB = *MI.getParent();
  MachineFunction &MF = *MI.getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  const DebugLoc &DL = MI.getDebugLoc();

  /*
   *  Before Instrumentation
   *  1:    ret                    MBB
   *  --------------------------------
   *
   *  After Instrumentation
   *  1:    movq (%rsp), %tmp
   *  2:    cmpl $LABEL, OFFSET(%tmp)
   *  3:    jne .Lfail             MBB
   *  --------------------------------
   *  4:    add $8, %rsp
   *  5:    jmpq %TmpReg        RetMBB
   *  --------------------------------
   *  6:  .Lfail:
   *  7:    ud2            CFIErrorMBB
   *  --------------------------------
   */

  // STEP #1: Create RetMBB
  MachineBasicBlock &RetMBB = *MF.CreateMachineBasicBlock();
  MF.push_back(&RetMBB);
  RetMBB.moveAfter(&MBB);
  MBB.addSuccessor(&RetMBB);
  RetMBB.splice(RetMBB.begin(), &MBB, MachineBasicBlock::iterator(MI));

  // STEP #2: Create CFIErrorMBB
  MachineBasicBlock *CFIErrorMBB = getOrInsertCFIErrorMBB(MF);
  MBB.addSuccessor(CFIErrorMBB);

  // STEP #3: Check CFI Label
  BuildMI(&MBB, DL, TII->get(X86::MOV64rm), UsableReg)
      .addReg(/*Base*/ X86::RSP)
      .addImm(/*Scale*/ 1)
      .addReg(/*Index*/ 0)
      .addImm(/*Displacement*/ 0)
      .addReg(/*Segment*/ 0);

  addRegOffset(BuildMI(&MBB, DL, TII->get(X86::CMP32mi)),
      UsableReg, false, CFILabelOffset).addImm(CFILabel);

  BuildMI(&MBB, DL, TII->get(X86::JCC_1))
    .addMBB(CFIErrorMBB)
    .addImm(X86::COND_NE);

  // STEP #4: Convert RETQ to TAILJMPr64
  BuildMI(RetMBB, MI, DL, TII->get(X86::ADD64ri8), X86::RSP)
      .addReg(X86::RSP)
      .addImm(8);

  BuildMI(RetMBB, MI, DL, TII->get(X86::TAILJMPr64))
      .addReg(UsableReg, RegState::Kill);

  MI.eraseFromParent();

  return true;
}

MachineBasicBlock *X86GenesisLabelCFI::getOrInsertCFIErrorMBB(MachineFunction &MF)
{
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  DebugLoc Loc;

  if (this->CFIErrorMBB != nullptr) {
    return this->CFIErrorMBB;
  }

  MachineBasicBlock *CFIErrorMBB = MF.CreateMachineBasicBlock();
  assert(CFIErrorMBB && "[-] Failed to create MBB");
  this->CFIErrorMBB = CFIErrorMBB;
  MF.push_back(CFIErrorMBB);

  MachineBasicBlock::iterator InsertionPt = CFIErrorMBB->begin();

  BuildMI(*CFIErrorMBB, InsertionPt, Loc, TII->get(X86::TRAP));

  return CFIErrorMBB;
}

bool X86GenesisLabelCFI::enforceForwardLabelCFI(IndirectBranches &IndirectBranches)
{
  bool Changed;

  // Enforce forward CFI on indirect branches
  for (auto &p : IndirectBranches) {
    MachineInstr *MI = get<0>(p);
    unsigned Reg = get<1>(p);
    bool isMemOp = get<2>(p);

    Changed |= insertForwardCheck(*MI, Reg, isMemOp);
  }

  return Changed;
}

bool X86GenesisLabelCFI::enforceBackwardLabelCFI(CallInstrs &CallInstrs,
                             ReturnInstrs &ReturnInstrs)
{
  bool Changed = false;

  // STEP #1: Insert a CFI label after CALL instruction
  for (MachineInstr *CI : CallInstrs) {
    assert(CI != nullptr && "CI is nullptr");
    Changed |= insertCFILabel(CI);
  }

  // STEP #2: Instrument RET instructipon
  for (auto &p : ReturnInstrs) {
    MachineInstr *RI = get<0>(p);
    unsigned UsableReg = get<1>(p);

    Changed |= insertBackwardCheck(*RI, UsableReg);
  }

  return Changed;
}

bool X86GenesisLabelCFI::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;

  MachineModuleInfo &MMI = MF.getMMI();
  const Module *M = MMI.getModule();
  const Function &F = MF.getFunction();

  // XXX: find better way
  this->CFIErrorMBB = nullptr;

  // PRE-STEP #1: Check blacklist
  unique_ptr<SpecialCaseList> Blacklist = nullptr;
  if (option_no_instrument_blacklist != "-")
  {
    vector<string> paths;
    paths.push_back(option_no_instrument_blacklist);
    string err;
    Blacklist = SpecialCaseList::create(paths,
        *vfs::getRealFileSystem(), err);
  }

  if (isBlacklisted(Blacklist.get(), M))
    return Changed;

  if (isBlacklisted(Blacklist.get(), &F))
    return Changed;

  // PRE-STEP #2: Check target (64-bit only)
  const X86Subtarget &STI = MF.getSubtarget<X86Subtarget>();
  if (!STI.isTarget64BitLP64()) {
    errs() << "[+] Unsupported architecture! ("
           << M->getModuleIdentifier() << ")\n";
    return Changed;
  }

  // PRE-STEP #3: Do not instrument  __head section
  if(isBlacklistedSection(F))
    return Changed;

  // STEP #1: Find all instructions that we need to instrument
  vector<MachineInstr *> CallInstrs;
  vector<pair<MachineInstr *, unsigned>> ReturnInstrs;
  vector<tuple<MachineInstr *, unsigned, bool>> IndirectBranches;
  getInterestingInsts(MF, CallInstrs, ReturnInstrs, IndirectBranches);

  // STEP #2: Enforce backward label-based CFI
  if (!EnableGenesisShadowStack) {
    Changed |= enforceBackwardLabelCFI(CallInstrs, ReturnInstrs);
  }

  // STEP #3: Enforce forward label-based CFI
  Changed |= enforceForwardLabelCFI(IndirectBranches);

  // STEP #4-1: Insert CFI labels at the beginning of functions
  if ((!F.hasInternalLinkage() && !F.hasPrivateLinkage()) ||
      F.hasAddressTaken()) {
    if (MF.begin() != MF.end()) {
      Changed |= insertCFILabelInFunction(MF);
    }
  }

  // STEP #4-2: Insert CFI labels at jump targets
  SmallSet<MachineBasicBlock *, 12> Visited;
  if (MachineJumpTableInfo *JtInfo = MF.getJumpTableInfo()) {
    const vector<MachineJumpTableEntry> &JT = JtInfo->getJumpTables();
    for (unsigned I = 0; I < JT.size(); ++I) {
      const vector<MachineBasicBlock *> &MBBs = JT[I].MBBs;

      for (unsigned J = 0; J < MBBs.size(); ++J) {
        if (!Visited.count(MBBs[J])) {
          Changed |= insertCFILabelInJumpTarget(*MBBs[J]);
          Visited.insert(MBBs[J]);
        }
      }
    }
  }

  // STEP #4-3: Insert CFI labels at address-taken basic blocks
  for (auto &MBB : MF) {
    if (MBB.hasAddressTaken() && !Visited.count(&MBB))
      Changed |= insertCFILabelInJumpTarget(MBB);
  }

  return Changed;
}

char X86GenesisLabelCFI::ID = 0;
namespace llvm {
  FunctionPass * createX86GenesisLabelCFI(void) {
    return new X86GenesisLabelCFI();
  }
}
