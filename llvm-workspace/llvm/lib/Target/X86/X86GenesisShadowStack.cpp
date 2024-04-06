#include "X86GenesisShadowStack.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86RegisterInfo.h"
#include "X86InstrBuilder.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SpecialCaseList.h"

#define PASS_KEY "x86-shadow-stack"
#define DEBUG_TYPE PASS_KEY

STATISTIC(NumRetInstr, "Number of RET instrunctions");
STATISTIC(NumCallInstr, "Number of CALL instrunctions");
STATISTIC(NumRetNoAvailReg, "Number of RET that has no available register");
STATISTIC(NumCallNoAvailReg, "Number of CALL that has no available register");

using namespace llvm;
using namespace std;

extern cl::opt<string> option_no_instrument_blacklist;

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

bool X86GenesisShadowStack::instrumentCallInstr(MachineInstr *MI,
                                                unsigned ScratchReg)
{
  MachineBasicBlock &MBB = *MI->getParent();
  MachineFunction &MF = *MI->getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  const DebugLoc &DL = MI->getDebugLoc();

  bool Spilled = (ScratchReg == 0);

  /*
   * TODO: cli/sti
   * Call Instrumentation
   *
   * +   pushq %tmp [optional]
   * +   leaq .LRet(%rip), %tmp
   * +   stac
   * +   mov %tmp, -0x4000(%rsp) ;If spilled -0x3ff8(%rsp)
   * +   clac
   * +   popq %tmp
   *     call <target>
   * + .LRet:
   */

  if (Spilled) {
    ScratchReg = X86::RAX;

    BuildMI(MBB, MI, DL, TII->get(X86::PUSH64r))
        .addReg(ScratchReg);
    NumCallNoAvailReg++;
  }

  MCSymbol *RetSymbol =
    MF.getContext().createTempSymbol("shdw_ret_addr", true);

  MI->setPostInstrSymbol(MF, RetSymbol);

  BuildMI(MBB, MI, DL, TII->get(X86::LEA64r), ScratchReg)
    .addReg(/*Base*/ X86::RIP)
    .addImm(/*Scale*/ 1)
    .addReg(/*Index*/ 0)
    .addSym(RetSymbol)
    .addReg(/*Segment*/ 0);

  BuildMI(MBB, MI, DL, TII->get(X86::STAC));

  int ShadowStackOffset = PARALLEL_OFFSET + (Spilled ? 8 : 0);
  addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr)),
               X86::RSP, false, ShadowStackOffset)
      .addReg(ScratchReg);

  BuildMI(MBB, MI, DL, TII->get(X86::CLAC));

  if (Spilled) {
    BuildMI(MBB, MI, DL, TII->get(X86::POP64r))
      .addReg(ScratchReg);
  }

  return true;
}

bool X86GenesisShadowStack::instrumentRetInstr(MachineInstr *MI,
                                               unsigned ScratchReg)
{
  MachineBasicBlock &MBB = *MI->getParent();
  MachineFunction &MF = *MI->getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  const DebugLoc &DL = MI->getDebugLoc();

  /* Before Instrumentation
   *
   *    retq
   * -------------------
   * After Instrumentation
   *
   *    stac
   *    movq -0x4000(%rsp), %TmpReg
   *    clac
   *    add $8, %rsp
   *    jmpq *%TmpReg
   */

  BuildMI(MBB, MI, DL, TII->get(X86::STAC));

  BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), ScratchReg)
      .addReg(/*Base*/ X86::RSP)
      .addImm(/*Scale*/ 1)
      .addReg(/*Index*/ 0)
      .addImm(/*Displacement*/ PARALLEL_OFFSET + 8)
      .addReg(/*Segment*/ 0);

  BuildMI(MBB, MI, DL, TII->get(X86::CLAC));

#if (0) // Useful for debugging
  /*
   *    stac
   *    movq -0x4000(%rsp), %TmpReg
   *    clac
   *    cmpq %TmpReg, (%rsp)
   *    jne .LFail
   *  .Lsuccess:
   *    add $8, %rsp
   *    jmpq *%TmpReg
   *
   *    ...
   *
   *  .LFail:
   *    ud2
   */
  MachineBasicBlock* NewMBB = MF.CreateMachineBasicBlock();
  MF.push_back(NewMBB);
  NewMBB->moveAfter(&MBB);
  MBB.addSuccessor(NewMBB);
  NewMBB->splice(NewMBB->begin(), &MBB,
                 MachineBasicBlock::iterator(MI), MBB.end());

  MachineBasicBlock* ErrorMBB = MF.CreateMachineBasicBlock();
  MF.push_back(ErrorMBB);
  MBB.addSuccessor(ErrorMBB);
  BuildMI(*ErrorMBB, ErrorMBB->begin(), DL, TII->get(X86::TRAP));

  BuildMI(&MBB, DL, TII->get(X86::CMP64rm), ScratchReg)
    .addReg(/*Base*/ X86::RSP)
    .addImm(/*Scale*/ 1)
    .addReg(/*Index*/ 0)
    .addImm(/*Displacement*/ 0)
    .addReg(/*Segment*/ 0);

  BuildMI(&MBB, DL, TII->get(X86::JCC_1))
    .addMBB(ErrorMBB)
    .addImm(X86::COND_NE);

  BuildMI(*NewMBB, MI, DL, TII->get(X86::ADD64ri8), X86::RSP)
      .addReg(X86::RSP)
      .addImm(8);

  BuildMI(*NewMBB, MI, DL, TII->get(X86::TAILJMPr64))
      .addReg(ScratchReg, RegState::Kill)
      .setCFIFlag(MachineInstr::ShdwStkRet);

  MI->eraseFromParent();

  return true;
#endif

  // XXX: LEA is better?
  BuildMI(MBB, MI, DL, TII->get(X86::ADD64ri8), X86::RSP)
      .addReg(X86::RSP)
      .addImm(8);

  BuildMI(MBB, MI, DL, TII->get(X86::TAILJMPr64))
      .addReg(ScratchReg, RegState::Kill)
      .setCFIFlag(MachineInstr::ShdwStkRet);

  MI->eraseFromParent();

  return true;
}

bool X86GenesisShadowStack::runOnMachineFunction(MachineFunction &MF)
{
  bool Changed = false;

  MachineModuleInfo &MMI = MF.getMMI();
  const Module *M = MMI.getModule();
  const Function &F = MF.getFunction();

  // PRE STEP #1: Check blacklist
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
    errs() << "[-] Unsupported architecture! ("
           << M->getModuleIdentifier() << ")\n";
    return Changed;
  }

  // PRE-STEP #3: Do not instrument  __head section
  if(isBlacklistedSection(F))
    return Changed;

  // STEP #1: Find all interesting CALL/RET instrs
  vector<pair<MachineInstr *, unsigned>> CallInstrs;
  vector<pair<MachineInstr *, unsigned>> ReturnInstrs;
  for (MachineBasicBlock &MBB: MF) {
    RegScavenger RS;
    RS.enterBasicBlock(MBB);
    for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); I++) {
      MachineInstr *MI = &*I;

      if (!MI->isCall() && !MI->isReturn())
        continue;

      if (I != MBB.begin())
        RS.forward(std::prev(I));

      unsigned UnusedReg = RS.FindUnusedReg(&X86::GR64RegClass);

      switch(MI->getOpcode()) {
      case X86::RETQ:
      {
        assert(UnusedReg != 0 && "No available Reg at RET");
        ReturnInstrs.push_back(make_pair(MI, UnusedReg));
        NumRetInstr++;
        break;
      }

      case X86::TAILJMPd:
      case X86::TAILJMPr:
      case X86::TAILJMPm:
      case X86::TAILJMPd_CC:
      case X86::TAILJMPd64:
      case X86::TAILJMPr64:
      case X86::TAILJMPm64:
      case X86::TAILJMPr64_REX:
      case X86::TAILJMPm64_REX:
      case X86::TAILJMPd64_CC:
      {
        break;
      }

      case X86::CALL64r:
      case X86::CALL64m:
      case X86::CALL64pcrel32:
      {
#if (1) // Useful for debugging
        if (MI->getOpcode() == X86::CALL64pcrel32) {
          MachineOperand &MO = MI->getOperand(0);
	  if (MO.isGlobal()){
	    const GlobalValue *GV = MO.getGlobal();
	    if (GV->hasName() && (GV->getName() == "__stack_chk_fail"))
              continue;
	  }
	}
#endif

        CallInstrs.push_back(make_pair(MI, UnusedReg));
        NumCallInstr++;
        break;
      }

      // TODO: compatible with spectre defenses

      default:
        if (MI->isReturn() || MI->isCall()) {
          errs () << "MI: " << *MI;
          report_fatal_error("Unexpected Return instruction");
        }
      }
    }
  }

  // STEP #2: Instrument CALL instructions
  for (auto &p : CallInstrs) {
    MachineInstr *MI = get<0>(p);
    unsigned Reg = get<1>(p);

    Changed |= instrumentCallInstr(MI, Reg);
  }

  // STEP #3: Instrument RET instructions
  for (auto &p : ReturnInstrs) {
    MachineInstr *MI = get<0>(p);
    unsigned Reg = get<1>(p);

    Changed |= instrumentRetInstr(MI, Reg);
  }

  return Changed;
}

StringRef X86GenesisShadowStack::getPassName() const {
  return "X86 Genesis Shadow Stack Pass";
}

char X86GenesisShadowStack::ID = 0;
namespace llvm {
  FunctionPass *createX86GenesisShadowStack(void) {
    return new X86GenesisShadowStack();
  }
}
