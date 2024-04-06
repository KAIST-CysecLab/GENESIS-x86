#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SpecialCaseList.h"

#include <iostream>

using namespace llvm;
using namespace std;

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

typedef vector<tuple<Instruction *, unsigned, unsigned>> Plan;

static cl::opt<string> option_no_instrument_blacklist(
    "nested-kernel-blacklist",
    cl::desc("Do not intercept privilege instructions"
      "in the functions/modules specified in the given blacklist"),
    cl::init("-"));

static void addToPlan(Instruction *I, unsigned Kind, bool IsPrivInst, Plan &plan) {
  plan.push_back(make_tuple(I, Kind, IsPrivInst));
}

#define INSTRUMENT_SENSITIVE_OPERATION(FuncName, SensitiveFunc, PrivEnum, IsPrivInst, I, plan) do {  \
  if(FuncName.equals(SensitiveFunc)) {                                    \
    addToPlan(I, PrivEnum, IsPrivInst, plan);                             \
    return;                                                               \
  }                                                                       \
} while (0);

static void replaceFunctionCall(Module *M, StringRef OldName, StringRef NewName)
{
  Function *OldFunc = M->getFunction(OldName);
  if (OldFunc != nullptr) {
    FunctionCallee NewFunc = M->getOrInsertFunction(NewName,
        OldFunc->getFunctionType());
    OldFunc->replaceAllUsesWith(NewFunc.getCallee()->stripPointerCasts());
  }
}

static void replaceSensitiveFunction(Module *M)
{
  // page table (de)allocation
  replaceFunctionCall(M, "pgd_alloc", "nk_pgd_alloc");
  replaceFunctionCall(M, "pgd_free",  "nk_pgd_free");
  replaceFunctionCall(M, "p4d_alloc_one", "nk_p4d_alloc_one");
  replaceFunctionCall(M, "p4d_free", "nk_p4d_free");
  replaceFunctionCall(M, "pud_alloc_one", "nk_pud_alloc_one");
  replaceFunctionCall(M, "pud_free", "nk_pud_free");
  replaceFunctionCall(M, "pud_free_pmd_page", "nk_pud_free_pmd_page"); // XXX: test
  replaceFunctionCall(M, "pmd_alloc_one", "nk_pmd_alloc_one");
  replaceFunctionCall(M, "pmd_free", "nk_pmd_free");
  replaceFunctionCall(M, "pmd_free_pte_page", "nk_pmd_free_pte_page");

  // batch free
  replaceFunctionCall(M, "__tlb_remove_page_size", "nk__tlb_remove_page_size");

  // initialization
  replaceFunctionCall(M, "alloc_low_pages", "nk_alloc_low_pages");
  replaceFunctionCall(M, "spp_getpage", "nk_spp_getpage");

  // pgd_ctor XXX: find a better way
  replaceFunctionCall(M, "pgd_ctor", "nk_pgd_ctor");

  replaceFunctionCall(M, "copy_user_generic_unrolled", "nk_copy_user_generic_unrolled");
  replaceFunctionCall(M, "copy_user_generic_string", "nk_copy_user_generic_string");
  replaceFunctionCall(M, "copy_user_enhanced_fast_string", "nk_copy_user_enhanced_fast_string");
  replaceFunctionCall(M, "__copy_user_nocache", "nk__copy_user_nocache");
}

static void  getSensitiveOperations(Instruction *I, Plan &plan)
{
  if (CallInst *CI = dyn_cast<CallInst>(I)) {
    Function *F = CI->getCalledFunction();

    if (F == nullptr || !F->hasName())
      return;

    StringRef Name = F->getName();
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_write_cr0", NK_WRITE_CR0, true, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_write_cr3", NK_WRITE_CR3, true, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_write_cr4", NK_WRITE_CR4, true, I, plan);

    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_write_msr", NK_WRITE_MSR, true, I, plan);

    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_pgd", NK_SET_PGD, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_p4d", NK_SET_P4D, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_pud", NK_SET_PUD, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_pmd", NK_SET_PMD, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_pte", NK_SET_PTE, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_pte_atomic", NK_SET_PTE, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_set_pte_at", NK_SET_PTE_AT, false, I, plan);

    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_pgd_clear", NK_PGD_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_p4d_clear", NK_P4D_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_pud_clear", NK_PUD_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_pmd_clear", NK_PMD_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_pte_clear", NK_PTE_CLEAR, false, I, plan);

    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_pudp_get_and_clear", NK_PUDP_GET_AND_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_pmdp_get_and_clear", NK_PMDP_GET_AND_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "native_ptep_get_and_clear", NK_PTEP_GET_AND_CLEAR, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "ptep_set_wrprotect", NK_PTEP_SET_WRPROTECT, false, I, plan);

    INSTRUMENT_SENSITIVE_OPERATION(Name, "pmdp_set_wrprotect", NK_PMDP_SET_WRPROTECT, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "pudp_test_and_clear_young", NK_PUDP_TEST_AND_CLEAR_YOUNG, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "pmdp_test_and_clear_young", NK_PMDP_TEST_AND_CLEAR_YOUNG, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "ptep_test_and_clear_young", NK_PTEP_TEST_AND_CLEAR_YOUNG, false, I, plan);
    INSTRUMENT_SENSITIVE_OPERATION(Name, "pmdp_establish", NK_PMDP_ESTABLISH, false, I, plan);
  }
}

static void interceptSensitiveOperation(Module *M, Instruction *I,
                                        unsigned Kind, bool IsPrivInst)
{
  CallInst *CI = dyn_cast<CallInst>(I);
  Function *CalledFunc = CI->getCalledFunction();

  // (1): Declare Entry Gate Function
  SmallVector<Type*,4> ParamsType;
  SmallVector<std::pair<unsigned, Attribute>, 4> ParamsAttrs;
  const AttributeList& PAL = CalledFunc->getAttributes();

  // (1-1): Create New function type Info
  // e.g.,  write_cr3(long val); --> nk_entry(enum WRITE_CR3, long val)

  // Set First Param Type
  ParamsType.push_back(Type::getInt64Ty(M->getContext()));
  for(auto arg = CalledFunc->arg_begin(), argend = CalledFunc->arg_end();
      arg != argend; ++arg) {
    ParamsType.push_back(arg->getType());
  }

  // XXX: assume that nk_entry always returns 64-bit integer
  FunctionType *FTy = FunctionType::get(CalledFunc->getReturnType(),
      ParamsType, /* isVarArg */ false);

  // (1-2): Prepare arguments
  IRBuilder<> IRB(I->getNextNode());

  SmallVector<Value*,4> ArgsVec;
  ConstantInt *FuncID = IRB.getInt64(Kind);
  ArgsVec.push_back(FuncID);
  for (unsigned i = 0; i < CI->getNumArgOperands(); i++) {
    ArgsVec.push_back(CI->getArgOperand(i));
  }

  // (1-3) Finally declare the entry gate
  StringRef EntryName = IsPrivInst ? "__nk_priv_entry" :"__nk_entry";
  FunctionCallee NkEntryGate = M->getOrInsertFunction(EntryName, FTy);

  // (2): Jump to entry gate
  CallInst *NewCall = IRB.CreateCall(NkEntryGate, ArgsVec);
  I->replaceAllUsesWith(NewCall);
  I->eraseFromParent();
}

static void instrumentInlinedFunction(Module *M, Function *F)
{
  StringRef Name = F->getName();

  /* pte_alloc_one IR example
   *  Function Attrs: noredzone nounwind null_pointer_is_valid sspstrong
   *  define dso_local %struct.page* @pte_alloc_one(%struct.mm_struct* %mm) #0 !dbg !5767 {
   *  entry:
   *     call void @llvm.dbg.value(metadata %struct.mm_struct* %mm, metadata !5771, metadata !DIExpression()), !dbg !5772
   *     %0 = load i32, i32* @__userpte_alloc_gfp, align 4, !dbg !5773
   *     %call = call %struct.page* @__pte_alloc_one(%struct.mm_struct* %mm, i32 %0) #11, !dbg !5774
   *     ret %struct.page* %call, !dbg !5775
   *   }
   */
  if (Name.equals("pte_alloc_one"))
  {
    CallInst *CI = nullptr;
    for(auto &BB: *F)
      for(auto &I: BB) {
        if ((CI = dyn_cast<CallInst>(&I)) != nullptr) {
          Function *CalledFunc = CI->getCalledFunction();
          if (CalledFunc->getName().startswith("__pte_alloc_one"))
            break;
          else
            CI = nullptr;
        }
      }

    assert(CI != nullptr && "CallInst is NULL");

    IRBuilder<> IRB(CI->getNextNode());
    Function *PTEAllocFunc = CI->getCalledFunction();
    FunctionType *FTy = FunctionType::get(IRB.getInt8PtrTy(),
         { PTEAllocFunc->getReturnType() }, /* isVarArg */ false);

    FunctionCallee PTEProtectFunc =
      M->getOrInsertFunction("nk_protect_pte_one", FTy);

    IRB.CreateCall(PTEProtectFunc, { CI });

    return;
  }

  if (Name.equals("pte_alloc_one_kernel"))
  {
    CallInst *CI = nullptr;
    for(auto &BB: *F)
      for(auto &I: BB) {
        if ((CI = dyn_cast<CallInst>(&I)) != nullptr) {
          Function *CalledFunc = CI->getCalledFunction();
          if (CalledFunc->getName().startswith("__pte_alloc_one_kernel"))
            break;
          else
            CI = nullptr;
        }
      }

    assert(CI != nullptr && "CallInst is NULL");

    IRBuilder<> IRB(CI->getNextNode());
    Function *PTEAllocFunc = CI->getCalledFunction();
    FunctionType *FTy = FunctionType::get(IRB.getInt8PtrTy(),
         { PTEAllocFunc->getReturnType() }, /* isVarArg */ false);

    FunctionCallee PTEProtectFunc =
      M->getOrInsertFunction("nk_protect_pte_one_kernel", FTy);

    IRB.CreateCall(PTEProtectFunc, { CI });

    return;
  }

  if (Name.equals("pte_free"))
  {
    CallInst *CI = nullptr;
    for(auto &BB: *F)
      for(auto &I: BB) {
        if ((CI = dyn_cast<CallInst>(&I)) != nullptr) {
          Function *CalledFunc = CI->getCalledFunction();
          if (CalledFunc->getName().startswith("__free_page"))
            break;
          else
            CI = nullptr;
        }
      }

    assert(CI != nullptr && "CallInst is NULL");

    IRBuilder<> IRB(CI);
    FunctionType *FTy = FunctionType::get(IRB.getVoidTy(),
         { CI->getOperand(0)->getType() }, /* isVarArg */ false);

    FunctionCallee PTEUnprotectFunc =
      M->getOrInsertFunction("nk_unprotect_pte_one", FTy);

    IRB.CreateCall(PTEUnprotectFunc, { CI->getOperand(0) });

    return;
  }

  if (Name.equals("pte_free_kernel"))
  {
    CallInst *CI = nullptr;
    for(auto &BB: *F) {
      for(auto &I: BB) {
        if ((CI = dyn_cast<CallInst>(&I)) != nullptr) {
          Function *CalledFunc = CI->getCalledFunction();
          if (CalledFunc->getName().startswith("free_page"))
            break;
          else
            CI = nullptr;
        }
      }
    }

    assert(CI != nullptr && "CallInst is NULL");

    IRBuilder<> IRB(CI);
    FunctionType *FTy = FunctionType::get(IRB.getVoidTy(),
         { CI->getOperand(0)->getType() }, /* isVarArg */ false);

    FunctionCallee PTEUnprotectFunc =
      M->getOrInsertFunction("nk_unprotect_pte_one_kernel", FTy);

    IRB.CreateCall(PTEUnprotectFunc, { CI->getOperand(0) });

    return;
  }

  return;
}

/*
 * Blacklist checking.
 */
static bool isBlacklisted(SpecialCaseList *SCL, Module *M)
{
  if (SCL == nullptr)
    return false;
  if (SCL->inSection("", "src", M->getModuleIdentifier()))
    return true;
  return false;
}
static bool isBlacklisted(SpecialCaseList *SCL, Function *F)
{
  if (SCL == nullptr)
    return false;
  return SCL->inSection("", "fun", F->getName());
}

namespace {
  struct NestedKernel : public ModulePass {
    static char ID;
    NestedKernel() : ModulePass(ID) {}

    bool runOnModule(Module& M) override
    {
      // (1) Check blacklist
      unique_ptr<SpecialCaseList> Blacklist = nullptr;
      if (option_no_instrument_blacklist != "-")
      {
        vector<string> paths;
        paths.push_back(option_no_instrument_blacklist);
        string err;
        Blacklist = SpecialCaseList::create(paths,
            *vfs::getRealFileSystem(), err);
      }
      if (isBlacklisted(Blacklist.get(), &M))
        return true;

      replaceSensitiveFunction(&M);

      Plan plan;
      for (auto &F: M) {
        if (F.isDeclaration())
          continue;

        // special case of inlined functions
        // pte_alloc_one, pte_alloc_one_kernel, pte_free, pte_free_kernel
        instrumentInlinedFunction(&M, &F);

        if (isBlacklisted(Blacklist.get(), &F))
          continue;

        // functions in '.init.text' section are used for initialization.
	      /*
        if (F.hasSection()) {
          StringRef Section(F.getSection());
          if (Section.startswith(".init.text") ||
              Section.startswith(".meminit.text"))
            continue;
        }
	      */

        for(auto &BB: F)
          for(auto &I: BB)
            getSensitiveOperations(&I, plan);
      }

      if (plan.empty()) return false;

      for (auto &p: plan) {
        interceptSensitiveOperation(&M, get<0>(p), get<1>(p), get<2>(p));
      }

      return true;
    }
  };
} /* anonymous namespace */

char NestedKernel::ID = 0;
ModulePass* llvm::createNestedKernelPass() { return new NestedKernel(); }
