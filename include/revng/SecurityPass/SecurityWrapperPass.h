#ifndef REVNG_SECURITY_WRAPPER_PASS
#define REVNG_SECURITY_WRAPPER_PASS

#include "llvm/ADT/Statistic.h"
#include "llvm/Pass.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/JSON.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include <queue>
#include <ostream>
#include <vector>
#include <map>

#include "revng/Support/CommandLine.h"
#include "revng/Support/SecurityDefinitions.h"

#include "LoopDependenciesPass.h"
#include "FunctionParamsUsagePass.h"
#include "RevngFunctionParamsPass.h"
#include "FunctionParamsUsagePass.h"


using namespace llvm;

  /// Collect information about translated and isolated functions
namespace revng {

  json::Object* AnalysisOutputJSON;

  class SecurityWrapperPass : public FunctionPass {
  public:
    static char ID;
    SecurityWrapperPass();
    virtual ~SecurityWrapperPass() {};
    virtual bool runOnFunction(Function &F) override;
    virtual void getAnalysisUsage(AnalysisUsage &AU) const override;
    virtual void print(raw_ostream &OS, const Module *M) const override;
	  void printFunctionInfo(Function &F) const;
    virtual bool doInitialization(Module &) override;
    virtual bool doFinalization(Module &) override;
    bool updateJSON(Function* F);

  private:
    LoopDependenciesPass *LDP = nullptr;
    FunctionParamsUsagePass *FPU = nullptr;
    RevngFunctionParamsPass *RFP = nullptr;
    // BackwardPropagationPass *BPP = nullptr;
    const RevngFunction *currentRF;
 };


}

#endif // REVNG_SECURITY_WRAPPER_PASS
