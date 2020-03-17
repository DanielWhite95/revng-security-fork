#ifndef REVNG_LOOP_DEPENDENCIES_PASS
#define REVNG_LOOP_DEPENDENCIES_PASS

#include "llvm/ADT/Statistic.h"
#define DEBUG_TYPE "LoopDependenciesPass"
STATISTIC(LDPSkippedFunctions, "Number of functions Skipped by Loop Dependencies pass");
STATISTIC(FilteredStores, "Number of candidate risky stores");
STATISTIC(TotalLoops, "Number of loops found");
STATISTIC(CandidateLoops, "Number of loops with dangerous condition");
STATISTIC(VulnerableFunctions, "Number of function with at least one risky store");
STATISTIC(InputVulnerableFunctions, "Number of function with at least one risky store and reached by input");
STATISTIC(OverallFunctions, "Number of overall functions analyzed");

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
#include <ostream>
#include <vector>
#include <map>
#include "revng/Support/SecurityDefinitions.h"
#include "revng/Support/CommandLine.h"
#include "RevngFunctionParamsPass.h"
#include "FunctionParamsUsagePass.h"


using namespace llvm;

  /// Collect information about translated and isolated functions
namespace revng {




  class LoopDependenciesPass : public FunctionPass {
  public:
    static char ID;
    LoopDependenciesPass();
    virtual ~LoopDependenciesPass() {};
    virtual bool runOnFunction(Function &F) override;
    virtual void getAnalysisUsage(AnalysisUsage &AU) const override;
    virtual void print(raw_ostream &OS, const Module *M) const override;
    virtual bool doInitialization(Module &) override;
    virtual bool doFinalization(Module &) override;
    DefUseChain traverseBackwardDefUseChain(const User*);
    bool isFunctionSafe() const;
    json::Object toJSON() const;
	  std::map<const StringRef, VulnerableLoopItem*> getVulnerableLoops() const { return this->vulnerableLoops; };
	  unsigned int getNumRiskyStores() const {
		  unsigned int counter = 0;
		  for(auto VI : vulnerableLoops) {
			  counter +=  VI.second->second.size();
		  }
		  return counter;
	  }

  private:
    std::vector<const Instruction*> candidateBranches;
    std::map<const StringRef, VulnerableLoopItem*> vulnerableLoops;
    bool analyzeLoopBasicBlock(const BasicBlock*, FunctionParamsUsagePass&);
    bool analyzeLoop(const Loop*, FunctionParamsUsagePass&, VulnerableLoopItem&);
    bool analyzeLoopCondition(const CmpInst* , FunctionParamsUsagePass&);
    void dumpAnalysis(raw_fd_ostream &FOS, Function &F) const;
    const RevngFunction *currentRF;
 };


}

#endif // REVNG_LOOP_DEPENDENCIES_PASS
