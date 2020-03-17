#ifndef REVNG_FUNCTION_PARAMS_USAGE_PASS
#define REVNG_FUNCTION_PARAMS_USAGE_PASS

#include "llvm/ADT/Statistic.h"
#define DEBUG_TYPE "FunctionParamsUsagePass"
STATISTIC(FPUSkippedFunctions, "Number of functions skipped by Function Params Usage Pass");
STATISTIC(TotalStackChains, "Number of defuse chains found for stack");
STATISTIC(TotalVarChains, "Number of defuse chains found for parameters");
STATISTIC(TotalStores, "Number of stores depending on params found");

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
#include "llvm/IR/ValueSymbolTable.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/JSON.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"

#include <ostream>
#include <vector>
#include <queue>

#include "revng/Support/SecurityDefinitions.h"
#include "revng/Support/CommandLine.h"
#include "RevngFunctionParamsPass.h"



using namespace llvm;

/// Collect information about translated and isolated functions
namespace revng {

	class FunctionParamsUsagePass : public FunctionPass {
	public:
		static char ID;
		FunctionParamsUsagePass();
		virtual ~FunctionParamsUsagePass() {};
		virtual bool runOnFunction(Function &F) override;
		virtual void getAnalysisUsage(AnalysisUsage &AU) const override;
		virtual void print(raw_ostream &OS, const Module *M) const override;

		std::vector<DefUse> traverseDefUseChain(const Value *V) const;
		bool isaUserOfParams(const User *U) const;
		const std::vector<RiskyStore> getRiskyStores() const { return this->currentRiskyStores;}
		bool doInitialization(Module &M) override;
		bool doFinalization(Module &M) override;
		json::Object toJSON();

	private:
		const CallGraph* moduleCG = nullptr; // build local call graph on start
		const Function* currentF = nullptr;
		bool isaUserOfParameter(const User *U,const Value *P) const;
		bool isaRiskyStore(const DefUse &DU) const;
		void printOperandsRange(raw_ostream &OS, const Instruction *UR) const;
		void printValueRange(raw_ostream &OS, Value *V,const  BasicBlock* context) const;
		void dumpAnalysis(raw_fd_ostream &FOS, Function &F) const;
		std::vector<VariableFlow> currentVarsFlows;
		std::vector<StackVarFlow> currentStackVarsFlows;
		std::vector<RiskyStore> currentRiskyStores;
		// std::vactor<VariableFlow> getVarsFlows();
		// std::vector<StackVarFlow> getStackVarsFlows();
		// std::vector<RiskyStore> getRiskyStores();


		json::Object JSONoutput;
		const RevngFunction *currentRF;
		LazyValueInfo *LVI = nullptr ;
		ScalarEvolution *SCEV = nullptr;
		void deallocDefUseChains();
		void analyzeArgsUsage(const RevngFunction*, Function *F);
		void analyzePromotedArgsUsage(const RevngFunction*, Function* F);
		void analyzeStackArgsUsage(const RevngFunction*, Function *F);
		std::vector<DefUseChain> getValueFlows(const Value* V) const;
		std::vector<DefUseChain> getSSAValueFlows(const Value* V) const;


		std::vector<DefUseChain> analyzeSingleArgUsage(Function *F, const Value* var);
		void analyzeVSPUsage(const RevngFunction*, Function *F);
		void findRiskyStores();
		bool isInChain(std::vector<DefUse> &chain, DefUse &V) const;
		bool containsRiskyStore(std::vector<RiskyStore>& vector, const StoreInst* store) const;
		bool alreadyStartFile = false;
		// RevngFunction result;
	};
}

#endif // REVNG_FUNCTION_PARAMS_USAGE_PASS
