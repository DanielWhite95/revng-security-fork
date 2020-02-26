#ifndef REVNG_BACKWARD_PROPAGATION_PASS
#define REVNG_BACKWARD_PROPAGATION_PASS

#include "llvm/ADT/Statistic.h"
#define DEBUG_TYPE "BackwardPropagationPass"
STATISTIC(MarkedFunctions, "Number of functions marked for analyses");
STATISTIC(InputFunctions, "Number of input functions (or input propagator functions) found");


// LLVM LIBRARIES
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
#include "llvm/Support/Regex.h"
#include "llvm/IR/ValueSymbolTable.h"

// Standard Libraries
#include <queue>
#include <ostream>
#include <vector>

// LOCAL LIBERARIES
#include "CommonDefinitions.h"
#include "MaxStepsPass.h"
// #include "FunctionScraper.h"




using namespace llvm;

  /// Collect information about translated and isolated functions
namespace revng {

	/* SCRAPERS */

	struct RevngFunctionScraper {
	public:
		RevngFunctionScraper();
		bool runOnFunction(const Function &F);
		void print(raw_ostream &OS, const Module *M) const;
		const RevngFunction* getRevngFunction() const;
		json::Object toJSON();

		static StringRef getInstructionTypeString(Instruction* I);
		static StringRef printInstruction(Instruction* I);

	private:
		void printMDTuple(raw_ostream &OS, MDTuple &tuple);
		void parseMDTuple(std::vector<const GlobalVariable*> &res, MDTuple &tuple);
		const Value* findVirtStackParam(const User *U);
		void scanVirtualStack( std::vector<const VirtualStackParam*> &res,  const GlobalVariable *virtRSP);
		void filterOutRevngVars();
		bool isaRevngVar(const Value*);
		const Function *scrapedFun = nullptr;
		RevngFunction res;
		Regex revngFunctionRegex = { "bb..*" };
	};

	struct FunctionScraper  {

		// Public Methods
		FunctionScraper();
		bool analyze(LazyValueInfo &LVI);
		bool analyze(const Function* F);
		void print(raw_ostream &OS, const Module *M) const;
		bool isaUserOfParameter(const User *U,const Value *P) const;
		bool isaRiskyStore(const DefUse &DU) const;
		void printOperandsRange(raw_ostream &OS, const Instruction *UR) const;
		void printValueRange(raw_ostream &OS, Value *V,const  BasicBlock* context) const;
		const std::vector<RiskyStore> getRiskyStores() const { return this->currentRiskyStores; }
		const std::vector<VariableFlow> getVarsFlows() const { return this->currentVarsFlows; }
		const std::vector<StackVarFlow> getStackVarsFlows() const { return this->currentStackVarsFlows; }
		bool isaUserOfParams(const User *U) const;
		// Public attribtues
		const Function* getFunction() const { return this->currentF; };
		const RevngFunction* getRevngFunction() const { return this->currentRF; };

	private:

		void analyzeArgsUsage(const RevngFunction*, const Function *F);
		void analyzePromotedArgsUsage(const RevngFunction*, const Function* F);
		void analyzeStackArgsUsage(const RevngFunction*, const Function *F);
		std::vector<DefUseChain> getValueFlows(const Value* V) const;
		std::vector<DefUseChain> getSSAValueFlows(const Value* V) const;
		std::vector<DefUse> traverseDefUseChain(const Value *V) const;
		std::vector<DefUseChain> analyzeSingleArgUsage(const Function *F, const Value* var);
		void analyzeVSPUsage(const RevngFunction*,const  Function *F);
		void findRiskyStores();
		bool isInChain(std::vector<DefUse> &chain, DefUse &V) const;
		bool containsRiskyStore(std::vector<RiskyStore>& vector, const StoreInst* store) const;

		std::vector<VariableFlow> currentVarsFlows;
		std::vector<StackVarFlow> currentStackVarsFlows;
		std::vector<RiskyStore> currentRiskyStores;
		const Function* currentF = nullptr;
		const RevngFunction *currentRF = nullptr;
		// Stats
		unsigned int FPUSkippedFunctions;
                unsigned int TotalStackChains;
		unsigned int TotalVarChains;
                unsigned int TotalStores;
		RevngFunctionScraper rgScraper;
	};


	/* PASSES */

	using MarkedFunInfo = std::tuple<std::string, int, std::string>;

	using MarkedFunMap = std::map<Function*, MarkedFunInfo>;

	using RelocationsMap = std::map<std::string, std::string>;


	class BackwardPropagationPass : public ModulePass {
	public:


		static char ID;
		BackwardPropagationPass();
		virtual ~BackwardPropagationPass() {};
	        virtual bool doInitialization(Module &M);
		virtual bool doFinalization(Module &M) override;
		virtual bool runOnModule(Module &M) override;
		virtual void getAnalysisUsage(AnalysisUsage &AU) const override;
		virtual void print(raw_ostream &OS, const Module *M) const override;
		json::Object toJSON();

	private:
		FunctionScraper fScraper;

		MarkedFunMap markedFunctions;
		std::map<Function*, MarkedFunInfo> *nextCallers;



		const CallGraph* moduleCG = nullptr; // build local call graph on start
		const Function* currentF = nullptr;
		bool toAnalyze(Function *F); // Check metadata

		MarkedFunInfo getReachedParamIndex(Function &F, const Value* ); // Return -1 i
		MarkedFunInfo isReturnedByFun(Function &F, const Value*); // traverse backward de-chains
		const Value* getInputValue(Function &F, MarkedFunInfo& mf);
                void markCaller(Function* caller,  int argPos);
		void markInputFunctions(Module &M);
		void markInputFunction(Function* F);
		void markPassFunction(Function* F, bool);
		void parseInputFiles(Module &M);
		std::vector<Function*> findCallersInCG(Function *F);
		Function* searchFunctionByAddress(Module &M, std::string address);

		// Check if the values is a function argument and returns its index,
		// otherwise returns a negative number
		int getArgIndex(Function &F, const Value*);

		const Value* searchForNamedParameter(Function &F, const Value* startPoint, std::string name);
		const Value* searchForReturnRegister(Function &F, const Value* startPoint,  std::string resReg);


		// DEBUG ONLY FUNCTIONS
		void printMarkedFunctions();
		const Value* findNextInstructionInBB(const Instruction* I, const BasicBlock *BB);
		void printNextCallers();

		bool addMarkedFunction(Function *F, int argIndex, std::string argName, std::map<Function*,MarkedFunInfo>* );
  };


}

#endif // REVNG_BACKWARD_PROPAGATION_PASS
