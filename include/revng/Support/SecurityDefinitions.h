#ifndef SECURITY_DEFINITIONS_H
#define SECURITY_DEFINITIONS_H

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
#include <deque>

// Constant definitions

#define REVNG_INPUT_MD "revng.dm.inputgen"
#define REVNG_INPUT_NAME_MD "revng.dm.inputgen.called" // STRING
#define REVNG_INPUT_POS_MD "revng.dm.inputgen.argpos" // STRING
#define REVNG_INPUT_TOANALYZE_MD "revng.dm.inputgen.toanalyze" // BOOLEAN
#define REVNG_SECURITY_MARKED_CALLERS_MD "revng.dm.inputgen.callers" // list of strings
#define REVNG_SECURITY_MARKED_MD "revng.dm.inputgen.mark" // BOOL

#define MAX_PASS_VERBOSITY_LEVEL 3

using namespace llvm;

namespace revng {
	using DefUse = std::pair<const User*, const Value*>;
	using DefUseChain = std::vector<DefUse>;
	using VariableFlow = std::pair<const Value*, std::vector<DefUseChain>>;

	raw_ostream& get_print_stream(int verbosity);
	bool isaSkippedFunction(const Function*F);
	MDString* getMDString(const Function* F, std::string mdname);
	bool isMarked(const Function* F);
	bool isInputFunction(const Function* F);
	bool isInDefUseChain(Function &F, const Value* startVal, const Value* V);

	struct RiskyStore {
	public:
		explicit RiskyStore(const Value* V, const StoreInst* S);
		RiskyStore(const RiskyStore& copy);
		uint64_t originalBinaryAddress = 0;
		int instOffset = 0;
		const Value* pointedValue;
		const StoreInst* store;

		const uint64_t getOriginalAddress() const {return originalBinaryAddress; };
 	 	const Value* getPointedValue() const {return pointedValue; };
		const StoreInst* getStoreInst() const { return store; };
		const int getInstOffset() const { return instOffset; }
		json::Object toJSON() const;
		void attachValueInfo(LazyValueInfo&);
	private:
		int findAddress(const Instruction* I);
		const ConstantRange* pointedRange;
		const ConstantRange* valueRange;
	};

	using VulnerableLoopItem = std::pair<std::vector<const Instruction*>, std::vector<const RiskyStore*>>;



	class VirtualStackParam {
	public:
		VirtualStackParam(const Value* V, unsigned int i, int o) {  this->val = V; this->index = i; this->offset = o; }
		const Value* getValue() const  { return this->val; }
	        int getOffset() const { return this->offset; }
		std::string getName() const {
			std::string name = formatv("sp{0}", this->index);
			return name;
		}
	private:
		const Value* val = nullptr;
		unsigned int index = 0;
		int offset = 0;

	};

	using StackVarFlow = std::pair<const VirtualStackParam* , std::vector<DefUseChain>>;



	struct RevngFunctionParamsPass;
	struct RevngFunctionScraper;

	struct RevngFunction {
		enum TYPE{
			ISOLATED,
			NOT_ISOLATED
		};
		TYPE type;
		StringRef functionName;
		const TYPE getType() const {return this->type; }
		const StringRef getFunctionName() const {return this->functionName;}
		const std::vector<const GlobalVariable*> getArguments() const {return this->functionArguments;}
		const std::vector<const VirtualStackParam*> getStackParams() const {return this->functionVirtStackParams;}
		const GlobalVariable* getStackPointer() const { return virtStackPointer; };
	private:
		std::vector<const GlobalVariable*> functionArguments;
		std::vector<const VirtualStackParam*> functionVirtStackParams;
		const GlobalVariable* virtStackPointer = nullptr;
		friend RevngFunctionParamsPass;
		friend RevngFunctionScraper;

	};




}



#endif // SECURITY_DEFINITIONS_H
