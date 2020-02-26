#ifndef COMMON_DEFINITIONS_H
#define COMMON_DEFINITIONS_H

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
#define REVNG_SECURITY_MARKED_MD "revng.dm.inputgen.mark" // BOOL

#define MAX_PASS_VERBOSITY_LEVEL 3

using namespace llvm;

namespace revng {
	static bool only_marked_funs = false;


	using DefUse = std::pair<const User*, const Value*>;
	using DefUseChain = std::vector<DefUse>;
	using VariableFlow = std::pair<const Value*, std::vector<DefUseChain>>;


	struct RiskyStore {
	public:
		explicit RiskyStore(const Value* V, const StoreInst* S) {
			pointedValue = V;
			store = S;
			originalBinaryAddress = findAddress(dyn_cast<Instruction>(S));
		}
		RiskyStore(const RiskyStore& copy) {
			pointedValue = copy.getPointedValue();
			store = copy.getStoreInst();
			originalBinaryAddress = copy.getOriginalAddress();


		};
		uint64_t originalBinaryAddress = 0;
		const Value* pointedValue;
		const StoreInst* store;
		inline const uint64_t getOriginalAddress() const {return originalBinaryAddress; };
 	 	inline const Value* getPointedValue() const {return pointedValue; };
		inline const StoreInst* getStoreInst() const { return store; };

	private:
		inline int findAddress(const Instruction* I) {
			const Instruction* it = I->getNextNode();
			while(it && !(it->isTerminator())) {
				if(!isa<CallInst>(it)) {
					it = it->getNextNode();
					continue;
				}
				const CallInst* ci = dyn_cast<CallInst>(it);
				const Value* calledV = ci->getCalledValue();
				if(!(calledV && calledV->getName().equals("newpc"))) {
					it = it->getNextNode();
					continue;
				}
				const Value* op = ci->getArgOperand(1);
				if(!(op && isa<ConstantInt>(op))) {
					it = it->getNextNode();
					continue;
				}
				const ConstantInt* const_op = dyn_cast<ConstantInt>(op);
			        errs() << "Found original address in ";
				ci->print(errs());
			        errs() << "\n";
				return const_op->getZExtValue();
			}
		        return 0;
		}
	};

	using VulnerableLoopItem = std::pair<std::vector<const Instruction*>, std::vector<const RiskyStore*>>;



	class VirtualStackParam {
	public:
		VirtualStackParam(const Value* V, unsigned int i, int o) {  this->val = V; this->index = i; this->offset = o; }
		inline const Value* getValue() const  { return this->val; }
	        inline int getOffset() const { return this->offset; }
		inline std::string getName() const {
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
		inline const TYPE getType() const {return this->type; }
		inline const StringRef getFunctionName() const {return this->functionName;}
		inline const std::vector<const GlobalVariable*> getArguments() const {return this->functionArguments;}
		inline const std::vector<const VirtualStackParam*> getStackParams() const {return this->functionVirtStackParams;}
		inline const GlobalVariable* getStackPointer() const { return virtStackPointer; };
	private:
		std::vector<const GlobalVariable*> functionArguments;
		std::vector<const VirtualStackParam*> functionVirtStackParams;
		const GlobalVariable* virtStackPointer = nullptr;
		friend RevngFunctionParamsPass;
		friend RevngFunctionScraper;

	};


	inline raw_ostream& get_print_stream(int verbosity) {
		static raw_null_ostream* nullStream = new raw_null_ostream();
		if( verbosity <= MAX_PASS_VERBOSITY_LEVEL )
			return errs();
		else {
			// TODO return null stream
			return *nullStream;
		}

	}


	inline bool isaSkippedFunction(const Function*F) {
		if( F->getName().startswith("bb.__")) {
			return true;
		}
		if (F->getName().startswith("bb.vasnprintf")) {
		    return true;
		}
		if (F->getName().startswith("bb.")) {
			return false;
		} else {
			return true;
		}
	}

	inline MDString* getMDString(const Function* F, std::string mdname) {
		assert( F!=nullptr && "Passed a nullptr to getMarkString" );
		MDNode* functionMD = F->getMetadata(mdname);
		if (functionMD) {
			MDString* fMD = cast<MDString>(functionMD->getOperand(0));
			return fMD;
		}
		return nullptr;

	}

	inline bool isMarked(const Function* F)  {
		MDString* fMD = getMDString(F, REVNG_SECURITY_MARKED_MD);
		if(fMD) {
			if(fMD->getString().compare("true") == 0) {
				return true;
			} else {
				return false;
			}
		}
	        return false;
	}

	inline bool isInputFunction(const Function* F)  {
		MDString* fMD = getMDString(F, REVNG_INPUT_MD);
		if(fMD) {
			if(fMD->getString().compare("true") == 0) {
				return true;
			} else {
				return false;
			}
		}
		get_print_stream(3) << "Warning! The function " << F->getName() << " is not an input function\n";
		return false;
	}

	inline bool isInDefUseChain(Function &F, const Value* startVal, const Value* V) {
		if(startVal == V)
			return true;
		if(startVal == nullptr || V == nullptr)
			return false;
		std::deque<const Value*> nextValues;
		nextValues.push_back(startVal);
		do {
			const Value* currentVal = nextValues.front();
			nextValues.pop_front();
			if (currentVal == nullptr) {
				continue;
			}
			if(currentVal == V)
				return true;

			for( const Use &U : currentVal->uses()) {
				if(U.getUser() == nullptr) {
					continue;
				}
				const User* currentUser = U.getUser();
				if( ! isa<Instruction>(currentUser) )
					continue;
				if( dyn_cast<Instruction>(currentUser)->getFunction() != &F) {
					continue;
				}
				const Value* nextVal = dyn_cast<Value>(currentUser);
				if(std::find(nextValues.begin(), nextValues.end(), nextVal) == nextValues.end() ) {
					nextValues.push_back(nextVal);

				}
			}
		} while( !nextValues.empty() );
		return false;

	}



}

#endif // COMMON_DEFINITIONS_H
