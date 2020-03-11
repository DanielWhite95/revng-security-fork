#include "revng/Support/SecurityDefinitions.h"

using namespace llvm;
using namespace revng;


raw_ostream& get_print_stream(int verbosity) {
	static raw_null_ostream* nullStream = new raw_null_ostream();
	if( verbosity <= MAX_PASS_VERBOSITY_LEVEL )
		return errs();
	else {
		// TODO return null stream
		return *nullStream;
	}

}

bool isaSkippedFunction(const Function*F) {
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

MDString* getMDString(const Function* F, std::string mdname) {
	assert( F!=nullptr && "Passed a nullptr to getMarkString" );
	MDNode* functionMD = F->getMetadata(mdname);
	if (functionMD) {
		MDString* fMD = cast<MDString>(functionMD->getOperand(0));
		return fMD;
	}
	return nullptr;

}

bool isMarked(const Function* F)  {
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

bool isInputFunction(const Function* F)  {
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

bool isInDefUseChain(Function &F, const Value* startVal, const Value* V) {
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


RiskyStore::RiskyStore(const Value* V, const StoreInst* S) {
	pointedValue = V;
	store = S;
	originalBinaryAddress = findAddress(dyn_cast<Instruction>(S));
}


RiskyStore::RiskyStore(const RiskyStore& copy) {
	pointedValue = copy.getPointedValue();
	store = copy.getStoreInst();
	originalBinaryAddress = copy.getOriginalAddress();
}


int RiskyStore::findAddress(const Instruction* I) {
	const Instruction* it = I->getNextNode();
	while(it && !(it->isTerminator())) {
		if(!isa<CallInst>(it)) {
			it = it->getNextNode();
			instOffset++;
			continue;
		}
		const CallInst* ci = dyn_cast<CallInst>(it);
		const Value* calledV = ci->getCalledValue();
		if(!(calledV && calledV->getName().equals("newpc"))) {
			it = it->getNextNode();
			instOffset++;
			continue;
		}
		const Value* op = ci->getArgOperand(0);
		if(!(op && isa<ConstantInt>(op))) {
			it = it->getNextNode();
			instOffset++;
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

json::Object RiskyStore::toJSON() const {
	json::Object stObj;
	const Value* VAL = getPointedValue();
	const StoreInst* ST = getStoreInst();
	const int origAddr = getOriginalAddress();
	const int offset = getInstOffset();
	assert(ST != nullptr && VAL != nullptr && "Null risky store detected");
	std::string serializedST;
	serializedST = formatv("{0}",  *VAL);
	json::Value stVal(serializedST);
	stObj.try_emplace("value", std::move(stVal));
	serializedST = formatv("{0}",  *ST);
	json::Value stInst(serializedST);
	stObj.try_emplace("storeInstruction", std::move(stInst));
	serializedST = formatv("{0:x}",  origAddr);
	json::Value stAddr(serializedST);
	stObj.try_emplace("binaryAddress", std::move(stAddr));
	json::Value instOffset(offset);
	stObj.try_emplace("instructionOffset", std::move(instOffset));
	return stObj;
}
