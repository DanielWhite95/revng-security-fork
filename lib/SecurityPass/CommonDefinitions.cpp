#include "revng/SecurityPass/CommonDefinitions.h"


using namespace llvm;
using namespace revng;

static cl::opt<bool, true> OnlyMarkedFunctions("only-marked-funs", cl::desc("Analyze only functions reached by inputs"), cl::location(only_marked_funs));

json::Object riskyStoreToJSON(RiskyStore& RS) {
      			json::Object stObj;
			const Value* VAL = RS->getPointedValue();
			const StoreInst* ST = RS->getStoreInst();
			const int origAddr = RS->getOriginalAddress();
			const int offset = RS->getInstOffset();
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
