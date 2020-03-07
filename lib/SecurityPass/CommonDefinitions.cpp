#include "revng/SecurityPass/CommonDefinitions.h"


using namespace llvm;
using namespace revng;

cl::opt<bool> OnlyMarkedFunctions("only-marked-funs", cl::desc("Analyze only functions reached by inputs"));
