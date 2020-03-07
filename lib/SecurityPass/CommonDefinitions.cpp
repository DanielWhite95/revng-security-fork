#include "revng/SecurityPass/CommonDefinitions.h"


using namespace llvm;


static cl::opt<bool> revng::OnlyMarkedFunctions("only-marked-funs", cl::desc("Analyze only functions reached by inputs"));
