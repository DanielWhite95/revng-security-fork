#include "revng/SecurityPass/CommonDefinitions.h"


using namespace llvm;
using namespace revng;

static cl::opt<bool, true> OnlyMarkedFunctions("only-marked-funs", cl::desc("Analyze only functions reached by inputs"), cl::location(only_marked_funs));
