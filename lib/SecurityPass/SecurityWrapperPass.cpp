#include "revng/SecurityPass/SecurityWrapperPass.h"

using namespace llvm;
using namespace revng;

char SecurityWrapperPass::ID = 4;


enum JSONOpts {
  // 'inline' is a C++ keyword, so name it 'inlining'
	ldp,fpu,rfp
};



cl::opt<bool> VerboseAnalysis("verbose-analysis", cl::desc("Write more informations about analysis"));
cl::opt<std::string> AnalysisOutputFilename("dump-result-file", cl::desc("Specify output filename"), cl::value_desc("filename"));
cl::opt<bool> DumpAnalysis("dump-result", cl::desc("Dump analysis results to json"), cl::value_desc("filename"));
cl::bits<JSONOpts> JSONSectionsBits(cl::desc("JSON sections dumped"),
  cl::values(clEnumVal(fpu, "Dump function params usage pass to JSON"),
	     clEnumVal(rfp, "Dump revng function params pass to json"),
	     clEnumVal(ldp, "Dump revng loop dependencies pass to json")));

static RegisterPass<SecurityWrapperPass> Y("revng-security-analysis", "Analyze function reached by vulnerable points",
					       false /* Only looks at CFG */,
					       true /* Analysis Pass */);


SecurityWrapperPass::SecurityWrapperPass() : FunctionPass(ID) {
}


bool SecurityWrapperPass::doInitialization(Module &M) {
	AnalysisOutputJSON = new json::Object();
	return false;
}


bool SecurityWrapperPass::doFinalization(Module &M) {
	// Add statistics to json
	if (DumpAnalysis) {
		json::ObjectKey statsKey("analysisStatistics");
		json::Object stats;
		if (AreStatisticsEnabled())
		{
			auto Stats = GetStatistics();
			for( auto Stat : Stats) {
				stats.try_emplace(std::get<0>(Stat), json::Value(std::get<1>(Stat)));
			}
			AnalysisOutputJSON->try_emplace(std::move(statsKey), std::move(stats));
		}
		json::Value valuewrp(std::move(*AnalysisOutputJSON));
		std::error_code FileError;
		StringRef FileName( AnalysisOutputFilename.c_str());
		raw_fd_ostream Output(FileName, FileError, sys::fs::OpenFlags::OF_None);
		if (!FileError)  {
			Output << valuewrp;
		}
	}
	return false;

}

bool SecurityWrapperPass::updateJSON(Function* F) {
	get_print_stream(3) << "Updating json for " << F->getName() << "\n";
	assert( LDP != nullptr && "LDP analysis non obtained");
	assert( FPU != nullptr && "FPU analysis non obtained");
	assert( RFP != nullptr && "RFP analysis non obtained");
	json::Object functionJSON;
	if (JSONSectionsBits.isSet(ldp)) {
		get_print_stream(3) << "Obtaining json from LoopDependencies pass...\n";
		json::Value ldpJSON(LDP->toJSON()) ;
		functionJSON.try_emplace("loopDependenciesAnalysis", ldpJSON);
	}
	if (JSONSectionsBits.isSet(fpu)) {
		get_print_stream(3) << "Obtaining json from FunctionParamsUsagePass pass...\n";
		json::Value fpuJSON(FPU->toJSON());
		functionJSON.try_emplace("functionParamsUsageAnalysis", fpuJSON);
	}
	if (JSONSectionsBits.isSet(rfp)) {
		get_print_stream(3) << "Obtaining json from RevngFunctionParams pass...\n";
		json::Value rfpJSON(RFP->toJSON());
		functionJSON.try_emplace("functionInfos", rfpJSON);
	}
	json::Value marked(isMarked(F));
	json::Value safe(LDP->isFunctionSafe());
	// json::Value &bppSON  BPP.toJSON() ;
	functionJSON.try_emplace("isMarked", marked);
	functionJSON.try_emplace("isSafe", safe);
	// functionJSON.try_emplace("backwardPropagationAnalysis", ldpJSON);
	json::Value functionWrapped(std::move(functionJSON));
	AnalysisOutputJSON->try_emplace(currentRF->getFunctionName(), functionWrapped);
	return true;
}

void SecurityWrapperPass::getAnalysisUsage(AnalysisUsage &AU) const {
	AU.addRequired<RevngFunctionParamsPass>();
	AU.addRequired<FunctionParamsUsagePass>();
	AU.addRequired<LoopDependenciesPass>();
	AU.setPreservesAll();
}


bool SecurityWrapperPass::runOnFunction(Function &F) {

	RFP = nullptr;
	FPU = nullptr;
	LDP = nullptr;
	currentRF = nullptr;

	get_print_stream(3) << "Starting SecurityWrapperPass on function " << F.getName() << "...\n";
	currentRF = getAnalysis<RevngFunctionParamsPass>().getRevngFunction();
	if(!(currentRF->getFunctionName() == F.getName() && currentRF->getType() == RevngFunction::TYPE::ISOLATED) ) {
		get_print_stream(3) << "Skipping non-revng function " << F.getName() << "...\n";
		return false;
	}
	if ( isaSkippedFunction(&F) || (!isMarked(&F) && OnlyMarkedFuns) ) {
		get_print_stream(3) << "Skipping not marked function " << F.getName() << "...\n";
		return false;
	}
	RFP = &(getAnalysis<RevngFunctionParamsPass>());
	FPU = &(getAnalysis<FunctionParamsUsagePass>());
	LDP = &(getAnalysis<LoopDependenciesPass>());
	if (DumpAnalysis) {
	   updateJSON(&F);
	}
	printFunctionInfo(F);
	return false;
}


void SecurityWrapperPass::print(raw_ostream &OS, const Module *M) const {
	if(!( RFP && FPU && LDP)) {
		// has riksy stores?
		OS << "No result analysis for this function...\n ";

	}
}

void SecurityWrapperPass::printFunctionInfo(Function &F) const {
	if(!( RFP && FPU && LDP)) {
		get_print_stream(1) << "No result analysis for this function...\n";
	}

	get_print_stream(1) << "===============================\n";
	get_print_stream(1) << "Analysis Info for " << F.getName() << "\n";
	get_print_stream(1) << "===============================\n";
	get_print_stream(1) << "Is Function Safe: " << LDP->isFunctionSafe() << "\n";
	get_print_stream(1) << "Is Function Marked: " << isMarked(&F) << "\n";
	get_print_stream(1) << "Number of risky stores found: " << LDP->getNumRiskyStores() << "\n";


}
