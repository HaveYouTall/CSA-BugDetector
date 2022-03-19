#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"


#include <iostream>

using namespace clang;
using namespace ento;

// using namespace taint;

namespace {

class HytBofChecker : public Checker<check::PreCall> {
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &Ctx) const;

private:
  mutable std::unique_ptr<BugType> BT;

};

} // anonymous namespace




void HytBofChecker::checkPreCall(const CallEvent &Call, CheckerContext &Ctx) const {
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  //ProgramStateRef State = Ctx.getState();
  bool bug = false;


  //llvm::errs() << "PreCall:\n";
  if(II==NULL){
    return;
  }

  if(II->isStr("memcpy") || II->isStr("strncpy")){

    SVal SizeArg = Call.getArgSVal(2);
    //SVal src = Call.getArgSVal(1);
    SVal DestSVal = Call.getArgSVal(0);
    // uint64_t SizeInt;
    if(SizeArg.isConstant()){
      //std::cout<< "Constant" << std::endl;
      // nonloc::ConcreteInt CI = SizeArg.castAs<nonloc::ConcreteInt>();
      // SizeInt = CI.getValue().getLimitedValue();

      // Optional<NonLoc>  SizeArgNL = SizeArg.getAs<NonLoc>();
      // if(this->isArgUnConstrained(SizeArgNL, svalBuilder, state) == true) 

      //Get Dest size
      const MemRegion *MR = DestSVal.getAsRegion(); 
      if (!MR)
        return;
      const MemRegion *BaseR = MR->getBaseRegion();
      if (!BaseR)
        return;
      // const SubRegion *SR = dyn_cast_or_null<SubRegion>(BaseR);
      // if (!SR)
      //   return;
      //const MemRegionManager MRM = BaseR->getMemRegionManager(); 
      SValBuilder &svalBuilder = Ctx.getSValBuilder();
      // SVal extent = SR->getExtent(svalBuilder);
      SVal extent = BaseR->getMemRegionManager().getStaticSize(BaseR, svalBuilder);

      //compare the dest size with copy length.
      ProgramStateRef state = Ctx.getState();
      Optional<DefinedSVal> DestRSizeDSVal = extent.getAs<DefinedSVal>();
      if (!DestRSizeDSVal)
        return;
      Optional<DefinedSVal> CopyLenDSVal = SizeArg.getAs<DefinedSVal>();
      SVal DestRSizeLessThanSrcLength = svalBuilder.evalBinOp(
        state, BO_LT, *DestRSizeDSVal, *CopyLenDSVal, svalBuilder.getConditionType());

      Optional<DefinedSVal> DestRSizeLessThanCopyLenDSVal = 
        DestRSizeLessThanSrcLength.getAs<DefinedSVal>();
      
      if (!DestRSizeLessThanCopyLenDSVal)
        return;
      
      // The DestRSizeLessThanCopyLenDSVal(bool) true or false?
      ConstraintManager &CM = Ctx.getConstraintManager();
      ProgramStateRef stateLT = CM.assume(state, *DestRSizeLessThanCopyLenDSVal, true);
      if (stateLT){
        bug = true;
        BT.reset(new BugType(this, "Stack overflow detected!", "Example checker"));
      }


    }else{
      //std::cout<< "Not Constant" << std::endl;
      bug = true;
      BT.reset(new BugType(this, "Variable length may cause stack overflow", "Example checker"));
      
    }

    if(bug){
      ExplodedNode *Node = Ctx.generateErrorNode();
      auto Report = std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), Node);
      Ctx.emitReport(std::move(Report));
    }
    

  }

}





void ento::registerHytBofChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<HytBofChecker>();
}

bool ento::shouldRegisterHytBofChecker(const CheckerManager &mgr) {
  return true;
}
