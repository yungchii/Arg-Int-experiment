#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/AbstractCallSite.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <vector>
#include <utility>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string.h>
#include <cstring>
using namespace llvm;
#define API_CHECK 0
#define API_STORE_RECORD 1
#define API_GLOBAL_RECORD 2
#define API_MEMCPY_RECORD 3
#define API_FP_RECORD 4
#define API_STRNCPY_RECORD 5
#define API_FP_CHECK 6
#define API_FGETS_RECORD 7
#define API_RECORD_REG 8
#define API_GETS_RECORD 9
#define API_INDIRECT_CALL 10
#define API_CHECK_REG 11
#define API_CHECK_SYSCALL 12
#define API_REMAP 13
#define HANDLER_THRESHOLD 3
namespace {

class ArgumentAnalysisPass: public PassInfoMixin<ArgumentAnalysisPass> {
private:
    struct strInst {
	StoreInst *inst;
	bool is_fp;
    };
    std::vector<StringRef> syscallVec;
    //<callee, (caller address, caller call instruction address)>
    std::map<Value*, std::vector<std::pair<Function*, CallInst*>>> \
	ccPair;

    std::unordered_set<StoreInst*> temp_insertion;
    std::unordered_set<Instruction*> temp_fp_insertion;
    std::unordered_set<Instruction*> temp_reg_insertion;
    std::unordered_set<Instruction*> temp_fp_check_insertion;
    std::unordered_set<CallInst*> temp_record_reg_insertion;
    //function pointer array,
    //key: the arrray address
    //value: each element in the array. Each is an address of a function
    std::unordered_map<Value*, std::vector<Value*> > ptrArr;
    std::vector<std::pair<Function*, GlobalVariable*>> toInsertList;
    void setCalleeCallerPair(Module &M);
    bool calleeIsSyscall(CallInst *ci);
    std::unordered_set<int> getRegIndexList(Function *curFunc, \
	    CallInst *call, std::unordered_set<int> calleeRegIndexList, bool is_fp);
    void handler(std::pair<Function*, CallInst*> cur, \
	    std::unordered_set<int> &calleeRegIndexList, \
	    std::unordered_map<Function *, bool> &visitedList, int &count, bool is_fp);
    std::unordered_set<int> FPGetRegIndexList(Function *curFunc, CallInst *call);
    void FPHandler(std::pair<Function*, CallInst*>cur, \
	    std::unordered_map<Function*, bool> visitedList);
    bool runOnFunction(Function &F);
    Value *getFuncptr(CallInst *ci);
    void insertApiCall(Value *val, int api);
    void iterateGlobalVar(Module &M);
    void iterateGlobalFp(Module &M);
    //void insertScsMap(Module &M);
    bool FPProtoisSyscall(CallInst *ci);
    std::vector<Value> getStoredAddr(Function &F);
    void do_insertion();
public:
    ArgumentAnalysisPass();
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
	bool Transformed = false;
	//iterateGlobalVar(M);
	iterateGlobalFp(M);
	setCalleeCallerPair(M);
	//insertScsMap(M);
	for(auto &F: M) {
	    Transformed |= runOnFunction(F);
	}
	do_insertion();
	errs() << "================Compilation done=================\n";
	return PreservedAnalyses::all();
    }
};
}
void ArgumentAnalysisPass::do_insertion() {
//    errs() << "insert API_STORE_RECORD: " << temp_insertion.size() << "\n";
    for (auto &store: temp_insertion) {
	   insertApiCall(store, API_STORE_RECORD);
    }
//    errs() << "insert API_FP_RECORD: " << temp_fp_insertion.size() << "\n";
    for (auto &store: temp_fp_insertion) {
	insertApiCall(store, API_FP_RECORD);
    }
//    errs() << "insert API_CHECK_REG: " << temp_reg_insertion.size() << "\n";
    for (auto &inst: temp_reg_insertion) {
        insertApiCall(inst, API_CHECK_REG);
    }
//    errs() << "insert API_RECORD_REG: " << temp_record_reg_insertion.size() << "\n";
    for (auto &inst: temp_record_reg_insertion) {
	insertApiCall(inst, API_RECORD_REG);
    }
//    errs() << "insert API_FP_CHECK: " << temp_fp_check_insertion.size() << "\n";
    for (auto &inst: temp_fp_check_insertion) {
	insertApiCall(inst, API_FP_CHECK);
    }
}
void ArgumentAnalysisPass::iterateGlobalFp(Module &M) {
  for (auto &GV: M.getGlobalList()) {
    if (GV.hasInitializer()) {
      if (GV.getInitializer()->getType()->isPointerTy() &&
	  !GV.getInitializer()->isNullValue())  {
	  Function *F = dyn_cast<Function>(GV.getInitializer());
	    if (F) {
	      toInsertList.push_back(std::make_pair(F, &GV));
	    }
      }
    }
  }
}
//void ArgumentAnalysisPass::insertScsMap(Module &M) {
//    auto &Ctx = M.getContext();
//    auto &DL = M.getDataLayout();
//    auto retType = Type::getVoidTy(Ctx);
//    std::vector<Type*> paramTypes;
//    paramTypes.push_back(Type::getVoidTy(Ctx));
//    FunctionType *fTy = FunctionType::get(retType, paramTypes, false); 
//    Function 
//    appendGlobalCtors(M, ctor, 0, ConstantPointerNull::get(ConstantDataTy);
//    return;
//
//}
void ArgumentAnalysisPass::iterateGlobalVar(Module &M) {
    //std::unordered_map<unsigned long, std::vector<unsigned long> > ptrArr;
    for (auto &g: M.getGlobalList()) {
	if (g.hasInitializer()) {
	    Constant *init = g.getInitializer();
	    if (init->getType()->isArrayTy()) {
		if (init->getType()->getArrayElementType()->isPointerTy()) {
		    Value *addr = dyn_cast<Value>(&g);
		    for (int i = 0; i < init->getType()->getArrayNumElements(); i++) {
		        ptrArr[addr].push_back(init->getOperand(i));
		    }
		}
		else if (init->getType()->getArrayElementType()->isStructTy()) {
		    Value *addr = dyn_cast<Value>(&g);
		    if (ConstantAggregateZero *cZero = dyn_cast<ConstantAggregateZero>(init)) {
		    }
		    else if (ConstantArray *cArr = dyn_cast<ConstantArray>(init)) {
			if (Constant *firstElement = cArr->getAggregateElement((unsigned)0)) {
			    int funcptrIdx = 0;
			    for (int i = 0 ; i < firstElement->getNumOperands(); i++) {
				if (Function *func = dyn_cast<Function>(firstElement->getOperand(i))) {
				    funcptrIdx = i;
				    break;
				}
			    }
			    if (funcptrIdx != 0) {
				for (int i = 0; i < init->getType()->getArrayNumElements(); i++) {
				    if (cArr->getAggregateElement((unsigned)(i))->getNumOperands() < funcptrIdx) 
					continue;
				    ptrArr[addr].push_back((cArr->getAggregateElement((unsigned)(i)))->getOperand(funcptrIdx));
				}
			    }
			} 
		    }
		}
	    }
	    else if (init->getType()->isPointerTy()) {
		Value *addr = dyn_cast<Value>(&g);
		GlobalVariable *gv = dyn_cast<GlobalVariable>(&g);
		ptrArr[addr].push_back(gv->getOperand(0));
	    }
	}
    }	
}
Value *ArgumentAnalysisPass::getFuncptr(CallInst *ci) {
    Value *ret = NULL;
    Instruction *callee = dyn_cast<Instruction>(ci->getCalledOperand());
    if (callee == NULL) {
	return ret;
    }
    unsigned opcode = callee->getOpcode();
    if (opcode == Instruction::Load) {
	   Value *calleePtr = callee->getOperand(0);
	   if (calleePtr == NULL)
	       return ret;
	   if (ptrArr.find(callee->getOperand(0)) != ptrArr.end()) {
	       ret = ptrArr[callee->getOperand(0)][0];
	   }
	   else if (GEPOperator *gep = dyn_cast<GEPOperator>(calleePtr)) {
	       Value *baseAddr = gep->getPointerOperand();
	       if (baseAddr == NULL)
		   return ret;
	       if (ptrArr.find(baseAddr) != ptrArr.end()) {
		   if (ConstantInt *offsetCons = dyn_cast<ConstantInt>(gep->getOperand(2))) {
		       uint64_t offset = offsetCons->getZExtValue();
		       ret = ptrArr[baseAddr][offset];
		   }
	       }
	   }
    }
    return ret;

}
void ArgumentAnalysisPass::setCalleeCallerPair(Module &M) {
    //errs() << "setCalleeCallerPair\n";
    for (auto &F: M) {
	std::set<Value *> possibleCalleeList;
	for (auto &BB: F) {
	    for (auto &I: BB) {
		if (StoreInst *si = dyn_cast<StoreInst>(&I)) {
		    if (Value *possibleCallee = si->getValueOperand()) {
			auto name = possibleCallee->getName();
			if (!name.empty()) {
			    if (possibleCallee->getType()->isPointerTy()) {
				//errs() << "name: " << name << "\n";
				possibleCalleeList.insert(possibleCallee);
			    }
			}
		    }
		}
		if (CallInst *ci = dyn_cast<CallInst>(&I)) {
		    Value *callee = ci->getCalledFunction();
		    if (!callee) {
			if (!possibleCalleeList.empty()) {
			    for (auto callee: possibleCalleeList) {
				ccPair[callee].push_back(std::make_pair(&F, ci));
				//errs() << "possible: " << callee << "\n";
			    }
			    possibleCalleeList.clear();
			    continue;
			}
//			errs() << "caller: " << *ci << "\n";
			callee = getFuncptr(ci);
			if (callee)
			    ccPair[callee].push_back(std::make_pair(&F, ci));
		    }
		    else
			ccPair[callee].push_back(std::make_pair(&F, ci));
		}
	    }
	}
    }
    
//    for (auto &m: ccPair) {
//        errs() << "callee: " << m.first << " " << (m.first)->getName() \
//            << "\n";
//        errs() << "caller:\n";
//        for (auto &vec: m.second) {
//            errs() <<  vec.first->getName() << " ";
//        }
//        errs() << "\n";
//    }
//    errs() << "===================================================\n";
}

bool ArgumentAnalysisPass::calleeIsSyscall(CallInst* ci) {
    Value *callee = ci->getCalledFunction();
    if (!callee) {
      return false;
//	callee = getFuncptr(ci);
//	if (callee) {
//	    //errs() << "find callee: " << *callee << "\n";
//	}
//	if (!callee){
//	    //errs() << "still not found\n";
//	    return false;
//	}
    }

    for (auto iter: syscallVec) {
	if (callee->getName() == iter) {
	    //errs() << "found syscall: " << iter << "\n";
	    return true;
	}
    }
    return false;
}
std::unordered_set<int> ArgumentAnalysisPass::FPGetRegIndexList(Function *curFunc, CallInst *call) {
    std::unordered_set<int> res;
    struct node{
	std::unordered_set<Value*> uset;
	Value *funcArg;
	bool care;
    };
    std::unordered_set<Value*> storeInstList;
    std::vector<struct node> argList(curFunc->arg_size());
    int argIndex = 0;
    for (auto arg = curFunc->arg_begin(); \
	    arg != curFunc->arg_end(); arg++) {
	argList[argIndex].care = 0;
	argList[argIndex].uset.insert(arg);
	argIndex++;
    }
    auto M = curFunc->getParent();
    std::unordered_map<Value *, struct node> globalList;
    for (auto &GV: M->getGlobalList()) {
	if (GV.hasInitializer()) {
	    if (GV.getInitializer()->getType()->isPointerTy())  {
		Function *F = dyn_cast<Function>(GV.getInitializer());
		//TODO: global fp that is not assigned will not be executed here.
		if (F) {
		    if (Value *v = dyn_cast<Value>(&GV)) {
			globalList[v].funcArg = v;
			globalList[v].care = 0;
			globalList[v].uset.insert(v);
		    }
		}
	    }
	}
    }
    DataLayout DL = call->getModule()->getDataLayout();
    std::unordered_map<Value *, struct node> allocaList;
    CallInst *ci;
    bool target_is_cared = 0;
    for (auto &BB: *curFunc) {
	for (auto &I: BB) {
	    Value *source, *target, *source2;
	    unsigned opcode = I.getOpcode();
	    switch (opcode) {
	    case Instruction::Load:
		source = I.getOperand(0);
		for (auto &m: argList) {
		    if (m.uset.find(source) != m.uset.end()) {
			m.uset.insert(&I);
		    }
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(source) != \
			    m.second.uset.end()) {
			m.second.uset.insert(&I);
			break;
		    }
		}
		for (auto &m: globalList) {
		  if (m.second.uset.find(source) != \
		      m.second.uset.end()) {
		    m.second.uset.insert(&I);
		    break;
		  }
		}
		break;
	    case Instruction::Store:
		source = I.getOperand(0);
		target = I.getOperand(1);
		for (auto &m: argList) {
		    if (m.uset.find(source) != m.uset.end()) {
			m.uset.insert(&I);
			m.uset.insert(target);
		    }
		    if (m.uset.find(target) != m.uset.end()) {
			m.uset.insert(&I);
		    }
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(target) != \
			    m.second.uset.end()) {
			m.second.uset.insert(&I);
			break;
		    }
		    if (m.second.uset.find(source) != m.second.uset.end()) {
			m.second.uset.insert(&I);
			m.second.uset.insert(target);
		    }
		}
		for (auto &m: globalList) {
		  if (m.second.uset.find(target) != m.second.uset.end()) {
		    m.second.uset.insert(&I);
		    break;
		  }
		}
		break;
	    case Instruction::Alloca:
		allocaList[&I].funcArg = &I;
		allocaList[&I].care = 0;
		allocaList[&I].uset.insert(&I);
		break;
	    case Instruction::BitCast:
		source = I.getOperand(0);
		for (auto &m: allocaList) {
		    if (m.second.uset.find(source) != m.second.uset.end()) {
			m.second.uset.insert(&I);
		    }
		}
	    default:
		break;
	    }
	}
    }
    if (curFunc->arg_size() == 0) {
	    for (auto &iter: allocaList) {
		if (iter.second.uset.find(call->getCalledOperand()) != \
			iter.second.uset.end()) {
		    for (auto &I: iter.second.uset) {
			if (StoreInst *store = dyn_cast<StoreInst>(I)) {
			    temp_fp_insertion.insert(store);
			    //insertApiCall(store, API_FP_RECORD);
			}
		    }
		}
	    }
    }
    else {
	for (int i = 0; i < argList.size(); i++) {
	    if (argList[i].uset.find(call->getCalledOperand()) != \
		    argList[i].uset.end()) {
		argList[i].care = true;
		res.insert(i);
		for (auto &I: argList[i].uset) {
		    if (StoreInst *store = dyn_cast<StoreInst>(I)) {
			temp_fp_insertion.insert(store);
			//insertApiCall(store, API_STORE_RECORD);
		    }
		}
	    }
	}
	for (auto &iter: allocaList) {
	    if (iter.second.uset.find(call->getCalledOperand()) != \
		    iter.second.uset.end()) {
		for (auto &I: iter.second.uset) {
		    if (StoreInst *store = dyn_cast<StoreInst>(I)) {
			temp_fp_insertion.insert(store);
		    }
		}
	    }
	}
    }
    for (auto &iter: globalList) {
	 if (iter.second.uset.find(call->getCalledOperand()) != \
	    iter.second.uset.end()) {
	    for (auto &I: iter.second.uset) {
		if (LoadInst *load = dyn_cast<LoadInst>(I)) {
		    temp_fp_insertion.insert(load);
		}
		if (StoreInst *store = dyn_cast<StoreInst>(I)) {
		    temp_fp_insertion.insert(store);
		}
	    }
	}
    }
    
    return res;
}
std::unordered_set<int> ArgumentAnalysisPass::getRegIndexList( \
	Function *curFunc, CallInst *call, \
	std::unordered_set<int> calleeRegIndexList, bool is_fp) {
    std::unordered_set<int> res;
    struct node{
	std::unordered_set<Value*> uset;
	Value *funcArg;
	bool care;
    };
    std::unordered_set<Value*> storeInstList;
    std::vector<struct node> argList(curFunc->arg_size());
    int argIndex = 0;
    for (auto arg = curFunc->arg_begin(); \
	    arg != curFunc->arg_end(); arg++) {
	argList[argIndex].care = 0;
	argList[argIndex].uset.insert(arg);
	argIndex++;
    }
    DataLayout DL = call->getModule()->getDataLayout();
    std::unordered_map<Value *, struct node> allocaList;
    std::string calledName;
    char name_memcpy[12] = "llvm.memcpy";
    char name_strncpy[8] = "strncpy";
    char name_fgets[6] = "fgets";
    char name_gets[5] = "gets";
    CallInst *ci;
    bool target_is_cared = 0;
    for (auto &BB: *curFunc) {
	for (auto &I: BB) {
	    Value *source, *target, *source2;
	    unsigned opcode = I.getOpcode();
	    switch (opcode) {
	    case Instruction::Load:
		source = I.getOperand(0);
		for (auto &m: argList) {
		    if (m.uset.find(source) != m.uset.end()) {
			m.uset.insert(&I);
		    }
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(source) != \
			    m.second.uset.end()) {
			m.second.uset.insert(&I);
			break;
		    }
		}
		break;
	    case Instruction::GetElementPtr:
		source = I.getOperand(0);
		for (auto &m: argList) {
		    if (m.uset.find(source) != m.uset.end()) {
			m.uset.insert(&I);
		    }
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(source) != \
			    m.second.uset.end()) {
			m.second.uset.insert(&I);
		    }
		}
		break;
	    case Instruction::Store:
		source = I.getOperand(0);
		target = I.getOperand(1);
		for (auto &m: argList) {
		    if (m.uset.find(source) != m.uset.end()) {
			m.uset.insert(&I);
			m.uset.insert(target);
		    }
		    //if (m.uset.find(target) != m.uset.end()) {
		    //    m.uset.insert(&I);
		    //}
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(target) != \
			    m.second.uset.end()) {
			m.second.uset.insert(&I);
			break;
		    }
		}
		break;
	    case Instruction::Sub:
	    case Instruction::Add:
	    case Instruction::Mul:
	    case Instruction::Shl:
	    case Instruction::And:
	    case Instruction::Or:
	    case Instruction::ICmp:
		// Instruction::And, Or
		source = I.getOperand(0);
		source2 = I.getOperand(1);
		for (auto &m: argList) {
		    if (m.uset.find(source) != m.uset.end() || \
			    m.uset.find(source2) != m.uset.end()) {
			    m.uset.insert(&I);
		    }
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(source) != m.second.uset.end() || \
			    m.second.uset.find(source2) != m.second.uset.end()) {
			    m.second.uset.insert(&I);
		    }
		}
		break;
	    case Instruction::Br:
		break;
	    case Instruction::Alloca:
		allocaList[&I].funcArg = &I;
		allocaList[&I].care = 0;
		allocaList[&I].uset.insert(&I);
		break;
	    case Instruction::Call:
		ci = dyn_cast<CallInst>(&I);
	        if (!ci->getCalledFunction())
	            continue;
		for (auto &m: argList) {
		    if (m.uset.find(target) != m.uset.end()) {
			target_is_cared = 1;
			m.uset.insert(target);
			break;
		    }
		}
		for (auto &m: allocaList) {
		    if (m.second.uset.find(target) != \
			    m.second.uset.end()) {
			target_is_cared = 1;
			m.second.uset.insert(target);
			break;
		    }
		}
		if (!target_is_cared)
		    continue;
	        calledName = (ci->getCalledFunction()->getName()).str();
	        if (strstr(calledName.c_str(), name_memcpy)) {
		    insertApiCall(ci, API_MEMCPY_RECORD);
	        }
		else if (strcmp(calledName.c_str(), name_strncpy) == 0) {
		    insertApiCall(ci, API_STRNCPY_RECORD);
		}
		else if (strcmp(calledName.c_str(), name_fgets) == 0) {
		    //insertApiCall(ci, API_FGETS_RECORD);
		}
		else if (strcmp(calledName.c_str(), name_gets) == 0) {
		    //insertApiCall(ci, API_GETS_RECORD);
		}
		target_is_cared = 0;
	    default:
		break;
	    }
	}
    }
    if (curFunc->arg_size() == 0) {
	for (auto &regIndex: calleeRegIndexList) {
	    for (auto &iter: allocaList) {
		if (regIndex >= call->getNumOperands()) {
		  continue;
		}
		if (iter.second.uset.find(call->getOperand(regIndex)) != \
			iter.second.uset.end()) {
		    for (auto &I: iter.second.uset) {
			if (StoreInst *store = dyn_cast<StoreInst>(I)) {
			    if (is_fp)
				temp_fp_insertion.insert(store);
			    else temp_insertion.insert(store);
			    //insertApiCall(store, API_STORE_RECORD);
			}
		    }
		}
	    }
	}
    }
    else {
	for (auto &regIndex: calleeRegIndexList) {
	    for (int i = 0; i < argList.size(); i++) {
		if (regIndex >= call->getNumOperands()) {
		     continue;
		}
		if (argList[i].uset.find(call->getOperand(regIndex)) != \
			argList[i].uset.end()) {
		    argList[i].care = true;
		    res.insert(i);
		    for (auto &I: argList[i].uset) {
			if (StoreInst *store = dyn_cast<StoreInst>(I)) {
			    if (is_fp)
				temp_fp_insertion.insert(store);
			    else temp_insertion.insert(store);
			    //insertApiCall(store, API_STORE_RECORD);
			}
		    }
		}
	    }
	    for (auto &iter: allocaList) {
		if (regIndex >= call->getNumOperands()) {
		     continue;
		}
	        if (iter.second.uset.find(call->getOperand(regIndex)) != \
	        	iter.second.uset.end()) {
	            for (auto &I: iter.second.uset) {
	        	if (StoreInst *store = dyn_cast<StoreInst>(I)) {
			    if (is_fp)
				temp_fp_insertion.insert(store);
	        	    else temp_insertion.insert(store);
	        	}
	            }
	        }
	    }
	}
	for (auto &store: temp_insertion) {
	    if (is_fp)
		temp_fp_insertion.insert(store);
	    else temp_insertion.insert(store);
	}
    }
    return res;
}
void ArgumentAnalysisPass::FPHandler(std::pair<Function*, CallInst*>cur, \
    std::unordered_map<Function*, bool> visitedList) {
    auto curFunc = cur.first;
    auto ci = cur.second;
    std::unordered_set<int> regIndexList = FPGetRegIndexList(curFunc, ci);
    temp_fp_check_insertion.insert(ci);
    if (regIndexList.empty()) {
	return;
    }
    int count = 0;
    visitedList[curFunc] = true;
    bool is_fp = 1;
    for (auto &iter: ccPair[curFunc]) {
        if (visitedList[iter.first] == false) {
            handler(iter, regIndexList, visitedList, count, is_fp);
        }
    }
}
void ArgumentAnalysisPass::handler( \
	std::pair<Function*, CallInst*> cur, \
	std::unordered_set<int> &calleeRegIndexList, \
	std::unordered_map<Function*, bool> &visitedList, int &count, bool is_fp) {
    Function *curFunc = cur.first;
    CallInst *callInstruction = cur.second;
    visitedList[curFunc] = true;
    count++;
    if (count > HANDLER_THRESHOLD) {
        return;
    }
    std::unordered_set<int> regIndexList = getRegIndexList(curFunc, \
	    callInstruction, calleeRegIndexList, is_fp);
    for(auto &iter: regIndexList) {
    }
    //Insert check point at the last instruction
    BasicBlock &lastBB = curFunc->back();
    Instruction &lastInst = lastBB.back();
    BasicBlock &firstBB = curFunc->front();
    Instruction &firstInst = firstBB.front();
    if (regIndexList.empty()) {
	return;
    }
//    if (is_fp)
//	temp_fp_check_insertion.insert(&lastInst);
//	insertApiCall(&lastInst, API_FP_CHECK);
//    else
//	insertApiCall(&lastInst, API_CHECK);
//    insertApiCall(&firstInst, API_CHECK_REG);
    temp_reg_insertion.insert(&firstInst);

    for (auto &iter: ccPair[curFunc]) {
	if (visitedList[iter.first] == false) {
	    visitedList[iter.first] = true;
	    //insertApiCall(iter.second, API_RECORD_REG);
	    temp_record_reg_insertion.insert(iter.second);
	    handler(iter, regIndexList, visitedList, count, is_fp);
	}
    }
}
void ArgumentAnalysisPass::insertApiCall(Value *val, int api) {
    if (!isa<Instruction>(val))
	return;
    Instruction *apiCall = dyn_cast<Instruction>(val);
    Instruction *nextInst;
    LLVMContext &Ctx = apiCall->getContext();
    DataLayout DL = apiCall->getModule()->getDataLayout();
    std::vector<Type*> paramTypes;
    Type *retType = Type::getVoidTy(Ctx);
    FunctionType *apiFuncType;
    FunctionCallee apiFunc;
    std::vector<Value *>args;
    switch (api) {
    case API_REMAP: {
	IRBuilder<> builder(apiCall);
	builder.SetInsertPoint(apiCall);
	paramTypes.push_back(Type::getVoidTy(Ctx));
	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = apiCall->getModule()->getOrInsertFunction( \
		    "api_scs_remap", apiFuncType);
	builder.CreateCall(apiFunc, args);
	return;

    }
    case API_CHECK: {
	int is_syscall = 0;
	if (auto ci = dyn_cast<CallInst>(val)) {
	    if (calleeIsSyscall(ci)) {
		is_syscall = 1;
	    }
	}
	IRBuilder<> builder(apiCall);
	builder.SetInsertPoint(apiCall);
	paramTypes.push_back(Type::getInt32Ty(Ctx));
	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = apiCall->getModule()->getOrInsertFunction( \
		"api_check", apiFuncType);
	args.push_back(builder.getInt32(is_syscall));
	builder.CreateCall(apiFunc, args);
	return;
    }
    case API_RECORD_REG: {
	nextInst = apiCall;
	CallInst *apiCall = dyn_cast<CallInst>(val);
	if (apiCall == NULL)
	    return;
	IRBuilder<> builder(nextInst);
	//IRBuilder<> builder(apiCall);
//	builder.SetInsertPoint(apiCall);
	paramTypes.push_back(Type::getInt32Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));

	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = apiCall->getModule()->getOrInsertFunction( \
	            "api_record_reg", apiFuncType);
	int i = 0;
	for (i = 0; i < apiCall->arg_size(); i++) {
	    args.push_back(builder.getInt32(i));
	    if (isa<LoadInst>(apiCall->getOperand(i))) {
		auto load = dyn_cast<LoadInst>(apiCall->getOperand(i));
		auto src = load->getOperand(0);
		args.push_back(src);
	    }
	    else {
		args.push_back(apiCall->getOperand(i));
	    }
	    builder.SetInsertPoint(nextInst);
	    builder.CreateCall(apiFunc, args);
	    //nextInst = nextInst->getNextNode();
	}
	return;		
    }
    case API_CHECK_SYSCALL: {
	nextInst = apiCall;
	CallInst *ci = dyn_cast<CallInst>(val);
	if (ci == NULL)
	    return;
	//IRBuilder<> builder(apiCall);
//	builder.SetInsertPoint(apiCall);
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));

	paramTypes.push_back(Type::getInt32Ty(Ctx));
	paramTypes.push_back(Type::getInt32Ty(Ctx));
	//last argument bit i means ith arg is addr/val 
	paramTypes.push_back(Type::getInt32Ty(Ctx));
	int reg_max = 6;
	reg_max -= ci->arg_size();
	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = ci->getModule()->getOrInsertFunction( \
	            "api_check_syscall", apiFuncType);
	IRBuilder<> builder(nextInst);
	int i, bits = 0;
	for (i = 0; i < ci->arg_size(); i++) {
	    if (isa<LoadInst>(ci->getOperand(i))) {
		auto load = dyn_cast<LoadInst>(ci->getOperand(i));
		auto src = load->getOperand(0);
		args.push_back(src);
		bits |= 1 << i;
	    }
	    else {
		args.push_back(ci->getOperand(i));
	    }
	}
	while (reg_max > 0) {
	    args.push_back(builder.getInt32(0));
	    reg_max--;
	}
	auto name = ci->getCalledFunction()->getName();
	if (name.equals("open")) {
	    args.push_back(builder.getInt32(0x38));
	}
	else if (name.equals("read")) {
	    args.push_back(builder.getInt32(0x3f));
	}
	else {
	    args.push_back(builder.getInt32(-1));
	}
	args.push_back(builder.getInt32(i));
	args.push_back(builder.getInt32(bits));
	builder.SetInsertPoint(nextInst);
	builder.CreateCall(apiFunc, args);
	return;		
    }
    case API_CHECK_REG: {
	nextInst = apiCall;
	paramTypes.push_back(Type::getInt32Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = apiCall->getModule()->getOrInsertFunction( \
		"api_check_reg", apiFuncType);
	auto F = apiCall->getParent()->getParent();
	//errs() << "API_CHECK_REG: " << F->getName() << "\n";
	int i = 0;
	for (auto arg = F->arg_begin(); arg != F->arg_end(); arg++, i++) {
	    IRBuilder<> builder(nextInst);
	    args.push_back(builder.getInt32(i));
	    if (isa<LoadInst>(arg)) {
		auto load = dyn_cast<LoadInst> (arg);
		auto src = load->getOperand(0);
		//errs() << "src: " << src <<"\n";
		args.push_back(src);
	    }
	    else args.push_back(arg);
	    builder.SetInsertPoint(nextInst);
	    builder.CreateCall(apiFunc, args);
	    args.clear();
	    //nextInst = nextInst->getNextNode();
	}
	return;
    }
    case API_FP_RECORD: {
	nextInst = apiCall->getNextNode();
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	paramTypes.push_back(Type::getInt64Ty(Ctx));
	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = apiCall->getModule()->getOrInsertFunction( \
		"api_fp_record", apiFuncType);
	IRBuilder<> builder(nextInst);
	builder.SetInsertPoint(nextInst);
	if (StoreInst *store = dyn_cast<StoreInst>(apiCall)) {
	    args.push_back(apiCall->getOperand(0));
	    args.push_back(apiCall->getOperand(1));
	} else if (LoadInst *load = dyn_cast<LoadInst>(apiCall)) {
	    args.push_back(apiCall);
	    args.push_back(apiCall->getOperand(0));
	}
	builder.CreateCall(apiFunc, args);
	return;
    }
    case API_FP_CHECK: {
	IRBuilder<> builder(apiCall);
	builder.SetInsertPoint(apiCall);
	paramTypes.push_back(Type::getVoidTy(Ctx));
	apiFuncType = FunctionType::get(retType, paramTypes, false);
	apiFunc = apiCall->getModule()->getOrInsertFunction( \
		"api_fp_check", apiFuncType);
	builder.CreateCall(apiFunc, args);
	return;
    }
    }

    //Record api
    nextInst = apiCall->getNextNode();
    IRBuilder<> builder(nextInst);
    builder.SetInsertPoint(nextInst);
    paramTypes.push_back(Type::getInt64Ty(Ctx));
    paramTypes.push_back(Type::getInt64Ty(Ctx));
    paramTypes.push_back(Type::getInt32Ty(Ctx));;
    paramTypes.push_back(Type::getInt64Ty(Ctx));
    apiFuncType = FunctionType::get(retType, paramTypes, false);
    apiFunc = apiCall->getModule()->getOrInsertFunction( \
		"api_record", apiFuncType);
    switch (api) {
    case API_STORE_RECORD:
	args.push_back(apiCall->getOperand(0));
	args.push_back(apiCall->getOperand(1));
	if (apiCall->getOperand(0)->getType()->isIntegerTy()) {
	    //errs() << "size: " << dyn_cast<IntegerType>(apiCall->getOperand(0)->getType())->getBitWidth() << "\n";
	    args.push_back(builder.getInt32(0));
	    args.push_back( \
		builder.getInt32( \
		dyn_cast<IntegerType>( \
		apiCall->getOperand(0)->getType())->getBitWidth()
		)
	    );
	}
	else if (apiCall->getOperand(0)->getType()->isPointerTy()){
	    //I think default is pointer?
	    args.push_back(builder.getInt32(1));
	    args.push_back(builder.getInt64(0));
	}
	else{
	    errs() << "ERROR: Instruction with unknown type operand.\n";
	    // Is not pointer and size is zero is an error case.
	    args.push_back(builder.getInt32(0));
	    args.push_back(builder.getInt64(0));
	}
	break;
    case API_MEMCPY_RECORD:
    case API_STRNCPY_RECORD:
	args.push_back(apiCall->getOperand(1));
	args.push_back(apiCall->getOperand(0));
	args.push_back(builder.getInt32(1));
	args.push_back(apiCall->getOperand(2));
	break;
    case API_FGETS_RECORD:
	args.push_back(apiCall->getOperand(0));
	args.push_back(apiCall->getOperand(0));
	args.push_back(builder.getInt32(1));
	args.push_back(apiCall->getOperand(1));
	break;
    case API_GETS_RECORD:
	args.push_back(apiCall->getOperand(0));
	args.push_back(apiCall->getOperand(0));
	args.push_back(builder.getInt32(1));
	args.push_back(builder.getInt32(0));
	break;
    default:
	errs() << "ERROR: Unkown api.\n";
	break;
    }
    builder.CreateCall(apiFunc, args);
    return;
}

bool ArgumentAnalysisPass::runOnFunction(Function &F) {
    //errs() << "[" << __func__ << "]" << F.getName() << " " << &F << "\n";
    bool Transformed = false;
    std::unordered_map<Function*, bool> visitedList;
    for (auto &BB: F) {
	for (auto I = BB.begin(); I != BB.end(); I++) {
	    if (CallInst *ci = dyn_cast<CallInst>(I)) {
	        if (calleeIsSyscall(ci)) {
		    //insertApiCall(ci, API_REMAP);
	            std::unordered_set<int> callRegList;
	            for (unsigned i = 0; i < ci->arg_size(); i++) {
			callRegList.insert(i);
		    }
		    if (!callRegList.empty()) {
			//insertApiCall(ci, API_CHECK_SYSCALL);
			//insertApiCall(ci, API_CHECK);
			int count = 0;
			handler(std::make_pair(&F, ci), callRegList, visitedList, count, 0);
		    }    	        
		}
		else if (!ci->getCalledFunction()) {
		    FPHandler(std::make_pair(&F,ci), visitedList);
		    //temp_fp_check_insertion.insert(ci);
		    //insertApiCall(ci, API_FP_CHECK);
		    std::unordered_set<int> callRegList;
		    //if (ci->arg_size() > 0) {
		    //    callRegList.insert(0);
		    //}
		    //for (unsigned i = 0; i < ci->arg_size(); i++) {
		    //    callRegList.insert(i);
		    //}
		    //if (!callRegList.empty()) {
		    //    errs() << __func__ << " " << __LINE__ << "\n";
		    //    insertApiCall(ci, API_CHECK);
		    //    int count = 0;
		    //    handler(std::make_pair(&F, ci), callRegList, visitedList, count);
		    //}
		}
	    }
	}
    }
    return false;
}


ArgumentAnalysisPass::ArgumentAnalysisPass() {
    syscallVec.push_back("execve");
    syscallVec.push_back("execveat");
    syscallVec.push_back("clone");

    syscallVec.push_back("mmap");
    syscallVec.push_back("mermap");
    syscallVec.push_back("mprotect");

    syscallVec.push_back("socket");
    syscallVec.push_back("bind");
    syscallVec.push_back("connect");
    syscallVec.push_back("accept");
    syscallVec.push_back("accept4");
    syscallVec.push_back("listen");

    syscallVec.push_back("pthead_create");
    syscallVec.push_back("fopen");
    syscallVec.push_back("open");
    syscallVec.push_back("openat");
    syscallVec.push_back("read");
    syscallVec.push_back("write");
    syscallVec.push_back("sendfile");
    syscallVec.push_back("recvfrom");
}
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "ArgumentAnalysis pass",
        .PluginVersion = "v0.1",
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
		    MPM.addPass(ArgumentAnalysisPass());
                });
        }
    };
}
