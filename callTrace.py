#Currently finds all the functions called from within main, and the address its called at.
#@author Alex Wollman
#@category Python.GhidraScript.Analysis
#@keybinding
#@menupath
#@toolbar

import ghidra.app.script.GhidraScript
import sys

def printFunctions(funcDict, nameString):
    print("%s function and addresses called at:" % nameString)
    for key in funcDict.keys():
        sys.stdout.write("\t%s: " % key)
        for value in funcDict[key]:
            sys.stdout.write(" %s" % value)
        sys.stdout.write("\n")


if __name__ == "__main__":
    mainFunction = getFunctionContaining(currentAddress)
    walkAddr = mainFunction.body.getMinAddress()
    endAddr = mainFunction.body.getMaxAddress()
    
    thunkFunctions = dict()
    nonThunkFunctions = dict()
    
    while walkAddr != endAddr:
        currInstr = getInstructionAt(walkAddr)
        if "CALL" == currInstr.getMnemonicString():
            calledFunc = getFunctionContaining(currInstr.getPrimaryReference(0).getToAddress())
            if calledFunc.isThunk():
                if calledFunc.getName() not in thunkFunctions:
                    thunkFunctions[calledFunc.getName()] = [walkAddr.toString()]     #same address as the primary reference address.
                else:
                    thunkFunctions[calledFunc.getName()].append(walkAddr.toString())
            else:
                if calledFunc.getName() not in nonThunkFunctions:
                    nonThunkFunctions[calledFunc.getName()] = [walkAddr.toString()]     #same address as the primary reference address.
                else:
                    nonThunkFunctions[calledFunc.getName()].append(walkAddr.toString())
        walkAddr = currInstr.getNext().getAddress()
    
    
    printFunctions(thunkFunctions, "Thunked")
    printFunctions(nonThunkFunctions, "Non-Thunked")