# Headless script that finds the functions that main calls.
#@author Alex Wollman
#@category Functions.Python
import ghidra.app.util.headless.HeadlessScript
import binascii
import os
import json
import sys

#Important constant values
ELF_32BIT                   = 0x1
ELF_64BIT                   = 0x2
ENTRY_POINT_OFFSET          = 24
#Not a great choice, looking for improvements
HOME_DIR                    = os.path.expanduser("~")+"/.cycle2Output"


def retrieveNonThunkFunctionCalls(startAddr, endAddr):
    movingAddr = startAddr
    retList = list()

    while movingAddr != endAddr:
        #https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html
        instr = getInstructionAt(movingAddr)
        if instr.getMnemonicString() == "CALL":
            boolThunk = getFunctionContaining(instr.getPrimaryReference(0).getToAddress()).isThunk()
            if boolThunk != True:
                retList.append(movingAddr)
        movingAddr = getInstructionAt(movingAddr).getNext().getAddress()
    
    return retList

def retrieveMainFunc(start, end):
    movingAddr = start
    mainLocation = None

    while movingAddr != end:
        #https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html
        instr = getInstructionAt(movingAddr)
        if instr.getMnemonicString() == u"LEA" and 2 == instr.getNumOperands():
            if u"RDI" == instr.getRegister(0).toString():
                mainLocation = instr.getPrimaryReference(1).getToAddress()
        movingAddr = getInstructionAt(movingAddr).getNext().getAddress()

    return getFunctionContaining(mainLocation)

def retrieveEntryPointFunction():
    entryPointLocation = currentAddress.add(ENTRY_POINT_OFFSET)
    temp = getBytes(entryPointLocation,8)[::-1]
    #This is technically a long, so GHIDRA_OFFSET will also contain a 'L' which needs to be removed.
    GHIDRA_OFFSET = currentProgram.getImageBase().getUnsignedOffset()
    tempArray = binascii.hexlify(temp)
    #removing 'L' to allow for proper conversion in getAddress function.
    hexArray = hex(GHIDRA_OFFSET + int(tempArray,16)).rstrip("L")
    newAddress = currentAddress.getAddress(hexArray)
    entryPoint = getFunctionContaining(newAddress)

    return entryPoint

def verify64Bit():
    arch = getBytes(currentAddress.add(4),1)[0]
    retValue = False
    if ELF_64BIT == arch:
        retValue = True
    
    return retValue

'''
    This script, unlike others, starts within the header. We have to navigate our way to the 
    start function and then to main.
'''
if __name__ == "__main__":

    programName = currentProgram.getName()
    programPath = currentProgram.getExecutablePath().rstrip(programName)

    programInfo = dict()
    programInfo["Path"] = programPath
    programInfo["Name"] = programName

    if not os.path.exists(HOME_DIR):
        os.mkdir(HOME_DIR)

    if True == verify64Bit():
        startFunction = retrieveEntryPointFunction()

        if None != startFunction:
            beginRange = startFunction.getBody().getMinAddress()
            endRange = startFunction.getBody().getMaxAddress()
            
            mainFunc = retrieveMainFunc(beginRange, endRange)
            callInstrAddr = retrieveNonThunkFunctionCalls(mainFunc.getBody().getMinAddress(), mainFunc.getBody().getMaxAddress())

            callInstr = dict()
            for x in callInstrAddr:
                instr = getInstructionAt(x)
                callInstr[getFunctionContaining(instr.getPrimaryReference(0).getToAddress()).getName()] = instr.getPrimaryReference(0).getToAddress().toString()

            programInfo["FunctionsCalled"] = callInstr
    
        with open(HOME_DIR+"/"+programName+"output.json", "w") as outputFile:
            json.dump(programInfo, outputFile)
    else:
        print("Must not be 64 bit")