# Headless script that finds the functions that main calls.
#@author Alex Wollman
#@category Functions.Python
import ghidra.app.util.headless.HeadlessScript
import binascii
import os


#Important constant values
#Offset within header where entry point is
ENTRY_POINT_OFFSET          = 24
GHIDRA_OFFSET               = 0x10
ELF_32BIT                   = 0x1
ELF_64BIT                   = 0x2

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

    print(currentProgram.getName())
    print(currentProgram.getExecutablePath())
    print(currentProgram.getImageBase())

    if True == verify64Bit():
        startFunction = retrieveEntryPointFunction()

        if None != startFunction:
            beginRange = startFunction.getBody().getMinAddress()
            endRange = startFunction.getBody().getMaxAddress()
            
            mainFunc = retrieveMainFunc(beginRange, endRange)
            callInstrAddr = retrieveNonThunkFunctionCalls(mainFunc.getBody().getMinAddress(), mainFunc.getBody().getMaxAddress())

            for x in callInstrAddr:
                instr = getInstructionAt(x)
                print(getFunctionContaining(instr.getPrimaryReference(0).getToAddress()).getName())
            

    else:
        print("Must not be 64 bit")