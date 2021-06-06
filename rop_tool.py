import ghidra.app.util.headless.HeadlessScript
import ghidra.app.services
import os
from ghidra.program.model.lang import Register
from ghidra.app.services import AbstractAnalyzer

#Important constant values
ELF_32BIT                   = 0x1
ELF_64BIT                   = 0x2
HOME_DIR                    = os.path.expanduser("~")+"/.cycle2Output"
INTERESTING_INSTR           = list(("JMP", "RET"))
HELPFUL_INSTR               = list(("NOP", "POP", "PUSH", "MOV", "ADD", "SUB", "MUL", "DIV", "XOR"))


def isStartInstruction(instruction):
    retValue = False
    
    for opCode in INTERESTING_INSTR:
        if opCode == instruction.getMnemonicString():
            retValue = True
            break
    
    return retValue

def makeGadget(instr, gadgetList):
    programName = currentProgram.getName()
        
    outputFile = open(HOME_DIR+"/"+programName+"_roptest.txt", "w")
    if instr.getMnemonicString() in HELPFUL_INSTR:
        gadgetList.append(instr)
        makeGadget(instr.getPrevious(), gadgetList)
        
        for index in range(len(gadgetList)-1, -1, -1):
            tempInstr = gadgetList[index]
            if index == len(gadgetList) - 1:
                outputFile.write(tempInstr.getMinAddress().toString()+": ")
            outputFile.write(tempInstr.toString() +";")
        outputFile.write("\n")
        del gadgetList[:]
            
if __name__ == "__main__":
    
    if not os.path.exists(HOME_DIR):
        os.mkdir(HOME_DIR)
    
    
    #retrieves an iterator going forward through the code
    code = currentProgram.getListing().getInstructions(True)
    gadget = list()
    
    while code.hasNext():
        tmp = code.next()
        if isStartInstruction(tmp):
            gadget.append(tmp)
            prevInstr = tmp.getPrevious()
            makeGadget(prevInstr, gadget)
            
            
            
            
            
            
