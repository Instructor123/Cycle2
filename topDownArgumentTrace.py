#Traces the arguments to the current function through any subsequent function calls. Will not do anything on thunked functions.
#@author Alex Wollman
#@category Python.GhidraScript.Analysis
#@keybinding
#@menupath
#@toolbar

import ghidra.app.script.GhidraScript

'''
    This function needs to know how many arguments to locate at the calling location.
    For each argument there will be an equal number of pushes, which also means there will be an equal amount of 'load' style commands.
    These can take many forms: add, sub, mul, div, mod, mov, lea, etc. The method I'm going to use will be to find the mov, push command
    which stores the value onto the stack and examine the previous instruction to see if the register is the destination. If it is then I've
    found the relevant instruction, if it isn't I have to keep looking. 
    
    UPDATE:
    The problem:
       prior to the call there can be (at minimum) 2 different ways of setting up the call
           push ABC
           push XXX
           call ...
        OR
            MOV ABC, ZZZ
            push ABC
            LEA XXX, YYY
            push XXX
            call ...
    This makes it more difficult to track down which arguments are located where.
    
    What we know:
        * The function knows how many arguments to expect, so we know how many PUSH instructions to look for.
        * Since we know the PUSH count, we also know the LEA count.
    
    What does this mean:
        Once we find a push we can add the register to a list and track if we've found an LEA which stores a value there.
        Once found we can print that stuff to the screen, remove it from the list, and continue on.
    
    Way Forward:
        Move up the instructions and store PUSH instructions in one list (or their address) and anything else with a matching destination into
        another list. The benefit here is that as we move up we MUST encounter the PUSH before the associated LEA otherwise we'd be PUSHing an
        incorrect value. This will prevent us missing an LEA that we care about.
'''
def evaluateELF32Function(currAddr, func):
    #Find out how many arguments I need to find.
    argCount = func.getParameterCount()
    #likely not a complete list - maybe ghidra has something?
    regList = list(("EAX", "EBX", "ECX", "EDX"))
                
    #This involves more stepping so we'll create a local variable to modify and move
    localAddr = currAddr
    pushRegList = list()
    otherList = list()  #This could be empty depending on the scenario
    while argCount > 0:
        prevInstr = getInstructionAt(currAddr).getPrevious()
        if "PUSH" == prevInstr.getMnemonicString():
            pushRegList.append(prevInstr.getDefaultOperandRepresentation(0))
            argCount -= 1
        else:
            otherList.append(prevInstr)
        currAddr = prevInstr.getAddress()
    
    #TODO: Fix this argCount reset to not be necessary.
    argCount = func.getParameterCount()
    #If this list is not empty we need to find out if the destination matches any of the PUSH registers
    if 0 != len(otherList):
        for instr in otherList:
            destLoc, source = retrieveOperands(instr)
            if destLoc in pushRegList:
                print(destLoc, source)
                argCount -= 1
                pushRegList.remove(destLoc)
    
    #first check if any of the values are immediates; if they are we print it and we're done.
    for value in pushRegList:
        if value not in regList:
            print(value)
            argCount -= 1

    #if it's greater than 0 we still have to locate a register, and pushRegList is not empty.
    while argCount > 0:
        prevInstr = prevInstr.getPrevious()
        destLoc, source = retrieveOperands(prevInstr)
        
        if destLoc != None and source != None:
            print(destLoc, source)
            argCount -= 1
            
def retrieveFunction(addr):
    instr = getInstructionAt(addr)
    retValue = None
    
    if "CALL"  != instr.getMnemonicString():
        print("ERROR: Cursor must be on CALL instruction. Quitting")
    else:
        retValue = getFunctionContaining(instr.getPrimaryReference(0).getToAddress())

    return retValue

'''
    This will test to find which instruction is being used, and then retrieve the subsequent operands. Two things will be returned:
    *** The destination as a single argument
    *** The source as a list of arguments
    Operands are, from left to right, the destination and source. Using the 'getDefaultOperandRepresentation function we can retrieve a string of the operand.
'''
def retrieveOperands(instr):
    mnemonic = instr.getMnemonicString()
    
    dest = None
    source = None
    
    #LEA should only have 2 operands: destination and source. However to be cautious...
    if "LEA" == mnemonic:
        operandCount = instr.getNumOperands()
        dest = instr.getDefaultOperandRepresentation(operandCount - 2)
        source = instr.getDefaultOperandRepresentation(operandCount - 1)
    elif "MOV" == mnemonic:
        operandCount = instr.getNumOperands()
        dest = instr.getDefaultOperandRepresentation(operandCount - 2)
        source = instr.getDefaultOperandRepresentation(operandCount - 1)
    else:
        print("Unhandled mnemonic: %s" % mnemonic)
    
    return dest, source

def verify32Bit():
    retValue = False
    #returns a colon (:) separated list of values comprised of architecture, endianness, bits(32/64) and something else which is labeled 'default'
    idSplit = currentProgram.getLanguageID().toString().split(":")
    
    if "32" == idSplit[2]:
        retValue = True

    return retValue

def verifyELF():
    retValue = False
    format = currentProgram.getExecutableFormat().split(" ")[-1]
    
    if "(ELF)" == format:
        retValue = True
    
    return retValue

if __name__ == "__main__":
    
    if True != verify32Bit() and True != verifyELF():
        print("Only 32-bit ELF is currently supported.")
    else:
        addr = currentAddress
        func = retrieveFunction(addr)
        if None != func:
            evaluateELF32Function(addr, func)
            
            
            
            
            
            
            