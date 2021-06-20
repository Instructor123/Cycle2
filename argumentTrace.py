#Traces the arguments of the currently selected function and displays any function calls (in the current function) that uses it.
#@author Alex Wollman
#@category Python.GhidraScript.Analysis
#@keybinding
#@menupath
#@toolbar

import ghidra.app.script.GhidraScript
#https://github.com/NationalSecurityAgency/ghidra/blob/e43ef9baaf3c21efb5ea20c3a4d3314d64fdb5cf/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/lang/OperandType.java#L24
import ghidra.program.model.lang.OperandType

def retrieveELF32Arguments(currAddr, func, argCount):
    #Find out how many arguments I need to find.
    #likely not a complete list - maybe ghidra has something?
    regList = list(("EAX", "EBX", "ECX", "EDX"))
    #This involves more stepping so we'll create a local variable to modify and move
    localAddr = currAddr
    pushRegList = list()
    otherList = list()  #This could be empty depending on the scenario
    retList = list()
    while argCount > 0:
        prevInstr = getInstructionAt(currAddr).getPrevious()
        if "PUSH" == prevInstr.getMnemonicString():
            argCount -= 1
            operandType = hex(prevInstr.getOperandType(0))
            if "0x4000" == operandType or "0x6000" == operandType:
                print("\tScalar or memory address \"%s\" in argument list, not searching." % prevInstr.getDefaultOperandRepresentation(0))
            else:
                pushRegList.append(prevInstr.getDefaultOperandRepresentation(0))
        else:
            otherList.append(prevInstr)
        currAddr = prevInstr.getAddress()
    
    '''
    #TODO: Fix this argCount reset to not be necessary.
    This is causing problems due to immediate values. If we simply reset to 'argCount' then we're
    negating the exclusion of immediates, which are not loaded into a register but simply PUSHed. The
    2nd for loop below would iterate until it found all of the PUSHes that have register values, which is
    not correct. For now I am fixing this by taking the len of the pushReglist, which should represent the
    real number of registers to search for. This value however is slightly 'magical' because it is not being
    used in the 2nd for loop below, when it maybe should.
    '''
    argCount = len(pushRegList)
    #If this list is not empty we need to find out if the destination matches any of the PUSH registers
    if 0 != len(otherList):
        for instr in otherList:
            destLoc, source = retrieveOperands(instr)
            if destLoc in pushRegList:
                retList.append(source)
                argCount -= 1
                pushRegList.remove(destLoc)
    #first check if any of the values are immediates; if they are we print it and we're done.
    #This should be obsolete now because of lines 25-29, but leaving in just in case
    for value in pushRegList:
        if value not in regList:
            print("\t\"%d\" is an immediate; not searching for it." % int(value, 16))
            argCount -= 1

    #if it's greater than 0 we still have to locate a register, and pushRegList is not empty.
    while argCount > 0:
        prevInstr = prevInstr.getPrevious()
        destLoc, source = retrieveOperands(prevInstr)
        
        if destLoc != None and source != None:
            retList.append(source)
            argCount -= 1

    return retList

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

def trackELF32Arguments():
    loc = currentAddress
    tracingFunction = retrieveFunction(loc)

    if None != tracingFunction:
        parentFunction = getFunctionContaining(loc)
        paramCount = tracingFunction.getParameterCount()
        paramList = list()
        if 0 != paramCount:
            print("%d parameters to function %s. Starting search..." % (paramCount, tracingFunction.getName()))
            argumentList = retrieveELF32Arguments(loc, tracingFunction, paramCount)
            if 0 != len(argumentList):
                parentStart = parentFunction.body.getMinAddress()
                parentEnd = parentFunction.body.getMaxAddress()
                instr = getInstructionAt(parentStart)
                
                while parentEnd != instr.getAddress():
                    numOperands = instr.getNumOperands()
                    if 2 <= numOperands:
                        for operPos in range(numOperands):
                            #Need to check if any of the operands match the ones we're looking for.
                            oper = instr.getDefaultOperandRepresentation(operPos)
                            if oper in argumentList:
                                paramList.append((instr.getAddress(), oper))
                    instr = instr.getNext()
            else:
                print("\tNo dynamic arguments: does this function accept variables?")
        else:
            print("\tNo arguments are provided for this function.")
        
        if 0 != len(paramList):
            for x in paramList:
                print("\tMatching parameter \'%s\' found at address 0x%s" % (x[1],  x[0]))

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

'''
    This script is going to look through the whole program to find where specified arguments are used.
    The user will click on a function that contains arguments, and this script will locate all the other locations, in the same function, that those
    arguments are used.
    
    Order:
        * Grab the arguments out of the selected function
        * Go over the entire function and collect all of the call instructions
        * For each call instruction
        ** Determine if it takes arguments
        ** If it does determine if it is referencing/using the ones' we care about
        *** If it is then print it to the screen, otherwise continue on.
    
    There is a possibility to recursively go through this process to find all the subsequent function calls that use these variables too.
'''

if __name__ == "__main__":
    
    if True != verify32Bit() and True != verifyELF():
        print("Only 32-bit ELF is currently supported.")
    else:
        trackELF32Arguments()
        
    