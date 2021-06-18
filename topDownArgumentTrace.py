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
    
    TODO:
        *Determine how many far to look back before I determine an unsuccessful lookup and cut my losses.
'''
def evaluateELF32Function(currAddr, func):
    #Find out how many arguments I need to find.
    argCount = func.getParameterCount()
    
    if 1 <= argCount:
        #Since this is 32bit elf everything will be passed on the stack, so start looking for push arguments at the called address
        prevInstr = getInstructionAt(currAddr).getPrevious()
    
        if "PUSH" != prevInstr.getMnemonicString():
            print("Something is awry...previous instruction should be a PUSH. Exiting...")
        else:
            '''
                TODO: Will likely need to create a loop here for functions with multiple arguments
            '''
            #Retrieve the register used by PUSH. There should only ever be 1 operand for PUSH but just in case...
            numOfOperands = prevInstr.getNumOperands()
            regOfInterest = prevInstr.getDefaultOperandRepresentation(numOfOperands-1)
            
            #Retrieve previous instruction to see if this is where the register was assigned a value
            prevInstr = prevInstr.getPrevious()
            
            #The possible previous instruction will be very difficult to know. We can limit it slightly, but there are a lot of possibilities
            destString, sourceString = retrieveOperands(prevInstr)
            
            if regOfInterest == destString:
                if "EBP" in sourceString:
                    print("FOUND")
    else:
        print("Shouldn't be here...There are no arguments.")
            
            
            

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