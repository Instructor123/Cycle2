# Cycle 2
## Details
- Course: CSC842 Security Tool Development
- Developer: Alex Wollman
- Language: Python 2.7 (Jython technically)
- Scope: File Analysis/Exploitation
## Description
In this cycle I'm creating headless python scripts for Ghidra 9.2.3. The purpose is to build a suite of scripts which can be run in bulk analysis through Ghidra's 'analyseHeadless' tool. Scripts will range from simple analysis (finding functions, starting addresses, number of arguments, etc.) to exploitation assistance.
## Capabilities
### Main's functions
The first script finds main and all of the called functions within main. Here a called function means a non-standard library function, or something that is resolved through the PLT/GOT process. The output is formatted in a JSON file and saved in the home directory under a hidden folder called ".cycle2Output." A better name and location would be preferred. Each file analyzed gets its own file, which will help with analysis after the fact. Currently only JSON is supported as an output file format.

The purpose of this function is to give the analyst an idea of how "big" the program is and how many user defined functions exist within the program. Future work could include providing how big the function is (how many 'lines' it is comprised of) and any calls made from within that function.

### ROP Tool
This fledgling script is loosely based off the excellent work done by Chris Eagle and Kara Nance in their book "The Ghidra Book." Trying to find (and build) ROP gadgets is a very large problem that has many different nuances and rabbit holes. What is attempted in this script is the beginning of a ROP gadget locator/creator that runs in headless mode. Much like the previous script, the output files are located under the hidden folder ".cycle2Output", with each input file creating a cooresponding output file. This file is not JSON formatted, but instead contains a possible gadget on each line.

As this is just the very beginning steps of the script the gadgets are, quite honestly, useless. The script keys off of 'JMP' and 'RET' instructions to begin its gadget search, working backwards to identify the other operations. This method obviously does not take advantage of any problems inherent with the RISC design to locate/create gadgets, but it is a starting place.

## Usage
There is plenty of documentation available for Ghidra, so instead of repeating everything, below are the commands that will execute the scripts. The first command creates the project (if it doesn't exist) TestProject and imports all the files under the exec/ folder. This triggers analysis and all of the usual analyzers that run when you start Ghidra normally. The second command skips the analysis step. This is useful when you've already imported/analyzed the binaries and you only want to run scripts. 
- analyzeHeadless ~/ghidraProjects/ghidra_9.2.3/ TestProject/ -import ~/exec/* -postScript headless_FindingMain.py -postScript rop_tool.py
- analyzeHeadless ~/ghidraProjects/ghidra_9.2.3/ TestProject/ -process -noanalysis -postScript headless_FindingMain.py -postScript rop_tool.py
