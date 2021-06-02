# Cycle 2
## Details
- Course: CSC842 Security Tool Development
- Developer: Alex Wollman
- Language: Python 2.7 (Jython technically)
- Scope: File Analysis/Exploitation
## Description
In this cycle I'm creating headless python scripts for Ghidra 9.2.3. The purpose is to build a suite of scripts which can be run in bulk analysis through Ghidra's 'analyseHeadless' tool. Scripts will range from simple analysis (finding functions, starting addresses, number of arguments, etc.)
## Capabilities
### Main's functions
The first script finds main and all of the called functions within main. Here a called function means a non-standard library function, or something that is resolved through the PLT/GOT process.

The purpose of this function is to give the analyst an idea of how "big" the program is and how many user defined functions exist within the program. Future work could include providing how big the function is (how many 'lines' it is comprised of) and any calls made from within that function.
