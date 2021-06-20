# Cycle 5
## Details
- Course: CSC842 Security Tool Development
- Developer: Alex Wollman
- Language: Python 2.7 (Jython technically)
- Scope: File Analysis/Exploitation
## Description
I'm creating more scripts this cycle, basically extending the work from cycle 3. Instead of headless scripts this time however I'm writing 'normal' Ghidra Scripts designed to be run from the GUI. In addition I'm starting work on a module to offer an interface for all of the scripts and their output. The design goal is to write several scripts that do one thing, then combine them through the module to offer many different capabilities without having to rewrite everything. This will also offer one place to do analysis, instead of tracking data through the script output.
## Capabilities
### callTrace
I'm taking the idea of finding function calls in main and extending it. Now I'm looking for all functions and dividing them into Thunked (library functions) and non-thunked (user functions.) Again this will not always result in a clean split of 'user' and 'library' but it gets started in the right direction. From here the script begins new work by retrieving the arguments to these functions. The eventual goal is to enable tracing of arguments to see where values were initially assigned or created in a different script.

The reason behind variable tracking stems from vulnerability hunting. In a world where strcpy is (or was if you're in denial) used, we want to find out if the contents of the source can in any way be controlled. If this strcpy is nested four, five, or more functions deep all while passing around the buffer it can be complicated and time consuming tracking this data. The goal of this script is to make that process easier.

### topDownArgumentTrace
One of the useful features of the GUI is you can double click on the output in the script and it will take you to that address. This is what the callTrace script will provide. This script will take the arguments to the function you're currently on and finds the stack location of the arguments. The next goal will be to track where those arguments are used within the function, and follow them through all the subsequent calls (and nested calls) of the program.

One of the limiting factors in this script is architecture. The calling convention most drastically changes depending on if we're in 32 or 64 bit (it changes depending on other factors too but this is what I'm focusing on right now.) 32-bit, for the most part, uses the stack to pass arguments to functions whereas 64-bit *primarily* uses registers. Linux/Mac/Windows comes into play here as well, so this becomes a very complicated task very quickly in the general case.

### argumentTrace
This is the prototype functionality that will likely be included in topDownArgumentTrace. This script starts at a function call, determines what the arguments to the function are, and then searches the same address space for the locations of the arguments. It does ignore immediates and memory addresses (think printf and scanf, though scanf is different) and focuses on locating stack refereces (for 32 bit programs.)

## Future Work
The obvious extension of the callTrace is to implement the argument feature. This is currently being done in the topDown script (which is maybe where it deserves to live anyway) so there's definitely room to expand. 

The topDownArgumentTrace turned into a rather complex script, despite it not really doing much. There are lots of different edge cases and checks that needed to be done, so the next obvious goal would be to expand out the different checks it makes and instructions it looks for.

argumentTrace works fairly well, but there are a couple strange behaviors still. Scanf for instance is written "scanf("%d", &temp)" so one would think it takes an argument. However Ghidra reports that it does not, which is strange to say the least. One challenge that comes to mind that still exists, and was the same type of problem in topDown, is that diving into function calls is tricky. Stack references change, so what was EBP-0x10 in "main" is now EBP+0x8 in "funcOne", though they are the same variable.