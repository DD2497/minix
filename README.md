# Project in DD2497 SYSSEC 


## Created by:
* Michael Chlebek
* Kristian Alvarez
* Niklas Reje
* Vidar Palmér

Things to think about:
Adding nop instructions: Best way edit the clang compiler to add it in the beginning of every function
otherwise add enough nop instructions to after the header then swap header and nops.

Check if running old code. Investigate the stack frames, if any contain a return pointer to the old function space
then unpatched code will be run and the user should be informed.
More advanced: Make old function unreadable and when the os calls the exception check whether new or old should be run.

Where to put new code: If we put it on the heap it is vulnerable to heap overflow (BAD!). Either make slice of heap unwritable or declare part of data with nothing and later add patches to those addresses.

We need to be aware if patched code is place independant. Normal byte code is place dependant and have constant jumps rather than calulating the destination of jumps.

Magic grant (CPF_GRANT_MAGIC) to insert jump instruction into running program.

To find process endpoint: Get process table from process manager and search for PID and get endpoint from matching process.

do_safecopy maybe? Example of magic grant in request.c in vfs.

Minix source documentation: http://cinnabar.sosdg.org/~qiyong/qxr/minix3/source
