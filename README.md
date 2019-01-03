# Project in DD2497 SYSSEC 


## Created by:
* Michael Chlebek
* Kristian Alvarez
* Niklas Reje
* Vidar Palmér

How to run mpatch after booting minix:

1 run the program that you wish to patch. (If the program is not running it cannot be patched)

2 run do_mpatch. It is located in /usr/games

3 do_mpatch will prompt the user for the neccessary information. The path names can either be relative or absolute.

4 if the terminal prints SUCCESS running program should now be patched.

Below is an example of how to run mpatch on a testprogram called menu.
Ex in booted quemu image.

(user) alt + ->					(switch workspace to start seperate process)

(user) /usr/games/menu			(start the menu program for testing)

(user) print 					(tell menu to execute it's print function)

(minix) UNPATCHED!!!!!

(user) alt + <-					(switch workspace to start mpatch)

(user) cd /usr/games

(user) ./do_mpatch

(minix) write the path of the running binary

(user) menu

(minix) write the path of the file that contains the patch

(user) menupatch

(minix) write the name of the function that is to be patched

(user) print1

(minix) MPATCH is running
(minix) SUCCESS

(user) alt + ->

(user) print

(minix) patched from menupatch



Things to think about:

Check if running old code. Investigate the stack frames, if any contain a return pointer to the old function space
then unpatched code will be run and the user should be informed.
More advanced: Make old function unreadable and when the os calls the exception check whether new or old should be run.

We need to be aware if patched code is position independant. Normal byte code is place dependant and have constant jumps rather than calulating the destination of jumps.

Currently the code is position dependant
