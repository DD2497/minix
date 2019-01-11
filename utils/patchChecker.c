#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/proc.h>

__attribute__((noinline)) void print1(void);
__attribute__((noinline)) void print2(void);




// Structure to hold the retrieved data
struct functionDescriptor {
    long address;
    int size;
    char fName[100];        // Maybe not needed, remove?
};


int isCurrentlyPatchable(pid_t pid, struct functionDescriptor *fd) {

    int status = ptrace(PT_ATTACHEXEC, pid, NULL, NULL);
    struct proc data = malloc(1000);
    // ptrace(PTRACE_GETREGS, pid, NULL, data); 
    ptrace(PTRACE_GETUSER, pid, NULL, data); 


    // Utilize PTRACE in order to retrieve register so that we can check them
    //


    // Perform check to ensure that instruction pointer and stack pointer are not within bounds of
    // function contained in function descriptor
}



int main() {
    struct functionDescriptor fd;
    getFuncSize("ref.elf", "getFuncSize", &fd );
    printf("Name: %s, pos: %lx, size: %d\n", fd.fName, fd.address, fd.size);
	return 0;
}
