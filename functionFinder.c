#include <stdio.h>
#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void print1(void);
__attribute__((noinline)) void print2(void);




// Structure to hold the retrieved data
struct functionDescriptor {
    long address;
    int size;
    char fName[100];        // Maybe not needed, remove?
};

int getFuncSize(char* file, char* funcName, struct functionDescriptor *fd) {

    FILE *fp;
    // Might have to change the path to where readelf resides in minix
    // (AKA 'works on my computer'
    char path[1035] = "/usr/bin/readelf -s ";
        strcat(path, file);

      /* Open the command for reading. */
    
    fp = popen(path , "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }
    long address;
    int size;
    char symbolName[100] ;
    char symbolType[50] ;

          /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        // Pull out the relevant parts from the output
        sscanf (path ,"%*d: %lx %d %s %*s %*s %*s %s", &address, &size ,symbolType, symbolName);
                //printf("pos: %ld, size: %d, name: %s, type: %s\n", address, size, symbolName, symbolType);
        if (strcmp(symbolType,"FUNC") == 0) {
            if (strcmp(symbolName,funcName) == 0) {
                fd->address = address;
                fd->size = size;
                strcpy(fd->fName, symbolName);
                pclose(fp);
                return 0;
            }
        }
    }

            /* close */
    pclose(fp);
    return 1;


}


int main() {
    struct functionDescriptor fd;
    getFuncSize("ref.elf", "getFuncSize", &fd );
    printf("Name: %s, pos: %lx, size: %d\n", fd.fName, fd.address, fd.size);
	return 0;
}
