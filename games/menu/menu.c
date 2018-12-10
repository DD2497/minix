#include <stdio.h>
//#include <string.h>
#include <unistd.h>

__attribute__((noinline)) void print1(void);
__attribute__((noinline)) void print2(void);
void dummy_fun(void);

void print1(){
    asm("nop"); 
    asm("nop"); 
    asm("nop"); 
    asm("nop"); 
    asm("nop");
	printf("UNPATCHED!!!!!\n");
}

void print2(){
    asm("nop"); 
    asm("nop"); 
    asm("nop"); 
    asm("nop"); 
    asm("nop");
	printf("PATCHED!!!!!!\n");
}

int main() {
	printf("UNPATCHED!!!!!\n");
	printf("PATCHED!!!!!!\n");
	char in[20];
    while(1){
		scanf("%s", in);
        //sleep(3);
        print1();
        //fflush(stdout);
    }
	return 0;
}
//Padding in .text segment for patch
asm(".skip 0x4000 , 0x90");

