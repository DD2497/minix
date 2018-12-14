#include <stdio.h>
#include <unistd.h>

#define NOP5	asm(".skip 0x1, 0x0f"); \
				asm(".skip 0x1, 0x1f"); \
				asm(".skip 0x1, 0x44"); \
				asm(".skip 0x2, 0x00");


__attribute__((noinline)) void print1(void);
__attribute__((noinline)) void print2(void);
void dummy_fun(void);

void print1(){
	NOP5
	printf("UNPATCHED!!!!!\n");
}

void print2(){
	NOP5
	printf("UNPATCHED!!!!!!\n");
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

