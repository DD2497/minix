#include <stdio.h>
//#include <string.h>
#include <unistd.h>


#define NOP5    asm(".skip 0x1, 0x0f"); \
				asm(".skip 0x1, 0x1f"); \
				asm(".skip 0x1, 0x44"); \
				asm(".skip 0x2, 0x00");



__attribute__((noinline)) void print1(void);

void print1(){
	NOP5
	printf("Patched from menupatch!\n");
}

int main() {
	char in[20];
    while(1){
		scanf("%s", in);
        print1();
    }
	return 0;
}
//Padding in .text segment for patch
asm(".skip 0x4000 , 0x90");

