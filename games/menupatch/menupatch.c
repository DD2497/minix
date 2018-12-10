#include <stdio.h>
#include <unistd.h>

int print1(void);
int printhex(void);

int print1(void){
	int i;
	for(i = 0; i < 10; i++){	
		printf("%d\n", i);
	}
	return 1;
}

int printhex(void){
	int i;
	int j;
	char tre[1024];
	for(i = 0; i < 1024; i++)
		tre[i] = getchar();

	for(i = 0; i < 64; i++){
		printf("%x   ", i);
		for(j = 0; j < 16; j++)
			printf("%x ", tre[i*16 + j]);
		printf("\n");
	}
	return 0;
}

int main(){
	char str[16];
	printhex();
	while(1){
		scanf("%s",str);
		print1();
		//sleep(5);
	}
	return 0;
}
