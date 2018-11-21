#include <stdio.h>
#include <string.h>

int fibon(void);
int printConst(void);

int fibon(){
	printf("Called fib\n");
	return 0;
}

int printConst(){
	printf("A constant string\n");
	return 0;
}

int main(){
	char input[100];
	while(1){
		printf("write input\n");
		scanf("%s", input);
		if(!strncmp(input, "const", 5)){
			printConst();
		}
		if(!strncmp(input, "fib", 3)){
			fibon();
		}
		if(!strncmp(input, "quit", 4)){
			break;
		}
	}
}
