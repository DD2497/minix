#include <stdio.h>
#include <string.h>

int fibon(void);
int printConst(void);
long fib(long);

int fibon(){
	long target;
	printf("Called fib please write a number as input\n");
	scanf("%ld", &target);
	printf("the %ldth fibonacci number is: %lld\n", target, fib(target));
	return 0;
}

long fib(long n){
	if(n == 0)
		return 1;
	if(n == 1)
		return 1;
	if(n == 2)
		return 2;
	return fib(n-1) + fib(n-2);
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
