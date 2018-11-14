#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* secret2;
char* text;
const char* secret = "THIS IS A SECRET";

/*Not supposed to be read*/
static void readSecret(){
	printf("THE SECRET IS OUT: \"%s\"\n",secret);
}

/*Mismatch between array size of text and strncpy limit (heap)*/
static void enterText(char *te,int n){
	printf("DEBUG: int: %d\n",n);
	strncpy(text,te,n);
}

/*Can overwrite super secure check array (stack)*/
static void enterTest(char *te,char *comp){
	char check[16];
	char test[16];
	printf("POINTERS STACK: test: %p check: %p\n",(void *)&test,(void *)&check);
	printf("POINTERS STACK: diff: %p\n",(void *)((&check)-(&test)));
	strcpy(check,"UNCRACKABLE");
	strcpy(test,te);
	if(!strcmp(comp,check)) readSecret();
}

/*4 Inputs*/
int main(int argc, char **argv){
	text = (char*) malloc(32*sizeof(char));
	secret2 = (char*) malloc(32*sizeof(char));

	printf("POINTERS HEAP: text: %p secret2: %p\n",(void*) text,(void *) secret2);
	printf("POINTERS HEAP: diff: %p\n",(void *)(secret2 - text));

	strcpy(secret2,"THIS IS ANOTHER SECRET");
	enterTest(argv[1],argv[2]);
	enterText(argv[3],atoi(argv[4]));

	printf("read text: %s\n",text);
	printf("DEBUG secret2: %s\n",secret2);
}

