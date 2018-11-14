#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* text;
char* secret = "THIS IS A SECRET";
char* secret2;

/*Not supposed to be read*/
void readSecret(){
	printf("THE SECRET IS OUT: \"%s\"\n",secret);
}

/*Mismatch between array size of text and strncpy limit (heap)*/
void enterText(char *te){
	strncpy(text,te,32);
}

/*Can overwrite super secure check array (stack)*/
void enterTest(char *te,char *comp){
	char test[16];
	char check[16];
	strcpy(check,"UNCRACKABLE");
	strcpy(test,te);
	if(!strcmp(comp,check)) readSecret();
}

int main(int argc, char **argv){
	text = (char*) malloc(16*sizeof(char));
	secret2 = (char*) malloc(32*sizeof(char));

	strcpy(secret2,"THIS IS ANOTHER SECRET");
	enterTest(argv[1],argv[2]);
	enterText(argv[3]);

	printf("%s\n",text);
	/*printf("DEBUG: %s\n",secret2);*/
}

