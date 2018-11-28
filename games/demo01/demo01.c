#include <stdio.h>
#include <stdlib.h>

// Example functions
int f(void); 
int arg_f(int a); 
int local_var_f(void); 
int local_var_arg_f(int a); 
// Patch 
int patch(void* src, void* patch); 

int f() { 
  asm("nop");
  return 0; 
}
int arg_f(int a) { 
  asm("nop");
  return a; 
}
int local_var_f(){ 
  asm("nop"); 
  int b = 25; 
  return b; 
}

int local_var_arg_f(int a) { 
  asm("nop");
  int b = 26; 
  return a+b; 
}

int patch(void* src, void* patch) { 
  // Calculate diff
  int diff = (int) patch - (int) src; 

  // Short Jmp
  if (diff <= 127 || diff >= -128 ) { 
      *((int *) src) = 0xeb00 | diff; 
  }
  else 
    return 1;
  return 0; 
}


int main(int argc, char *argv[])
{
  void* ptr = &f; 
  printf("Hello World\n");
  printf("f: %p\n", ptr); 
  printf("arg_f: %p\n", &arg_f); 
  printf("value of f before patch: %x\n", *((int*) ptr)); 
  patch(ptr, &arg_f); 
  printf("value of f after jump: %x\n", *((int*) ptr)); 
  return 0;
}
