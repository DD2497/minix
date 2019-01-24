#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h> // for errno (believe it or not)
#include <sys/ptrace.h> // for ptrace, also imports reg struct

#define string_size 64

int is_proc_paused; // Keeps track if the process to be patched is paused

struct patch_info {
    char * process_name;
    unsigned int function_original_address;
    unsigned int origin_memory_start;
    
    char * file_name;
    int patch_size;
    unsigned int virtual_memory_start;
    unsigned int virtual_memory_location;
};

int get_input(pid_t * pid, char * file_name, char * patch_file, char * function_name, char * sign);
int get_procces_name(char * file_name, struct patch_info * info);
int get_func_info(char* file, char* funcName, unsigned int * addr, int * size);
int get_patch_start(char * patch_file, unsigned int * memory_start);
int is_patchable(struct patch_info info, pid_t pid, int patch_size );
int stop_ptrace(pid_t pid);
int do_mpatch(struct patch_info info, char signature);




int get_input(pid_t* pid, char * file_name, char * patch_file, char * function_name, char * sign){

    printf("write the PID of the process to be patched\n");
    int process_id; 
    int result = scanf("%u", &process_id);
    if (result == 0) {
        process_id = -1;
            while (fgetc(stdin) != '\n'); // Read until a newline is found
    }
    *pid = process_id;

    printf("write the path of the running binary\n");
    scanf("%s", file_name);
    printf("write the path of the file that contains the patch\n");
    scanf("%s", patch_file);
    printf("write the name of the function that is to be patched\n");
    scanf("%s", function_name);
    printf("write the signature of the patch (in hex)\n");
    scanf("%s",sign);
    return 0;
}

/*int get_procces_name(char * file_name, struct patch_info * info){
    int i;
    info->process_name = file_name;
    for(i = 0; i < string_size-2; i++){
        if(file_name[i] == '\0'){
            return 0;
        }
        if(file_name[i] == '/'){
            info->process_name = file_name + i + 1;
        }
    }
    printf("File name to long, currently limited to names of %d bytes or shorter\n", string_size);
    return 1;
}*/

int get_func_info(char* file, char* funcName, unsigned int * addr, int * size) {
    FILE *fp;
    char readelf[string_size + 20] = "/usr/bin/readelf -s ";
    strcat(readelf, file);

    //Open the command for reading.
    fp = popen(readelf, "r");
    if(fp == NULL){
        printf("Failed to read %s. Make sure that it is an ELF file\n", file);
        return 1;
    }

    char line[1024];
    
    long address;
    int tmp_size;
    char symbolName[128];
    char symbolType[64];

    //Read the output from readelf line for line
    while(fgets(line, sizeof(line), fp) != NULL){
        //Aquire the relevant parts from the readelf line
        sscanf(line ,"%*d: %lx %d %s %*s %*s %*s %s", &address, &tmp_size, symbolType, symbolName);
        if (strcmp(symbolType, "FUNC") == 0) {
            if (strcmp(symbolName, funcName) == 0) {
                *addr = address;
                *size = tmp_size;
                pclose(fp);
                return 0;
            }
        }
    }
    pclose(fp);
    printf("A function named %s was not found in %s\n", funcName, file);
    return 1;
}

int get_patch_start(char * patch_file, unsigned int * memory_start){
    unsigned char architechture;
    unsigned int e_phob;
    FILE *fp;
    fp = fopen(patch_file, "r");
    fseek(fp, 4, SEEK_SET);
    fread(&architechture, 1, 1, fp);
    if(architechture != (unsigned char) 1){
        printf("currently only supports 32-bit architechture, please apply a patch from a 32-bit ELF file\n");
        return 1;
    }

    fseek(fp, 0x1c, SEEK_SET);
    fread(&e_phob, 4, 1, fp);

    fseek(fp, e_phob + 0x08, SEEK_SET);
    fread(memory_start, 4, 1, fp);
    fclose(fp);
    return 0;
}

int is_patchable(struct patch_info info, pid_t pid, int patch_size) {
  // malloc(sizeof(struct reg));
   struct reg registers;
   // Begin tracing the process
   int status;
   status = ptrace(PT_ATTACH, pid, NULL, 0);
   if (errno == ESRCH) {
        printf("No process with pid:%u found - EXITING!\n", pid);
        return 0;
   }
    printf("Status:%d, errno:%d \n", status, errno);
   is_proc_paused = 1;
   // The third argument tells ptrace where to save the registers
   status = ptrace(T_GETUSER, pid, &registers, 0);
   //registers = (struct reg) data;
   unsigned int r_eip = registers.r_eip;
   unsigned int r_ebp = registers.r_ebp;
    printf("Status:%d, errno:%d \n", status, errno);

    printf("Instruction pointer:%u, func_addr: %u, size of func: %d\n", r_eip, info.function_original_address, patch_size);
   
   // Check that instruction pointer is not currently within function
    if ( !(r_eip < info.function_original_address  || r_eip > (info.function_original_address + patch_size) ) ) {   
        printf("Function in use, unsafe to apply patch - EXITING!\n");
        return 0;
    }
    unsigned int ret_addr = 0;
    // Apparently, PT_READ_D returns the data from the method
    ret_addr = ptrace(PT_READ_D, pid,(void*) (r_ebp + 4), ret_addr);
    // Check that return addr from current function is not in the function we want to patch
    if ( !(ret_addr < info.function_original_address || ret_addr > ( info.function_original_address + patch_size))) {   
    printf("Function in use, unsafe to apply patch - EXITING!\n");
        return 0;
    }
    printf("Function not in use, safe to apply patch!\n");
    return 1;
}

int stop_ptrace(pid_t pid) {
    int status = ptrace(PT_DETACH, pid, NULL, 0);
    is_proc_paused = 0;
    return status;
}

int do_mpatch(struct patch_info info, char signature){
    char str[PATH_MAX * 2 + 16];
    sprintf(str, "%s %x %x %s %x %x %x %c\n", info.process_name, info.function_original_address, info.origin_memory_start, 
        info.file_name, info.patch_size, info.virtual_memory_start, info.virtual_memory_location, signature);
    FILE * fp;
    fp = fopen("/dev/mpatch", "w");
    fprintf(fp, "%s", str);
    fclose(fp);
    return 0;
}

int main(){
    char origin_file[string_size];
    char patch_file[string_size];
    char function_name[string_size];

    char origin_path[PATH_MAX];
    char patch_path[PATH_MAX];
    char sign[2]; 

    struct patch_info info;
    pid_t pid;

    get_input(&pid, origin_file, patch_file, function_name, sign);

    if(realpath(origin_file, origin_path) == NULL){
        printf("Couldn't find the file which contains the patch\n");
        return 1;
    }
    info.process_name = origin_path;

    if(realpath(patch_file, patch_path) == NULL){
        printf("Couldn't find the file which contains the patch\n");
        return 1;
    }
    info.file_name = patch_path;

    int obsolete;
    if(get_func_info(origin_file, function_name, &info.function_original_address, &obsolete) != 0){
        printf("Error when reading file of running process, exiting\n");
        return 1;
    }

    if(get_patch_start(origin_file, &info.origin_memory_start) != 0){
        printf("Error in original file, exiting\n");
    }

    if(get_patch_start(patch_file, &(info.virtual_memory_start)) != 0){
        printf("Error in patch file, exiting\n");
        return 1;
    }
    
    if(get_func_info(patch_file, function_name, &info.virtual_memory_location, &info.patch_size) != 0){
        printf("Error when reading file containing the patch, exiting\n");
        return 1;
    }
    unsigned int temp;
    int function_size;
    get_func_info(origin_file, function_name, &temp , &function_size);
    // Pause process and ensure that it is not currently in the function
    if (is_patchable(info, pid, function_size)) {
        // Process safe to patch - proceed
    // Convert sign to single char
    char signature = (char) strtol(sign, NULL, 16); 
        do_mpatch(info, signature);
    }
    // Resume process if paused 
    if (is_proc_paused) {
        stop_ptrace(pid);       
    }


	return 0;
}
