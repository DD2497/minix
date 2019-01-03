#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define string_size 64

struct patch_info {
    char * process_name;
    unsigned int function_original_address;
    unsigned int origin_memory_start;
    
    char * file_name;
    int patch_size;
    unsigned int virtual_memory_start;
    unsigned int virtual_memory_location;
};

int get_input(char * file_name, char * patch_file, char * function_name);
int get_procces_name(char * file_name, struct patch_info * info);
int get_func_info(char* file, char* funcName, unsigned int * addr, int * size);
int get_patch_start(char * patch_file, unsigned int * memory_start);
int do_mpatch(struct patch_info info);




int get_input(char * file_name, char * patch_file, char * function_name){
    printf("write the path of the running binary\n");
    scanf("%s", file_name);
    printf("write the path of the file that contains the patch\n");
    scanf("%s", patch_file);
    printf("write the name of the function that is to be patched\n");
    scanf("%s", function_name);
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

int do_mpatch(struct patch_info info){
    char str[PATH_MAX * 2 + 16];
    sprintf(str, "%s %x %x %s %x %x %x\n", info.process_name, info.function_original_address, info.origin_memory_start, 
        info.file_name, info.patch_size, info.virtual_memory_start, info.virtual_memory_location);
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

    struct patch_info info;

    get_input(origin_file, patch_file, function_name);

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

    do_mpatch(info);
	return 0;
}
