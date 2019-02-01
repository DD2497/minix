#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <minix/type.h>

#define string_size 64

int get_input(char * file_name, char * patch_file, char * function_name, char * sign);
int get_procces_name(char * file_name, struct patch_info * info);
int get_func_info(char* file, char* funcName, unsigned int * addr, int * size);
int get_patch_start(char * patch_file, unsigned int * memory_start);
int do_mpatch(struct patch_info info, char signature);

int get_input(char * file_name, char * patch_file, char * function_name, char * sign){
    printf("write the path of the running binary\n");
    scanf("%63s", file_name);
    printf("write the path of the file that contains the patch\n");
    scanf("%63s", patch_file);
    printf("write the name of the function that is to be patched\n");
    scanf("%63s", function_name);
    printf("write the signing key in hex\n");
    scanf("%2s",sign);
    file_name[63] = '\0';
    patch_file[63] = '\0';
    function_name[63] = '\0';
    sign[2] = '\0';
    return 0;
}

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

int do_mpatch(struct patch_info info, char signature){
    char str[PATH_MAX * 2 + 16];
    sprintf(str, "%s %x %x %s %x %x %x %c\n", info.origin_file, info.function_original_address, info.origin_memory_start, 
        info.patch_file, info.patch_size, info.virtual_memory_start, info.virtual_memory_location, signature);
    FILE * fp;
    fp = fopen("/dev/mpatch", "w");
    fprintf(fp, "%s", str);
    fclose(fp);
    return 0;
}

static char* read_file(char* file_name, long *patch_size) { 
    FILE *fp;
    fp = fopen(file_name, "r");
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = (char*) malloc(size);

    fread(buffer, sizeof(char), size, fp);

    fclose(fp);

    *patch_size = size;

    return buffer; 
}

/** 
 * Bad but simple hash function.  
 * Replace with Sha2 or similar in real application. 
 */
static char hash(char seed, char* msg, long long size) { 
    char h = seed; 
    for (int i = 0; i<size; i++) { 
        int tmp = msg[i]; 
        tmp += h; 
        tmp = tmp % 0x100;
        h = tmp; 
    }
    return h; 
}

static char int_hash(char seed, unsigned int msg) { 
    char msg_arr[4];
    msg_arr[0] = (unsigned char) (msg & 0xFF);
    msg_arr[1] = (unsigned char) ((msg & 0xFF00) >> 8);
    msg_arr[2] = (unsigned char) ((msg & 0xFF0000) >> 16);
    msg_arr[3] = (unsigned char) ((msg & 0xFF000000) >> 24);
    return hash(seed, msg_arr, 4); 
}

/** 
 * Bad but simple decryption. 
 * Use with RSA-key or similar in a real application 
 */
static char sign(char msg,char key) { 
    return msg^key; 
}

static char create_signature(char key, struct patch_info p_info){
    // Patch file size used for hashing.
    long patch_size = 0;
    // Get the patch file binary.
    char *patch_binary = read_file(p_info.patch_file,&patch_size); 
    // Hash the patch file and attributes.   
    char patch_hash = hash('r', patch_binary, patch_size);  
    patch_hash = hash(patch_hash, p_info.origin_file, strlen(p_info.origin_file));  
    patch_hash = int_hash(patch_hash, p_info.function_original_address); 
    patch_hash = int_hash(patch_hash, p_info.origin_memory_start); 
    patch_hash = int_hash(patch_hash, p_info.origin_file_size); 
    patch_hash = hash(patch_hash, p_info.patch_file, strlen(p_info.patch_file));  
    patch_hash = int_hash(patch_hash, p_info.patch_size); 
    patch_hash = int_hash(patch_hash, p_info.virtual_memory_start); 
    patch_hash = int_hash(patch_hash, p_info.virtual_memory_location); 

    // Free used resources
    free(patch_binary);

    return sign(patch_hash,key);
}

int main(){
    char origin_file[string_size];
    char patch_file[string_size];
    char function_name[string_size];

    char origin_path[PATH_MAX];
    char patch_path[PATH_MAX];
    char key_s[3]; 

    struct patch_info info;

    get_input(origin_file, patch_file, function_name, key_s);

    if(realpath(origin_file, origin_path) == NULL){
        printf("Couldn't find the file which contains the patch\n");
        return 1;
    }
    info.origin_file = origin_path;

    if(realpath(patch_file, patch_path) == NULL){
        printf("Couldn't find the file which contains the patch\n");
        return 1;
    }
    info.patch_file = patch_path;

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

    // Convert sign to single char
    char key = (char) strtol(key_s, NULL, 16);

    char signature = create_signature(key,info);

    do_mpatch(info, signature);
	return 0;
}
