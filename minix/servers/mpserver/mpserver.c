#include "inc.h"
#include "mpserver.h"

#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include <minix/chardriver.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <minix/timers.h>
//#include <include/arch/i386/include/archtypes.h>
//#include "kernel/proc.h"
#include <minix/sysinfo.h>
#include <minix/mpserver.h>
//#include "servers/pm/mproc.h"

#define JMP_SIZE 5


/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  return(OK);
}

/*===========================================================================*
 *				do_publish				     *
 *===========================================================================*/
endpoint_t target_endpoint;

static int bytesEqual(unsigned char * first, unsigned char * second, int length){
    int i;
    for(i = 0; i < length; i++){
        if(first[i] != second[i])
            return 0;
    }
    return 1;
}

struct jmp_inst { 
    unsigned char opcode; 
    unsigned int  rel_addr; 
}__attribute__((packed));

static int read_from_target(unsigned char * text, int size, int addr){
    cp_grant_id_t grant_id = cpf_grant_magic(MPSERVER_PROC_NR, target_endpoint, (vir_bytes) addr, size, CPF_READ);
    if(grant_id < 0){
        printf("magic grant denied\n");
        return grant_id;
    }
    //printf("grant_id: %d\n",grant_id);
    int ret;
    if((ret = sys_safecopyfrom(MPSERVER_PROC_NR, grant_id, 0, (vir_bytes) text, size)) != OK){
        printf("safecopy failed: %d\n",ret);
        return ret;
    }
    if((ret = cpf_revoke(grant_id)) != OK) 
        printf("Revoke failed");
    return OK;
}

static int write_to_target(unsigned char * text, int size, int addr){
    cp_grant_id_t grant_id = cpf_grant_magic(MPSERVER_PROC_NR, target_endpoint, (vir_bytes) addr, size, CPF_WRITE);
    if(grant_id < 0)
        printf("magic grant denied\n");
    //printf("grant_id: %d\n",grant_id);
    int ret;
    if ((ret = sys_safecopyto(MPSERVER_PROC_NR, grant_id, 0, (vir_bytes) text, size)) != OK){
        printf("safecopy failed: %d\n",ret);
        return ret;
    }
    if((ret = cpf_revoke(grant_id)) != OK){
        printf("REVOKE FAILED");
        return ret;
    }
    return OK;
}

static int get_patch_address(struct patch_info * p_info){
    //Currently the available space shpuld be located above the the function in memory
    int potential_available_space = p_info->function_original_address - p_info->origin_memory_start;
    if(p_info->patch_size > potential_available_space){
        printf("patch is to big, cannot patch\n");
    }
    //Dividing everything into blocks may be redundant for this small amounts of memory
    int nops = 0;
    int block_size = (p_info->patch_size > 256) ? 4*p_info->patch_size : 1024;
    int blocks = potential_available_space / block_size;
    
    //Here we read block_size bytes at a time and see if we find enough space
    unsigned char text[block_size];
    int pos = p_info->function_original_address;
    int i; int j;
    for(i = 0; i < blocks; i++){
        pos = pos - block_size;
        read_from_target(text, block_size, pos);
        for(j = block_size - 1; j >= 0; j--){
            if(text[j] == (unsigned char) 0x90){
                nops++;
            } else {
                nops = 0;
            }
            //if we found enough space
            if(nops >= p_info->patch_size){
                p_info->patch_address = pos + j;
                return OK;
            }
        }
    }
    printf("Couldn't find space for patch\n");
    return -1;
}

static int inject_jump(struct patch_info p_info){
    int ret;
    struct jmp_inst jmp = {
        .opcode = 0xe9,
        .rel_addr = p_info.patch_address - (p_info.function_original_address + 5) // Rel addr is calculated from the instruction following the jmp
    }; 

    unsigned char header[32];
    read_from_target(header, 32, p_info.function_original_address);
    int i;
    unsigned char nop5[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
    for (i = 0; i < 32; i++){
        if(bytesEqual(&header[i], nop5, 5))
            break;
        //The following check should not create bugs since normal programs should not contain e9 jumps that points outsid the function
        if(header[i] == (unsigned char) 0xe9){  //If the function was already patched,
            int prev_jmp_dst = *((int*) (header + i + 1));
            if(prev_jmp_dst > p_info.origin_memory_start - p_info.function_original_address && prev_jmp_dst < 0)
                break;
        }
    }
    if(i == 32){
        printf("The function to be patched did not contain a 5 byte nop in it's header or had to many arguments\n");
        return i;
    }
    	
	write_to_target((char *) &jmp, JMP_SIZE, p_info.function_original_address + i);
	return OK;
}

/*
 * This function can still get false positives which will probably lead to a crash of the program that is patched
 * However the only way to improve this is to fully interpret all instructions in the function we are writing
 * whilch is currently out of scope. For now the chance for false positives should be negligable.
 */
static int realaign_calls(struct patch_info p_info, unsigned char * patch_buffer){
    int origin_binary = open(p_info.origin_file, O_RDONLY);
    if(origin_binary == -1){
        printf("couldn't open origin_binary\n");
        return -1;
    }
    int origin_file_size = lseek(origin_binary, 0, SEEK_END);
    close(origin_binary);

    int min_jmp = p_info.origin_memory_start - p_info.function_original_address;  //Relative position of first adress
    int max_jmp = origin_file_size + min_jmp;    //Relative position of last adress 
    int i;
    for(i = 0; i < p_info.patch_size; i++){
        if(patch_buffer[i] == (unsigned char) 0xe8){
            int prev_jmp = 0;
            prev_jmp = *((int *) (patch_buffer+i+1)); //Read next 4 bytes as int
            if(prev_jmp < min_jmp - i || prev_jmp > max_jmp - i)
                continue; //If prev_jmp is outside of scope this is not a correct jmp and is left alone
            int new_jmp = prev_jmp + (p_info.function_original_address - p_info.patch_address);
            *((int *) (patch_buffer+i+1)) = new_jmp;//Insert the new relative jmp over the old one
            i += 4;
        }
    }
    return OK;
}

static int move_data(struct patch_info p_info, unsigned char * patch_buffer){
    int patch_binary = open(p_info.patch_file, O_RDONLY);
    if(patch_binary == -1){
        printf("couldn't open patch_binary\n");
        return -1;
    }
    int patch_file_size = lseek(patch_binary, 0, SEEK_END);
    
    int i; int j;
    unsigned char movl[] = {0xc7, 0x04, 0x24};
    unsigned int data_address = p_info.patch_address;

    int buffer_size = 256;
    char data_buffer[buffer_size];

    for(i = 0; i < p_info.patch_size-7; i++){   //-7 since movl is 7 bytes
        if(bytesEqual(&patch_buffer[i], movl, 3)){

            unsigned int addr = *((int*) (patch_buffer + i + 3));
            unsigned int file_location = addr - p_info.virtual_memory_start;
            if(addr < p_info.virtual_memory_start || addr > p_info.virtual_memory_start + patch_file_size)
                continue;

            //Read data from file
            lseek(patch_binary, file_location, SEEK_SET);
            read(patch_binary, data_buffer, buffer_size);

            int data_size;

            for(j = 0; j < buffer_size; j++){
                if(data_buffer[j] == (unsigned char) 0x00){
                    data_size = j + 1;
                    break;
                }
            }
            data_buffer[j] = (unsigned char) 0x00;

            //TODO This should be done using the same function that patch uses
            //Check that there is space for the data
            data_address = data_address - data_size;
            unsigned char prog_buffer[data_size];
            read_from_target(prog_buffer, data_size, data_address);
            for(j = 0; j < data_size; j++){
                if(prog_buffer[j] != (unsigned char) 0x90){
                    printf("couldn't find space for patch data. Will try to continue without copying\n");
                    close(patch_binary);
                    return OK;  //There should be no space for any other data either so we don't break
                }
            }           

            //transfer the data to the running process
            write_to_target(data_buffer, data_size, data_address);

            //change the patch_buffer reference to the position of the copied data
            *(unsigned int *) (patch_buffer+i+3) = data_address;
            i += 6; 
        }   
    }
    close(patch_binary);
    return OK;
}

static int inject_patch(struct patch_info p_info){
	unsigned char patch_buffer[p_info.patch_size];
	int ret;

    unsigned int patch_location_in_file = p_info.virtual_memory_location - p_info.virtual_memory_start;
	//get the code from the binary
	int patch_binary = open(p_info.patch_file, O_RDONLY);
    if(patch_binary == -1){
        printf("couldn't open patch_binary\n");
        return -1;
    }
	lseek(patch_binary, patch_location_in_file, SEEK_SET);
	read(patch_binary, patch_buffer, p_info.patch_size);
	close(patch_binary);	

    if((ret = realaign_calls(p_info, patch_buffer)) != OK){
        return ret;
    }
	
    if((ret = move_data(p_info, patch_buffer)) != OK){
        return ret;
    }


    if((ret = write_to_target(patch_buffer, p_info.patch_size, p_info.patch_address)) != OK){
        return ret;
    }

    return OK;
}

static int check_patch(struct patch_info p_info){
	unsigned char text[p_info.patch_size];
	read_from_target(text, p_info.patch_size, p_info.patch_address);
    //read_from_target(text, p_info.patch_size, p_info.function_original_address);
	
    //print patch code
	int i;
	for(i = 0; i < p_info.patch_size; i++)
		printf("%02X ", text[i]);
	printf("\n");
	return OK;
}

static ssize_t mpatch(struct patch_info p_info){
    //printf("MPATCH SERVER is running\n"); //Mpatch seem to crash without this print, no idea why.
    
    int r;
    if((r = get_patch_address(&p_info)) != OK){
        return r;
    }

    if((r = inject_patch(p_info)) != OK) {
		return r;
    }

    if((r = inject_jump(p_info)) != OK){
        return r;
    }

	//if((r = check_patch(p_info)) != OK){
	//	return r;
    //}

    printf("SUCCESS\n");
    return 100;
}

//Get the paths to the binary files from the mpatch driver
static int retreive_path(endpoint_t mpatch_endpoint, void *addr, int size, char *path){
    cp_grant_id_t grant_id = cpf_grant_magic(MPSERVER_PROC_NR, mpatch_endpoint, (vir_bytes) addr, size, CPF_READ);
    if(grant_id < 0)
        printf("magic grant denied\n");
    //printf("grant_id: %d\n",grant_id);
    int ret;
    //path = malloc(size*sizeof(char));
    if ((ret = sys_safecopyfrom(MPSERVER_PROC_NR, grant_id, 0, (vir_bytes) path, size)) != OK){
        printf("safecopy failed: %d\n",ret);
        return ret;
    }
    if((ret = cpf_revoke(grant_id)) != OK){
        printf("REVOKE FAILED");
        return ret;
    }
    return OK;
}

int do_sys1(message *m_ptr)
{
  message m = *m_ptr;
  struct patch_info p_info = m.m_mp_mps_patchinfo.p_info;
  target_endpoint = m.m_mp_mps_patchinfo.target_endpoint;

  //Get the path to binary of the original process and the patch
  char origin_path[m.m_mp_mps_patchinfo.origin_path_length];
  retreive_path(m.m_source, p_info.origin_file, m.m_mp_mps_patchinfo.origin_path_length, origin_path);
  p_info.origin_file = origin_path;
  char patch_path[m.m_mp_mps_patchinfo.patch_path_length];
  retreive_path(m.m_source, p_info.patch_file, m.m_mp_mps_patchinfo.patch_path_length, patch_path);
  p_info.patch_file = patch_path;

  //Start the patching
  mpatch(p_info);
  return (OK);
}

