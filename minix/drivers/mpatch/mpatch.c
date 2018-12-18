#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include <minix/chardriver.h>
#include "mpatch.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <minix/timers.h>
#include <include/arch/i386/include/archtypes.h>
#include "kernel/proc.h"
#include <minix/sysinfo.h>
#include <minix/myserver.h>
#include "servers/pm/mproc.h"

#define JMP_SIZE 5

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int, int);
static int lu_state_restore(void);


/* MPATCH */
//static ssize_t mpatch();

/** State variable to count the number of times the device has been opened.
 * Note that this is not the regular type of open counter: it never decreases.
 */
static int open_counter;
extern int errno; 

static int sef_cb_lu_state_save(int UNUSED(state), int UNUSED(flags)) {
    return OK;
}

static int lu_state_restore() {
    return OK;
}

static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
    /* Initialize the hello driver. */
    int do_announce_driver = TRUE;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("%s", MPATCH_MSG);
            break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n", MPATCH_MSG);
            break;

        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", MPATCH_MSG);
            break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        chardriver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

static void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}


/*
 * Function prototypes for the hello driver.
 */
static int mpatch_open(devminor_t minor, int access, endpoint_t user_endpt);
static int mpatch_close(devminor_t minor);
static ssize_t mpatch_read(devminor_t minor, u64_t position, endpoint_t endpt,
        cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
static ssize_t mpatch_write(devminor_t minor, u64_t position, endpoint_t endpt,
        cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);

/* Entry points to the hello driver. */
static struct chardriver mpatch_tab =
{
    .cdr_open	= mpatch_open,
    .cdr_close	= mpatch_close,
    .cdr_read	= mpatch_read,
    .cdr_write	= mpatch_write,
};

struct patch_info {
    char * process_name;
    unsigned int function_original_address;
    
    char * file_name;
    int patch_size;
    unsigned int virtual_memory_start;
    unsigned int virtual_memory_location;

    unsigned int patch_address;
};

struct mproc mproc[NR_PROCS];

endpoint_t mpatch_endpoint;
endpoint_t target_endpoint;

static int bytesEqual(unsigned char * first, unsigned char * second, int length){
    int i;
    for(i = 0; i < length; i++){
        if(first[i] != second[i])
            return 0;
    }
    return 1;
}

static int get_endpoints(char *target_name){
	int r = getsysinfo(PM_PROC_NR, SI_PROC_TAB, mproc, sizeof(mproc));
	if (r != OK) {
		printf("MPATCH: warning: couldn't get copy of PM process table: %d\n", r);
		return 1;
	}

	mpatch_endpoint = -1; target_endpoint = -1;
	for (int mslot = 0; mslot < NR_PROCS; mslot++) {
		if (mproc[mslot].mp_flags & IN_USE) {
			if (!strcmp(mproc[mslot].mp_name, "mpatch"))
				mpatch_endpoint = mproc[mslot].mp_endpoint;
			if (!strcmp(mproc[mslot].mp_name, target_name))
				target_endpoint = mproc[mslot].mp_endpoint;
		}
	}
	if(target_endpoint == -1){
		printf("Process %s was not found\n", target_name);
		return -1;
	}
	return OK;
}

struct jmp_inst { 
    unsigned char opcode; 
    unsigned int  rel_addr; 
}__attribute__((packed));

static int read_from_target(unsigned char * text, int size, int addr){
     cp_grant_id_t grant_id = cpf_grant_magic(mpatch_endpoint, target_endpoint, (vir_bytes) addr, size, CPF_READ);
    if(grant_id < 0){
        printf("magic grant denied\n");
        return grant_id;
    }
    int ret;
    if((ret = sys_safecopyfrom(mpatch_endpoint, grant_id, 0, (vir_bytes) text, size)) != OK){
        printf("safecopy failed: %d\n",ret);
        return ret;
    }
    if((ret = cpf_revoke(grant_id)) != OK) 
        printf("Revoke failed");
    return OK;
}

static int write_to_target(unsigned char * text, int size, int addr){
    cp_grant_id_t grant_id = cpf_grant_magic(mpatch_endpoint, target_endpoint, (vir_bytes) addr, size, CPF_WRITE);
    if(grant_id < 0)
        printf("magic grant denied\n");
    int ret;
    if ((ret = sys_safecopyto(mpatch_endpoint, grant_id, 0, (vir_bytes) text, size)) != OK){
        printf("safecopy failed: %d\n",ret);
        return ret;
    }
    if((ret = cpf_revoke(grant_id)) != OK){
        printf("REVOKE FAILED");
        return ret;
    }
    return OK;
}

//We should find the amount of free space dynamicly, for now it is hardcoded to 16 000 bytes
#define FREE_SPACE 16000

static int get_patch_address(struct patch_info p_info){
    if(p_info.patch_size > FREE_SPACE){
        printf("patch is to big, cannot patch\n");
    }
    //Dividing everything into blocks may be redundant for this small amounts of memory
    int nops = 0;
    int block_size = (p_info.patch_size > 250) ? 4*p_info.patch_size : 1000;
    int blocks = FREE_SPACE / block_size;
    
    unsigned char text[block_size];
    int pos = p_info.function_original_address;
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
            //we found enough space
            if(nops >= p_info.patch_size){
                return pos + j;
            }
        }
    }
    printf("Couldn't find space for patch\n");
    return -1;
}

static int inject_jump(struct patch_info p_info){//Only add the address not any jump instructions.
    int ret;
    struct jmp_inst jmp = {
        .opcode = 0xe9,
        .rel_addr = p_info.patch_address - (p_info.function_original_address + 5) // Rel addr is calculated from the instruction following the jmp
    }; 
    printf("Opcode: 0x%x, Payload: %p\n", jmp.opcode, (void*) jmp.rel_addr);
    printf("Opcode addr: %p, Payload addr: %p \n", &jmp.opcode, &jmp.rel_addr);

    unsigned char header[32];
    read_from_target(header, 32, p_info.function_original_address);
    int i;
    unsigned char nop5[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
    for (i = 0; i < 32; i++){
        if(bytesEqual(&header[i], nop5, 5))
            break;
    }
    if(i == 32){
        printf("The function to be patched did not contain a 5 byte nop in it's header or had to many arguments\n");
        return OK;
    }
    	
	write_to_target((char *) &jmp, JMP_SIZE, p_info.function_original_address + i);
	return OK;
}

/*static char * read_any_size_data(struct patch_info p_info, unsigned int addr, unsigned int file_location){
    int j;
    int patch_binary = open(p_info.file_name, O_RDONLY);
    int done = 0;
    int size = 64;
    char * final_buffer;
    while(size < FREE_SPACE){
        size = size * 2;
        lseek(patch_binary, file_location, SEEK_SET);
        char data_buffer[size];
        read(patch_binary, data_buffer, size);
        for(j = 0; j < size; j++){
            if(data_buffer[j] = (unsigned char) 0x00){
                final_buffer = malloc(j);
                strcpy(data_buffer, final_buffer, j);
                return final_buffer
            }
        }
    }
    printf("Tried to copy data section that was to big\n");
    return NULL
}*/

static int move_data(struct patch_info p_info, unsigned char * patch_buffer){
    int i; int j;
    int movl = 0;
    unsigned int data_address = p_info.patch_address;
    for(i = 0; i < p_info.patch_size-7; i++){   //-7 since movl is 7 bytes
        if(patch_buffer[i] == (unsigned char) 0xc7 && patch_buffer[i+1] ==  
                (unsigned char) 0x04 && patch_buffer[i+2] == (unsigned char) 0x24){

            unsigned int addr = *((int*) (patch_buffer + i + 3));
            unsigned int file_location = addr - p_info.virtual_memory_start;

            printf("data file location: %x\n", file_location);

            //Read data from file
            //char * data_buffer = read_any_size_data(p_info, addr, file_location);
            /*=====================================*/   //This section could be replaced by read_any_size_data()
            int patch_binary = open(p_info.file_name, O_RDONLY);
            lseek(patch_binary, file_location, SEEK_SET);
            int max_size = 128;
            char data_buffer[max_size];
            read(patch_binary, data_buffer, max_size);
            for(j = 0; j < max_size; j++){
                if(data_buffer[j] == (unsigned char) 0x00){
                    max_size = j + 1;
                    break;
                }
            }
            if(j == max_size)
                data_buffer[j] = (char) 0x00;
            /* ==================================== */

            //Check that there is space for the data
            data_address = data_address - max_size;
            printf("data address: %x\n", data_address);
            unsigned char prog_buffer[max_size];
            read_from_target(prog_buffer, max_size, data_address);
            for(j = 0; j < max_size; j++){
                if(!(prog_buffer[j] == (unsigned char) 0x90)){
                    //free(data_buffer);
                    printf("couldn't find space for patch data continues without copying\n");
                    return OK;
                }
            }

            //writed the data
            write_to_target(data_buffer, max_size, data_address);

            //change the pointer to the copied data
            *(unsigned int *) (patch_buffer+i+3) = data_address;
            i += 6; 
            //free(data_buffer);
        }   
    }   
    return OK;
}

static int inject_patch(struct patch_info p_info){
	unsigned char patch_buffer[p_info.patch_size];
	int ret;

    unsigned int patch_location_in_file = p_info.virtual_memory_location - p_info.virtual_memory_start;
	//get the code from the binary
	int patch_binary = open(p_info.file_name, O_RDONLY);
	lseek(patch_binary, patch_location_in_file, SEEK_SET);
	read(patch_binary, patch_buffer, p_info.patch_size);
	close(patch_binary);	

	//fix addresses of calls
	int i; int j;
	for(i = 0; i < p_info.patch_size; i++){
		if(patch_buffer[i] == (unsigned char) 0xe8){
			int prev_jmp = 0;
			prev_jmp = *((int *) (patch_buffer+i+1)); //Read next 4 bytes as int
			printf("previous relative jump was to %x\n", prev_jmp);
			int new_jmp = prev_jmp + (p_info.function_original_address - p_info.patch_address);
			printf("new relative jump was to %x\n", new_jmp);
			*((int *) (patch_buffer+i+1)) = new_jmp;//Insert the new relative jmp over the old one
			i += 4;
		}
	}

    //TODO move_data should belong to a get_patch function that should be called before get_patch_adress
    move_data(p_info, patch_buffer);    

	write_to_target(patch_buffer, p_info.patch_size, p_info.patch_address);

	return OK;
}

static int check_patch(struct patch_info p_info){
	unsigned char text[p_info.patch_size];
	read_from_target(text, p_info.patch_size, p_info.patch_address);
	
    //print patch code
	int i;
	for(i = 0; i < p_info.patch_size; i++)
		printf("%02X ", text[i]);
	printf("\n");
	return OK;
}

//patch_orig_addr = 0x0804c2e0;
static ssize_t mpatch(struct patch_info p_info){
    endpoint_t mpatch_endpoint;
    endpoint_t target_endpoint;
    int r;
    if((r = get_endpoints(p_info.process_name)) != OK){
        return r;
    }

    if((p_info.patch_address = get_patch_address(p_info)) == -1){
        return -1;
    }
    
    printf("patch adress: %x\n", p_info.patch_address);
    //printf("Endpoint mpatch: %d, Endpoint target: %d\n",(int) mpatch_endpoint,(int) target_endpoint);

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

//char* proc_name = NULL; 
static int mpatch_open(devminor_t UNUSED(minor), int UNUSED(access),
        endpoint_t UNUSED(user_endpt))
{
    printf("mpatch_open(). Called %d time(s).\n", ++open_counter);
    //proc_name = (char*) malloc(0); 
    return OK;
}

static int mpatch_close(devminor_t UNUSED(minor))
{
    printf("mpatch_close\n");
    //free(proc_name); 
    return OK;
}

static ssize_t mpatch_read(devminor_t UNUSED(minor), u64_t position,
        endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
        cdev_id_t UNUSED(id))
{
    u64_t dev_size;
    char *ptr;
    int ret;
    char *buf = MPATCH_MSG;
    printf("mpatch_read()\n");

    /* This is the total size of our device. */
    dev_size = (u64_t) strlen(buf);

    /* Check for EOF, and possibly limit the read size. */
    if (position >= dev_size) return 0;		/* EOF */
    if (position + size > dev_size)
        size = (size_t)(dev_size - position);	/* limit size */

    /* Copy the requested part to the caller. */
    ptr = buf + (size_t)position;
    if ((ret = sys_safecopyto(endpt, grant, 0, (vir_bytes) ptr, size)) != OK)
        return ret;

    /* Return the number of bytes read. */
    return size;
}

static int parse(char* buff, int size, char* name_buff, unsigned int* patch_addr) { 
    int r = 0; 
    int i = 0; 
    // Parse name_buff
    for(; i < size; i++) { 
        //printf("%d %c\n", i, buff[i]);
        if (buff[i] == '\n' || buff[i] == ' ' || buff[i] == '\0') { 
            //printf("Will break after iter\n");
            if (i > 0) { 
                name_buff[i] = '\0';
                r++;
            }
            else { 
                return r; 
            }
            break;
        }
        name_buff[i] = buff[i]; 
    }

    for (i++; i < size && (buff[i] == ' ' || buff[i] == '\n' || buff[i] == '\0'); i++);

    if (i == size) { 
        return r; 
    }

    // Parse patch addr
    char* end; 
    unsigned int tmp_addr; 
    errno = 0; 
    tmp_addr = strtol(buff+i, &end, 16); 
    printf("Tmp addr: %x\n", tmp_addr); 
    if(errno || buff+i == end) { 
        printf("[MPATCH] ERROR PARSING ADDR"); 
        return r; 
    }
    *patch_addr = tmp_addr; 
    return ++r; 
}

static ssize_t mpatch_write(devminor_t UNUSED(minor), u64_t position,
        endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
        cdev_id_t UNUSED(id))
{
    int r;
    printf("mpatch_write(position=%llu, size=%zu)\n", position, size);
    char buff[size]; 
    r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) buff, size);
    if (r != OK) {
        printf("[MPATCH] WARNING: couldn't copy data %d\n", r);
        return OK;
    } 

    char name_buff[128];
    //unsigned int* patch_addr = (unsigned int*) malloc(sizeof(unsigned int)); 
	unsigned int original_addr;

    //printf("Patch_addr addr: %p\n", &patch_addr); 
    if (parse(buff, size, name_buff, &original_addr) != 2) { 
        printf("[MPATCH] WARNING: Could not parse input file."); 
        return OK; 
    }
    printf("Patch_addr value: %x\n", original_addr); 
    //free(proc_name); 
    //proc_name = (char*) malloc(strlen(name_buff));
    //strcpy(proc_name, name_buff);  
    //printf("received=%s menu?: %d\n",name_buff,!strcmp(name_buff,"menu"));
    //printf("patch_loc empty? %d\n", &patch_addr == '\0');

	struct patch_info p_info = {
		.process_name = name_buff, //"menu",
		.function_original_address = original_addr, //0x0804c2e0,
        .file_name = "/usr/games/menupatch",
		.patch_size = 32,
        .virtual_memory_start = 0x8048000,
        .virtual_memory_location = 0x0804c2e0,
		.patch_address = 0 //calculated later
	};

    mpatch(p_info);
    //free(patch_addr); 
    return size;
}

int main(void){
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    chardriver_task(&mpatch_tab);
    return OK;
}
