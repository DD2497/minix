#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
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
#include <minix/mpserver.h>
#include "servers/pm/mproc.h"

#define JMP_SIZE 5
#define SIGN_KEY 0xFA

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int, int);
static int lu_state_restore(void);


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


struct mproc mproc[NR_PROCS];

endpoint_t mpatch_endpoint;
endpoint_t target_endpoint;

static char* read_file(char* file_name, long long bytes) { 
    int fd = open(file_name, O_RDONLY); 
    char *buffer = (char*) malloc(bytes); 
    read(fd, buffer, bytes); 
    close(fd); 
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
    unsigned char msg_arr[4];
    *((unsigned int*)msg_arr) = msg;
    return hash(seed, msg_arr, 4); 
}

/** 
 * Bad but simple decryption. 
 * Use with RSA-key or similar in a real application 
 */
static char sign(char msg, char key) { 
    return msg^key; 
}

static int get_endpoints(char * file_name){
    //Get process name from the file name
    char * process_name = file_name;
    int i = 0;
    while(file_name[i] != '\0'){
        if(file_name[i] == '/'){
            process_name = file_name + i + 1;
        }
        i++;
    }

//get the PM process table
	int r = getsysinfo(PM_PROC_NR, SI_PROC_TAB, mproc, sizeof(mproc));
	if (r != OK) {
		printf("MPATCH: warning: couldn't get copy of PM process table: %d\n", r);
		return 1;
	}
    //Find endpoints of desired processes
	mpatch_endpoint = -1; target_endpoint = -1;
	for (int mslot = 0; mslot < NR_PROCS; mslot++) {
		if (mproc[mslot].mp_flags & IN_USE) {
			if (!strcmp(mproc[mslot].mp_name, "mpatch"))
				mpatch_endpoint = mproc[mslot].mp_endpoint;
			if (!strcmp(mproc[mslot].mp_name, process_name))
				target_endpoint = mproc[mslot].mp_endpoint;
		}
	}
	if(target_endpoint == -1){
		printf("Process %s was not found\n", process_name);
		return -1;
	}
	return OK;
}




//char* proc_name = NULL; 
static int mpatch_open(devminor_t UNUSED(minor), int UNUSED(access),
        endpoint_t UNUSED(user_endpt))
{
    printf("mpatch_open(). Called %d time(s).\n", ++open_counter);
    return OK;
}

static int mpatch_close(devminor_t UNUSED(minor))
{
    printf("mpatch_close\n");
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

static unsigned int parse_int(char ** buff, int * size){
    char * nextWord;
    unsigned int tmp_addr;
    tmp_addr = strtol(*buff, &nextWord, 16);
    if((nextWord - *buff) != *size){
        *size -= nextWord - *buff + 1;
        *buff = nextWord + 1;
    }
    return tmp_addr; 
}

static char * parse_string(char ** buff, int * size){
    int i;
    char * strPos = *buff;
    for(i = 0; i < *size; i++){
        if((*buff)[i] == '\n' || (*buff)[i] == ' ' || (*buff)[i] == '\0'){
            if(i == 0){
                errno = 1;
                printf("No string to parse\n");
                return *buff;
            }
            (*buff)[i] = '\0';
            *buff += i + 1;
            *size -= i + 1;
            break;
        }
    }
    return strPos;
}

static ssize_t mpatch_write(devminor_t UNUSED(minor), u64_t position,
        endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
        cdev_id_t UNUSED(id))
{
    int r;
    char buff[size];
    r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) buff, size);
    if (r != OK) {
        printf("[MPATCH] WARNING: couldn't copy data %d\n", r);
        return OK;
    }

    char * input_ptr = buff;
    int tmp_size = size;

    errno = 0;

    struct patch_info p_info = {
        .origin_file =                  parse_string(&input_ptr, &tmp_size),
        .function_original_address =    parse_int(&input_ptr, &tmp_size),
        .origin_memory_start =          parse_int(&input_ptr, &tmp_size),
        .origin_file_size = 0,
        .patch_file =                   parse_string(&input_ptr, &tmp_size),
        .patch_size =                   parse_int(&input_ptr, &tmp_size),
        .virtual_memory_start =         parse_int(&input_ptr, &tmp_size),
        .virtual_memory_location =      parse_int(&input_ptr, &tmp_size),
        .patch_address = 0 //calculated later
    };

    char signature = parse_string(&input_ptr, &tmp_size)[0]; 

    
    if (errno != 0) {
        printf("[MPATCH] WARNING: Could not parse input file.\n");
        return size;
    }

    if((r = get_endpoints(p_info.origin_file)) != OK){
        return r;
    }

    // Use stat to get the size of the patch file 
    struct stat st;
    stat(p_info.patch_file, &st);
    // Get the patch file binary 
    char *patch_binary = read_file(p_info.patch_file, st.st_size); 
    // Hash the patch file and attributes.   
    char patch_hash = hash('r', patch_binary, st.st_size);  
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

    // Verify 
    if (sign(patch_hash,SIGN_KEY) != signature) {
        printf("[MPATCH] Signature does not match! Patch denied!\n"); 
        return size;
    }

    mpserver_sys1(mpatch_endpoint,target_endpoint,p_info);

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
