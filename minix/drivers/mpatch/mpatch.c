#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include <minix/chardriver.h>
#include "mpatch.h"

#include <fcntl.h>
#include <unistd.h>

#include <minix/timers.h>
#include <include/arch/i386/include/archtypes.h>
#include "kernel/proc.h"
#include <minix/sysinfo.h>
#include <minix/myserver.h>
#include "servers/pm/mproc.h"

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
    printf("%s", HELLO_MESSAGE);
    break;
 
  case SEF_INIT_LU:
    /* Restore the state. */
    lu_state_restore();
    do_announce_driver = FALSE;
 
    printf("%sHey, I'm a new version!\n", HELLO_MESSAGE);
    break;
 
  case SEF_INIT_RESTART:
    printf("%sHey, I've just been restarted!\n", HELLO_MESSAGE);
    break;
  }

  /* Announce we are up when necessary. */
  if (do_announce_driver) {
    chardriver_announce();
  }

  //mpatch();
 
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


/*static int vm_debug(endpoint_t ep)
{
  message m;
  int result;

  memset(&m, 0, sizeof(m));

  m.VMPCTL_WHO = ep;
  result = _taskcall(VM_PROC_NR, VM_PT_DEBUG, &m);

  return(result);
}*/

struct mproc mproc[NR_PROCS];

static int get_endpoints(endpoint_t *mp, endpoint_t *op, char *other){
	int r = getsysinfo(PM_PROC_NR, SI_PROC_TAB, mproc, sizeof(mproc));
	if (r != OK) {
		printf("MPATCH: warning: couldn't get copy of PM process table: %d\n", r);
		return 1;
	}

	*mp = -1; *op = -1;
	for (int mslot = 0; mslot < NR_PROCS; mslot++) {
		if (mproc[mslot].mp_flags & IN_USE) {
			if (!strcmp(mproc[mslot].mp_name, "mpatch"))
				*mp = mproc[mslot].mp_endpoint;
			if (!strcmp(mproc[mslot].mp_name, other))
				*op = mproc[mslot].mp_endpoint;
		}
	}
	if(*op == -1){
		printf("Process %s was not found\n",other);
		return -1;
	}
	return OK;
}

struct jmp_inst { 
    unsigned char opcode; 
    unsigned int  rel_addr; 
}__attribute__((packed));

static int patch_jump(int patch_orig_addr,int jump_dest_address, endpoint_t mpatch_endpoint, endpoint_t target_endpoint){//Only add the address not any jump instructions.
	cp_grant_id_t grant_id = cpf_grant_magic(mpatch_endpoint, target_endpoint, (vir_bytes) patch_orig_addr, 5, CPF_WRITE);
	if(grant_id < 0)
		printf("magic grant denied\n");

	int ret;
    struct jmp_inst jmp = {
        .opcode = 0xe9,
        .rel_addr = jump_dest_address - (patch_orig_addr + 5) // Rel addr is calculated from the instruction following the jmp
    }; 
    printf("Opcode: 0x%x, Payload: %p\n", jmp.opcode, (void*) jmp.rel_addr);
    printf("Opcode addr: %p, Payload addr: %p \n", &jmp.opcode, &jmp.rel_addr);
    unsigned char* ptr = (unsigned char*) &jmp;
    printf("Paybload byte by byte: %x %x %x %x %x\n", 
            *ptr, 
            *(ptr+1), 
            *(ptr+2), 
            *(ptr+3), 
            *(ptr+4));
    	
	if ((ret = sys_safecopyto(mpatch_endpoint, grant_id, 0, (vir_bytes) &jmp, 5)) != OK){
		printf("RET J: %d\n",ret);
		return ret;
	}
	if((ret = cpf_revoke(grant_id)) != OK){
		printf("REVOKE FAILED");
	}
	return OK;
}

static int inject_patch(int original_address, int patch_address, endpoint_t mpatch_endpoint, endpoint_t target_endpoint){
	int patch_size = 48;
	unsigned char patch[patch_size];
	int ret;

	//get the code from the binary
	int patch_binary = open("/usr/games/menupatch", O_RDONLY);
	//lseek(patch_binary, 0x2e0, SEEK_SET);
	lseek(patch_binary, 0x42e0, SEEK_SET);
	read(patch_binary, patch, patch_size);
	close(patch_binary);	

	//fix addresses of calls
	int i; int j;
	for(i = 0; i < patch_size; i++){
		if(patch[i] == (unsigned char) 0xe8){
			int prev_jmp = 0;
			prev_jmp = *((int *) (patch+i+1));//Read next 4 bytes as int
			printf("previous relative jump was to %x\n", prev_jmp);
			int new_jmp = prev_jmp + (original_address - patch_address);
			printf("new relative jump was to %x\n", new_jmp);
			*((int *) (patch+i+1)) = new_jmp;//Insert the new relative jmp over the old one
			i += 4;
		}
	}
	//TODO fix so that constant datafields are also moved

	//get grant
	cp_grant_id_t grant_id = cpf_grant_magic(mpatch_endpoint, target_endpoint, (vir_bytes) patch_address, patch_size, CPF_WRITE);
	if(grant_id < 0)
		printf("grant not recieved");

	//write patch to patch_address in the process
	if ((ret = sys_safecopyto(mpatch_endpoint, grant_id, 0, (vir_bytes) &patch, patch_size)) != OK){
		printf("copy failed returned: %d\n",ret);
		return ret;
	}
	if((ret = cpf_revoke(grant_id)) != OK)
		printf("REVOKE FAILED");

	return OK;
}

static int check_patch(int patch_address, endpoint_t mpatch_endpoint, endpoint_t target_endpoint){
	int patch_size = 48;
	unsigned char text[patch_size];
	cp_grant_id_t grant_id = cpf_grant_magic(mpatch_endpoint, target_endpoint, (vir_bytes) patch_address, patch_size, CPF_READ);
	if(grant_id < 0)
		printf("magic grant denied\n");

	int ret;
	//unsigned int test_pay = 0xDEADBEEF;
	if((ret = sys_safecopyfrom(mpatch_endpoint, grant_id, 0, (vir_bytes) text, patch_size)) != OK){
		printf("RET C: %d\n",ret);
		return ret;
	}
	if((ret = cpf_revoke(grant_id)) != OK){
		printf("REVOKE FAILED");
	}
	//print patch code
	int i;
	for(i = 0; i < patch_size; i++)
		printf("%02X ", text[i]);
	printf("\n");
	return OK;
}

static ssize_t mpatch(char* name){
	endpoint_t mpatch_endpoint;
	endpoint_t target_endpoint;
	int r;
	if((r = get_endpoints(&mpatch_endpoint, &target_endpoint, name)) != OK)
		return r;
	
	printf("Endpoint mpatch: %d, Endpoint other: %d\n",(int) mpatch_endpoint,(int) target_endpoint);
	int jump_dest_address = 0x80482e0;
	int patch_orig_addr = 0x0804c2e0;

	if((r = inject_patch(patch_orig_addr, jump_dest_address, mpatch_endpoint, target_endpoint)) != OK)
		return r;

	if((r = patch_jump(patch_orig_addr, jump_dest_address, mpatch_endpoint, target_endpoint)) != OK)
		return r;

	//if((r = check_patch(jump_dest_address, mpatch_endpoint, target_endpoint)) != OK)
	//	return r;
		
	printf("SUCCESS\n");
	return 100;
}

char received_msg[1024];
int received_pos = 0;
static int mpatch_open(devminor_t UNUSED(minor), int UNUSED(access),
                      endpoint_t UNUSED(user_endpt))
{
  received_pos = 0;
  received_msg[0] = '\0';
  
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
  char *buf = HELLO_MESSAGE;
 
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

static ssize_t mpatch_write(devminor_t UNUSED(minor), u64_t position,
			  endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
			  cdev_id_t UNUSED(id))
{
  int r;
  //printf("hello_write(position=%llu, size=%zu)\n", position, size);
  
  if (size > 1023 - received_pos)
    size = (size_t)(1023 - received_pos);	/* limit size */
 
  r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) (received_msg+received_pos), size);
  if (r != OK) {
    printf("MPATCH: warning: couldn't copy data %d\n", r);
    return OK;
  }
  received_pos += size;
  received_msg[received_pos] = '\0';

  char *rest = received_msg;

  char *name = rest;
  char *patch_loc = NULL;

  int i; 
  while(rest[i] != '\0'){
	  if(rest[i] == ' ' || rest[i] == '\n'){
		  rest[i++] = '\0';
		  if(patch_loc == NULL) patch_loc = rest + i;
	  }
	  else i++;
  }
  printf("received=%s menu?: %d\n", name,!strcmp(name,"menu"));
  printf("patch_loc empty? %d\n",*patch_loc == '\0');

  mpatch(name);

  if (received_msg[received_pos-1] != '\n')
    return size;

  received_pos = 0;
  received_msg[0] = '\0';
  
  return size;
}


int main(void)
{
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
