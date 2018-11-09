#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include <minix/chardriver.h>
#include "groupdriver.h"

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
static int groupdriver_open(devminor_t minor, int access, endpoint_t user_endpt);
static int groupdriver_close(devminor_t minor);
static ssize_t groupdriver_read(devminor_t minor, u64_t position, endpoint_t endpt,
    cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
static ssize_t groupdriver_write(devminor_t minor, u64_t position, endpoint_t endpt,
			   cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);

/* Entry points to the hello driver. */
static struct chardriver groupdriver_tab =
{
 .cdr_open	= groupdriver_open,
 .cdr_close	= groupdriver_close,
 .cdr_read	= groupdriver_read,
 .cdr_write     = groupdriver_write,
};


static int vm_debug(endpoint_t ep)
{
  message m;
  int result;

  memset(&m, 0, sizeof(m));

  m.VMPCTL_WHO = ep;
  result = _taskcall(VM_PROC_NR, VM_PT_DEBUG, &m);

  return(result);
}

int group_number = 0;
char* group_members[] =
{
    "Kristian Alvarez Jorgensen\n", //örgensen", 
    "Michael Chlebek\n", 
    "Niklas Reje\n",
    "Vidar Palmer\n" //ér"
};
    
static int groupdriver_open(devminor_t UNUSED(minor), int UNUSED(access),
                      endpoint_t UNUSED(user_endpt))
{
  myserver_sys1();
  return OK;
}
 
static int groupdriver_close(devminor_t UNUSED(minor))
{
  printf("groupdriver_close()\n");
  return OK;
}
 
static ssize_t groupdriver_read(devminor_t UNUSED(minor), u64_t position,
                          endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
                          cdev_id_t UNUSED(id))
{
  u64_t dev_size;
  char *ptr;
  int ret;
  char *buf = group_members[group_number];
 
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

static ssize_t groupdriver_write(devminor_t UNUSED(minor), u64_t position,
			  endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
			  cdev_id_t UNUSED(id))
{
  int r;
  size = (size_t) 1; 
  char input_char; 
  r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) (&input_char), size);
  if (r != OK) {
    printf("groupdriver: warning: couldn't copy data %d\n", r);
    return OK;
  }

  if (input_char > '0' && input_char <= '4') { 
      group_number = (int) (input_char - '1'); 
  }

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
  chardriver_task(&groupdriver_tab);
  return OK;
}
