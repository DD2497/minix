/* Prototypes and definitions for MPSERVER interface. */

#ifndef _MINIX_MPSERVER_H
#define _MINIX_MPSERVER_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* mpserver.c */

/* U32 */
int mpserver_sys1(endpoint_t, endpoint_t, struct patch_info);

#endif /* _MINIX_MPSERVER_H */
