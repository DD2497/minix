#include <minix/ds.h>
#include <minix/mpserver.h>
#include <string.h>

#include "syslib.h"

static int do_invoke_mpserver(message *m, int type)
{
	int r;

	r = _taskcall(MPSERVER_PROC_NR, type, m);

	return r;
}

int mpserver_sys1(endpoint_t mpatch_endpoint, endpoint_t target_endpoint, struct patch_info p_info)
{
	message m;

	memset(&m, 0, sizeof(m));
        
        m.m_source = mpatch_endpoint;
        m.m_type = MPSERVER_SYS1;
        m.m_mp_mps_patchinfo.target_endpoint = target_endpoint;
        m.m_mp_mps_patchinfo.p_info = p_info;
        int path_length = 0;
        while(m.m_mp_mps_patchinfo.p_info.origin_file[path_length++] != '\0');
        m.m_mp_mps_patchinfo.origin_path_length = path_length;
        path_length = 0;
        while(m.m_mp_mps_patchinfo.p_info.patch_file[path_length++] != '\0');
        m.m_mp_mps_patchinfo.patch_path_length = path_length;


	return do_invoke_mpserver(&m, m.m_type);
}
