#ifndef __COMPAT_H__
#define __COMPAT_H__

#ifdef _WIN32

#include <windows.h>

#define sleep(secs) Sleep((secs) * 1000)

enum {
	PRIO_PROCESS		= 0,
};

static inline int setpriority(int which, int who, int prio)
{
	return -!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

#endif /* _WIN32 */

#endif /* __COMPAT_H__ */
