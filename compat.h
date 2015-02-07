#ifndef __COMPAT_H__
#define __COMPAT_H__

#ifdef WIN32

#include <windows.h>

#define sleep(secs) Sleep((secs) * 1000)

enum {
	PRIO_PROCESS		= 0,
};

static __inline int setpriority(int which, int who, int prio)
{
	return -!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

#ifdef _MSC_VER
#define snprintf(...) _snprintf(__VA_ARGS__)
#define strdup(...) _strdup(__VA_ARGS__)
#define strncasecmp(x,y,z) _strnicmp(x,y,z)
#define strcasecmp(x,y) _stricmp(x,y)
#define __func__ __FUNCTION__
#define __thread __delclspec(thread)
#define _ALIGN(x) __declspec(align(x))
typedef int ssize_t;

#include <stdlib.h>
static __inline char * dirname(char *file) {
	char buffer[_MAX_PATH] = { 0 };
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];
	_splitpath_s(file, drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
	sprintf(buffer, "%s%s", drive, dir);
	return strdup(buffer);
}
#endif

#endif /* WIN32 */

#ifndef _MSC_VER
#define _ALIGN(x) __attribute__ ((aligned(x)))
#endif

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#endif /* __COMPAT_H__ */
