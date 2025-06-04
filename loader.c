/* SPDX-License-Identifier: GPL-2.0-only */

#define  WIN32_LEAN_AND_MEAN
#undef   NDEBUG
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

#include "sib.h"

#define AUTOUNLOCK	__attribute__((cleanup(mutex_exit)))

#ifdef __i386__
#define SIB_LOCATION(teb)	&teb->Reserved1[7]
#endif

#define ACQUIRE_LOCK(x)					\
({							\
	assert(pthread_mutex_lock (x) == 0);		\
	x;						\
})

#define RELEASE_LOCK(x)					\
({							\
	assert(pthread_mutex_unlock (x) == 0);		\
	NULL;						\
})

struct loaded_dll
{
  HMODULE h;
  struct loaded_dll *next;
};

static struct loaded_dll *loaded_dlls = NULL;
static pthread_mutex_t lck = PTHREAD_MUTEX_INITIALIZER;

static inline void
mutex_exit (pthread_mutex_t **x)
{
  pthread_mutex_t *mutex;

  mutex = *x;
  if (!mutex)
    return;

  assert(pthread_mutex_unlock (mutex) == 0);
}

static __cdecl void
unload_dlls (void)
{
  struct loaded_dll *i, *next;
  int err = 0;

  for (i = loaded_dlls; i; i = next)
  {
    next = i->next;

    if (FreeLibrary (i->h) == 0)
      err = 1;
    free (i);
  }

  if (err)
    fprintf (stderr, "can't free some dlls\n");
}

WINAPI static void *
snow_lookup_w32_sym (const char *dll, size_t n, const char *name, size_t n2)
{
  AUTOUNLOCK pthread_mutex_t *mutex = NULL;
  HMODULE h;
  void *res;
  struct loaded_dll *node;

  assert(!IsBadReadPtr (dll, n + 1) && !IsBadReadPtr (name, n2 + 1));
  assert(dll[n] == '\0' && name[n2] == '\0');

  mutex = ACQUIRE_LOCK(&lck);
  h = GetModuleHandle(dll);
  if (!h)
  {
    node = (struct loaded_dll *)malloc (sizeof(struct loaded_dll));
    if (!node)
    {
      fprintf (stderr, "alloc list failed, errno=%d\n", errno);
      exit (1);
    }

    h = LoadLibrary(dll);
    if (!h)
    {
      fprintf (stderr, "load %s failed, err=%lu\n", dll, GetLastError ());
      free (node);
      exit (1);
    }

    node->h = h;
    node->next = loaded_dlls;
    loaded_dlls = node;
  }
  mutex = RELEASE_LOCK(&lck);

  res = (void *)GetProcAddress (h, name);
  if (!res)
  {
    fprintf (stderr, "resolv w32 sym fail, name=%s, dll=%s, err=%lu\n", name, dll, GetLastError ());
    exit (1);
  }

  return res;
}

static struct snow_info_blk early_sib = {
  .lookup_w32_sym = &snow_lookup_w32_sym
};

static inline int
init_early_sib (void)
{
  void **sib_location;

  sib_location = SIB_LOCATION(NtCurrentTeb());
  if (*sib_location)
  {
    fprintf (stderr, "env ptr nonzero before init\n");
    return -1;
  }

  *sib_location = &early_sib;

  return 0;
}

int
main ()
{
  if (init_early_sib () < 0)
    return 1;

  if (atexit (unload_dlls) != 0)
  {
    fprintf (stderr, "atexit failed\n");
    return 1;
  }

  return 0;
}
