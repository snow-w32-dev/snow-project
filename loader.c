/* SPDX-License-Identifier: GPL-2.0-only */

#define  WIN32_LEAN_AND_MEAN
#undef   NDEBUG
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

#include "sib.h"

struct loaded_dll
{
  HMODULE h;
  struct loaded_dll *next;
};

static struct loaded_dll *loaded_dlls = NULL;
static pthread_mutex_t lck = PTHREAD_MUTEX_INITIALIZER;

static int
unload_dlls (void)
{
  struct loaded_dll *i, *next;
  int res = 0;

  for (i = loaded_dlls; i; i = next)
  {
    next = i->next;

    if (FreeLibrary (i->h) == 0)
      res = -1;
    free (i);
  }

  return res;
}

WINAPI static void *
snow_lookup_w32_sym (const char *dll, size_t n, const char *name, size_t n2)
{
  HMODULE h;
  void *res;
  struct loaded_dll *node;

  if (IsBadReadPtr (dll, n + 1) || IsBadReadPtr (name, n2 + 1))
    return NULL;

  if (dll[n] != '\0' || name[n2] != '\0')
    return NULL;

  h = GetModuleHandle(dll);
  if (!h)
  {
    node = (struct loaded_dll *)malloc (sizeof(struct loaded_dll));
    if (!node)
    {
      perror ("malloc");
      return NULL;
    }

    h = LoadLibrary(dll);
    if (!h)
    {
      fprintf (stderr, "load %s failed, err=%lu\n", dll, GetLastError ());
      free (node);
      return NULL;
    }

    node->h = h;
    assert(pthread_mutex_lock (&lck) == 0);
    node->next = loaded_dlls;
    loaded_dlls = node;
    assert(pthread_mutex_unlock (&lck) == 0);
  }

  res = (void *)GetProcAddress (h, name);
  if (!res)
    fprintf (stderr, "resolv w32 sym fail, name=%s, dll=%s, err=%lu\n", name, dll, GetLastError ());

  return res;
}

static struct snow_info_blk early_sib = {
  .lookup_w32_sym = &snow_lookup_w32_sym
};

static int
init_early_sib (void)
{
  TEB *teb;

  teb = NtCurrentTeb();

#define sib_location()		teb->Reserved1[7]

  if (sib_location())
  {
    fprintf (stderr, "env ptr nonzero before init\n");
    return -1;
  }

  sib_location() = &early_sib;

  return 0;
}

int
main ()
{
  if (init_early_sib () < 0)
    return 1;

  if (unload_dlls () < 0)
  {
    fprintf (stderr, "can't free some dll\n");
    return 1;
  }

  return 0;
}
