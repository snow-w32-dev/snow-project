/* SPDX-License-Identifier: GPL-2.0-only */

#define  WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#include "sib.h"

WINAPI static void *
snow_lookup_w32_sym (const char *dll, const char *name)
{
  HMODULE h;
  void *res;

  h = GetModuleHandle(dll);
  if (!h)
  {
    h = LoadLibrary(dll);
    if (!h)
    {
      fprintf (stderr, "load %s failed, err=%lu\n", dll, GetLastError ());
      return NULL;
    }
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

  return 0;
}
