/* SPDX-License-Identifier: GPL-2.0-only */

#define  WIN32_LEAN_AND_MEAN
#include <stddef.h>
#include <stdio.h>
#include <windows.h>

// TODO: populate with random val
size_t __stack_chk_guard;

__attribute__((noreturn)) void
__stack_chk_fail (void)
{
  fprintf (stderr, "stkchk failure\n");
  ExitProcess (1);
}

__attribute__((noreturn)) void
__stack_chk_fail_local (void)
{
  __stack_chk_fail ();
}
