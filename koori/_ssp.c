/* SPDX-License-Identifier: GPL-2.0-only */

#define  WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <windows.h>

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
