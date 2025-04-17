/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>

__attribute__((noreturn)) void
__stack_chk_fail (void)
{
  fprintf (stderr, "stkchk failure\n");

  for (; ; )
    ;
}

__attribute__((noreturn)) void
__stack_chk_fail_local (void)
{
  __stack_chk_fail ();
}
