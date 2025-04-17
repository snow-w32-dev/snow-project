/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef    SNOW_SIB_H
#define    SNOW_SIB_H

#include <windef.h>

struct snow_info_blk
{
  void *(WINAPI *lookup_w32_sym) (const char *dll, const char *name);
};

#endif  /* SNOW_SIB_H */
