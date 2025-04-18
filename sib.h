/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef    SNOW_SIB_H
#define    SNOW_SIB_H

#include <windef.h>

struct snow_info_blk
{
  void *(WINAPI *lookup_w32_sym) (const char *dll, size_t n, const char *name, size_t n2);
};

#endif  /* SNOW_SIB_H */
