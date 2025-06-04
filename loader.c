/* SPDX-License-Identifier: GPL-2.0-only */

#define  WIN32_LEAN_AND_MEAN
#undef   NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
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

#define KOORI_IMG_NAME	"koori.elf"

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

static inline int
load_and_run_koori_img (void)
{
  int fd;
  struct stat st;
  int res;
  static union
  {
    char raw[0x1000];
    struct
    {
      char mgc[4];
      unsigned char bits;
      unsigned char endian;
      char pad[10];
#ifdef __i386__
      unsigned short pad1;
      unsigned short arch;
      void *pad2;
#endif
      int (*entry)(void) WINAPI;
      struct
      {
        size_t kind;
        char *data_ptr;
        size_t addr;
        size_t pad;
        size_t data_len;
        size_t size;
        size_t pad2[2];
      } *phdr;
#ifdef __i386__
      size_t pad3;
      void *pad4;
      unsigned short pad5[2];
      unsigned short num_segs;
#endif
    } hdr;
  } buf;

  fd = open (KOORI_IMG_NAME, O_RDONLY | O_BINARY);
  if (fd < 0)
  {
    fprintf (stderr, "open koori img failed, errno=%d\n", errno);
    return -1;
  }

  if (fstat (fd, &st) < 0)
  {
    fprintf (stderr, "get koori img size failed, errno=%d\n", errno);
    res = -1;
    goto quit_close_fd;
  }

  assert(st.st_size <= sizeof(buf.raw));

  if (read (fd, buf.raw, st.st_size) != st.st_size)
  {
    fprintf (stderr, "read koori img failed, errno=%d\n", errno);
    res = -1;
    goto quit_close_fd;
  }

  if (memcmp (buf.hdr.mgc, "\177ELF", 4))
  {
    fprintf (stderr, "koori img is not elf\n");
    res = -1;
    goto quit_close_fd;
  }

#ifdef __i386__
  if (buf.hdr.bits != 1)  // ELFCLASS32
  {
    fprintf (stderr, "koori img isn't elf32\n");
    res = -1;
    goto quit_close_fd;
  }

  if (buf.hdr.endian != 1)  // ELFDATA2LSB
  {
    fprintf (stderr, "koori img isn't in LE\n");
    res = -1;
    goto quit_close_fd;
  }

  if (buf.hdr.arch != 3)  // EM_386
  {
    fprintf (stderr, "koori img isn't for i386\n");
    res = -1;
    goto quit_close_fd;
  }
#else
#error i dont understand your architecture yet
#endif

  res = 0;

quit_close_fd:
  close (fd);

  return res;
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

  if (load_and_run_koori_img () < 0)
    return 1;

  return 0;
}
