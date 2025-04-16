#include <linux/errno.h>

static long (*syscalls[]) (long, long, long, long, long, long) = {
};

extern "C" long
_snow_dispatch_syscall(long nr,
                       long a0, long a1, long a2, long a3, long a4, long a5)
{
  long (*syscall) (long, long, long, long, long, long);

  if (nr < 0
      || (size_t)nr >= sizeof(syscalls) / sizeof(syscalls[0]))
illegal_num:
    return -ENOSYS;

  syscall = syscalls[nr];
  if (!syscall)
    goto illegal_num;

  return syscall (a0, a1, a2, a3, a4, a5);
}
