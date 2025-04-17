#define  WIN32_LEAN_AND_MEAN
#include <linux/errno.h>
#include <linux/unistd.h>
#include <windows.h>
#include <winternl.h>

#define SYSCALL_IMPLED(name)								\
	[__NR_##name] = [] (void) constexpr {						\
		long									\
		sys_##name (long, long, long, long, long, long) asm("sys_" #name);	\
											\
		return &sys_##name;							\
	} ()

extern "C" void
_snow_handle_syscall (void);

static long (*syscalls[]) (long, long, long, long, long, long) = {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-designator"
#pragma clang diagnostic pop
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

extern "C" __attribute__((visibility("default"))) int
_snow_init_layer (void)
{
  HANDLE hProc;
  HMODULE hK32;
  typeof(IsWow64Process2) *iswow64proc2;
  unsigned short mach_proc, mach_native;
  BOOL iswow64;
  TEB *teb;

  hProc = GetCurrentProcess ();

  hK32 = GetModuleHandle("kernel32.dll");
  if (!hK32)
    return -1;

  iswow64proc2 = (typeof(iswow64proc2))(void *)GetProcAddress (hK32, "IsWow64Process2");
  if (iswow64proc2)
  {
    if (iswow64proc2 (hProc, &mach_proc, &mach_native) == 0)
      return -1;

    if (mach_proc != mach_native)
      return -1;
  }
  else
  {
    if (IsWow64Process (hProc, &iswow64) == 0)
      return -1;

    if (iswow64)
      return -1;
  }

  teb = NtCurrentTeb();
  if (teb->WOW32Reserved)
    return -1;

  teb->WOW32Reserved = (void *)_snow_handle_syscall;

  return 0;
}
