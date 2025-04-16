#ifndef __i386__
#error unsupported architecture
#endif

.text
.globl _snow_handle_syscall
.hidden _snow_handle_syscall
.type _snow_handle_syscall, @function
_snow_handle_syscall:
	// save regs
	// switch stack
	// push params
	call	_snow_dispatch_syscall
	// restore regs
	ret
