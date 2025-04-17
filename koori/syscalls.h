#ifndef    KOORI_SYSCALLS_H
#define    KOORI_SYSCALLS_H

#define DEFINE_SYSCALL1(ret, name, t0, p0)					\
	static inline ret							\
	sys_impl_##name (t0 p0);						\
										\
	long									\
	sys_##name (long a0, long a1, long a2, long a3, long a4, long a5)	\
	{									\
		(void)a1;							\
		(void)a2;							\
		(void)a3;							\
		(void)a4;							\
		(void)a5;							\
		return (long)sys_impl_##name ((t0)a0);				\
	}									\
										\
	static inline ret							\
	sys_impl_##name (t0 p0)

#define DEFINE_SYSCALL3(ret, name, t0, p0, t1, p1, t2, p2)			\
	static inline ret							\
	sys_impl_##name (t0 p0, t1 p1, t2 p2);					\
										\
	long									\
	sys_##name (long a0, long a1, long a2, long a3, long a4, long a5)	\
	{									\
		(void)a3;							\
		(void)a4;							\
		(void)a5;							\
		return (long)sys_impl_##name ((t0)a0, (t1)a1, (t2)a2);		\
	}									\
										\
	static inline ret							\
	sys_impl_##name (t0 p0, t1 p1, t2 p2)

#endif  /* KOORI_SYSCALLS_H */
