__attribute__((noreturn)) void
__stack_chk_fail (void)
{
  for (; ; )
    ;
}

__attribute__((noreturn)) void
__stack_chk_fail_local (void)
{
  __stack_chk_fail ();
}
