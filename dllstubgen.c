#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AUTOCLO		__attribute__((cleanup(fd_exit)))
#define AUTOFCLO	__attribute__((cleanup(fp_exit)))
#define AUTOFREE	__attribute__((cleanup(ptr_exit)))

static void
fd_exit (int *x)
{
  int fd;

  fd = *x;
  if (fd < 0)
    return;

  if (close (fd) < 0)
    perror ("close");
}

static void
fp_exit (FILE **x)
{
  FILE *fp;

  fp = *x;
  if (!fp)
    return;

  if (fclose (fp) < 0)
    perror ("fclose");
}

static void
ptr_exit (void **x)
{
  void *ptr;

  ptr = *x;
  if (!ptr)
    return;

  free (ptr);
}

static int
do_gen_code (FILE *fp, FILE *fp2, FILE *fp3)
{
#define BUF_SIZE	64

  char *line;
  AUTOFREE void *buf = NULL;
  size_t n = BUF_SIZE;
  char *nlpos;

#define try_write_asm(s, ...)				\
	if (fprintf (fp2, s, ##__VA_ARGS__) < 0)	\
		return -1;

  try_write_asm("#ifndef __i386__\n"
                "#error unsupported architecture\n"
                "#endif\n");
  try_write_asm(".text\n");

  line = buf = malloc (BUF_SIZE);
  if (!buf)
  {
    perror ("malloc");
    return -1;
  }

  while (getline (&line, &n, fp) != EOF)
  {
    nlpos = strchr (line, '\n');
    if (nlpos)
      *nlpos = '\0';

    try_write_asm(".globl \"%s\"\n", line);
    try_write_asm(".hidden \"%s\"\n", line);
    try_write_asm(".type \"%s\", @function\n", line);
    try_write_asm("\"%s\":\n", line);
  }

  return 0;
}

int
main (int argc, char *argv[])
{
  AUTOCLO int fd = -1, fd2 = -1, fd3 = -1;
  AUTOFCLO FILE *fp = NULL, *fp2 = NULL, *fp3 = NULL;
  size_t n;
  int res = 0;

  if (argc != 2)
  {
    fprintf (stderr, "incorrect argument count\n");
die_usage:
    fprintf (stderr, "Usage: %s <symbol list>\n", argv[0]);
    return 1;
  }

#define pathname	argv[1]

  n = strlen (pathname);
  if (memcmp (pathname + n - 4, ".txt", 4))
  {
    fprintf (stderr, "input file must has .txt extension\n");
    goto die_usage;
  }

  fd = open (pathname, O_RDONLY);
  if (fd < 0)
  {
    fprintf (stderr, "cannot open input file\n");
    perror ("open");
    return 1;
  }

  memcpy (pathname + n - 4, ".S", 3);
  fd2 = open (pathname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd2 < 0)
  {
open_failed:
    fprintf (stderr, "cannot open output file\n");
    perror ("open");
    return 1;
  }

  memcpy (pathname + n - 4, ".c", 3);
  fd3 = open (pathname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd3 < 0)
    goto open_failed;

  fp = fdopen (fd, "r");
  if (!fp)
  {
fdopen_failed:
    perror ("fdopen");
    return 1;
  }
  fd = -1;

  fp2 = fdopen (fd2, "w");
  if (!fp2)
    goto fdopen_failed;
  fd2 = -1;

  fp3 = fdopen (fd3, "w");
  if (!fp3)
    goto fdopen_failed;
  fd3 = -1;

  if (do_gen_code (fp, fp2, fp3) < 0)
  {
    fprintf (stderr, "error occurred while writing output\n");
    res = 1;
  }

  if (fclose (fp) < 0)
  {
    perror ("fclose");
    res = 1;
  }
  fp = NULL;

  if (fclose (fp2) < 0)
  {
    perror ("fclose");
    res = 1;
  }
  fp2 = NULL;

  if (fclose (fp3) < 0)
  {
    perror ("fclose");
    res = 1;
  }
  fp3 = NULL;

  return res;
}
