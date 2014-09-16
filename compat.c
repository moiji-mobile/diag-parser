#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <time64.h>

#define CHAR_BIT 8
// From http://code.metager.de/source/xref/chromium/base/os_compat_android.cc
// 32-bit Android has only timegm64() and not timegm().
// We replicate the behaviour of timegm() when the result overflows time_t.
time_t timegm(struct tm* const t) {
  // time_t is signed on Android.
  static const time_t kTimeMax = ~(1L << (sizeof(time_t) * CHAR_BIT - 1));
  static const time_t kTimeMin = (1L << (sizeof(time_t) * CHAR_BIT - 1));
  time64_t result = timegm64(t);
  if (result < kTimeMin || result > kTimeMax)
    return -1;
  return result;
}

// https://android.googlesource.com/platform/external/elfutils/+/android-4.3.1_r1/bionic-fixup/getline.c
ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
  char *ptr;
  ptr = fgetln(stream, n);
  if (ptr == NULL) {
    return -1;
  }
  /* Free the original ptr */
  if (*lineptr != NULL) free(*lineptr);
  /* Add one more space for '\0' */
  size_t len = n[0] + 1;
  /* Update the length */
  n[0] = len;
  /* Allocate a new buffer */
  *lineptr = malloc(len);
  /* Copy over the string */
  memcpy(*lineptr, ptr, len-1);
  /* Write the NULL character */
  (*lineptr)[len-1] = '\0';
  /* Return the length of the new buffer */
  return len;
}
