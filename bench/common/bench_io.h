/* bench_io.h — emit bytes as ASCII hex on the bare-metal M4 path or stdout
 * on a host build. Each bench links exactly one of bench_io_baremetal.c or
 * bench_io_host.c, so this header is interface-only.
 */
#ifndef BENCH_IO_H
#define BENCH_IO_H

#include <stddef.h>
#include <stdint.h>

void bench_emit_hex(const uint8_t *data, size_t n);
void bench_emit_str(const char *s);

#endif
