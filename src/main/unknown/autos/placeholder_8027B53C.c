#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027B53C.h"

extern void audioFn_8027b42c(u16 voiceId, u16 a, u16 b, u16 c);
extern int fn_8027B89C(u16 voiceId, u16 a, u16 b, u16 c, u16 d, u32 e);

/*
 * audioFn_8027b42c — large voice-update inner helper (~152 instructions).
 * Stubbed pending full decode.
 */
#pragma dont_inline on
void audioFn_8027b42c(u16 voiceId, u16 a, u16 b, u16 c)
{
    (void)voiceId;
    (void)a;
    (void)b;
    (void)c;
}
#pragma dont_inline reset

/*
 * Iterate a u16 list terminated by 0xFFFF, dispatching each entry to
 * audioFn_8027b42c. Entries with bit 0x8000 set are "ranges": low 14 bits
 * are the start, the following u16 is the inclusive end.
 *
 * EN v1.0 Address: 0x8027B260
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B690
 * EN v1.1 Size: 156b
 */
void fn_8027B690(u16 *list, u16 a, u16 b, u16 c)
{
    while (*list != 0xffff) {
        u16 v = *list;
        if ((v & 0x8000) == 0) {
            list++;
            audioFn_8027b42c(v, a, b, c);
        } else {
            u16 i = v & 0x3fff;
            for (; (u32)i <= (u32)list[1]; i++) {
                audioFn_8027b42c(i, a, b, c);
            }
            list += 2;
        }
    }
}

/*
 * fn_8027B72C — second voice-update helper (~91 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027B72C(u16 voiceId)
{
    (void)voiceId;
}
#pragma dont_inline reset

/*
 * fn_8027B89C — voice-bank scanning loop with 7-arg signature (~80
 * instructions, walks 'lbl_803DE308' entries against multiple keys).
 * Stubbed pending full decode.
 */
#pragma dont_inline on
int fn_8027B89C(u16 voiceId, u16 a, u16 b, u16 c, u16 d, u32 e)
{
    (void)voiceId;
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    return 0;
}
#pragma dont_inline reset

/*
 * Thin wrapper inserting `0` as the f argument into fn_8027B89C and
 * shifting the caller's last arg into position g.
 *
 * EN v1.0 Address: 0x8027B26C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B9DC
 * EN v1.1 Size: 36b
 */
int fn_8027B9DC(u16 voiceId, u16 a, u16 b, u16 c, u32 e)
{
    return fn_8027B89C(voiceId, a, b, c, 0 /* d=arg5 was zeroed */, e);
}
