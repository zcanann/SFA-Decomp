#ifndef MAIN_DLL_DLL_0040_CREDITS_H_
#define MAIN_DLL_DLL_0040_CREDITS_H_

#include "types.h"

typedef struct
{
    u16 t0; /* fade-in start */
    u16 t1; /* fade-in end / full-alpha start */
    u16 t2; /* full-alpha end / fade-out start */
    u16 t3; /* fade-out end */
    u8 pad8[3];
    u8 alpha;
    f32 y;
} CreditsLine;

typedef struct
{
    CreditsLine lines[9];
    u16 scrollStartTime;
    u16 endTime;
    u8 count;
    u8 pad95[3];
} CreditsPage;

void Credits_render(void);
void Credits_frameEnd(void);
int Credits_frameStart(void);
void Credits_release(void);
void Credits_initialise(void);

#endif
