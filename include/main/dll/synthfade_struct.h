#ifndef MAIN_DLL_SYNTHFADE_STRUCT_H_
#define MAIN_DLL_SYNTHFADE_STRUCT_H_

#include "types.h"

typedef struct SynthFade
{
    f32 current;
    f32 target;
    f32 start;
    f32 progress;
    f32 progressStep;
    f32 auxCurrent;
    f32 auxTarget;
    f32 auxStart;
    f32 auxProgress;
    f32 auxProgressStep;
    u32 handle;
    u8 delayAction;
    u8 type;
    u8 pad[2];
} SynthFade;

#endif
