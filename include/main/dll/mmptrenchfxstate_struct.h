#ifndef MAIN_DLL_MMPTRENCHFXSTATE_STRUCT_H_
#define MAIN_DLL_MMPTRENCHFXSTATE_STRUCT_H_

#include "types.h"

typedef struct MmpTrenchfxState
{
    s16 enableBit; /* data+0x24 gamebit gate, -1 = always on */
    u16 extentX; /* data[0x1C..0x1E] << 2 random offset half-extents */
    u16 extentZ;
    u16 extentY;
    s16 emitAngles[3]; /* roll/pitch/yaw presets, mirrored to obj+4/2/0 */
    u8 pad0E[2];
    u32 fxUnk10; /* embedded partfx args record (state+0x10 passed to spawn) */
    u32 fxUnk14;
    f32 fxScale;
    f32 fxX;
    f32 fxY;
    f32 fxZ;
    f32 emitCooldown; /* rand(100,200) frames between bursts */
    f32 emitTimer; /* rand(50,100); spawns effect 0x71F while > 0 */
} MmpTrenchfxState;

#endif
