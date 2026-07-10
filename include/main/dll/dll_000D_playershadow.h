#ifndef MAIN_DLL_DLL_000D_PLAYERSHADOW_H_
#define MAIN_DLL_DLL_000D_PLAYERSHADOW_H_

#include "global.h"
#include "main/game_object.h"

/* One terrain-triangle hit record produced by the hit-detect pipeline
 * (hitDetectFn_800691c0 / fn_80069968). Stride 0x4c; the three struck-triangle
 * corners are stored as separate s16 component arrays (tile-local coords), and
 * the GameObject surface type lives at 0x48. */
typedef struct PlayerShadowTriHit
{
    u8 pad00[0x10];
    s16 vertX[3]; /* 0x10 */
    s16 vertY[3]; /* 0x16 */
    s16 vertZ[3]; /* 0x1c */
    u8 pad22[0x48 - 0x22];
    u8 surfaceType; /* 0x48 */
    u8 pad49[0x4c - 0x49];
} PlayerShadowTriHit;

STATIC_ASSERT(sizeof(PlayerShadowTriHit) == 0x4c);
STATIC_ASSERT(offsetof(PlayerShadowTriHit, vertX) == 0x10);
STATIC_ASSERT(offsetof(PlayerShadowTriHit, vertY) == 0x16);
STATIC_ASSERT(offsetof(PlayerShadowTriHit, vertZ) == 0x1c);
STATIC_ASSERT(offsetof(PlayerShadowTriHit, surfaceType) == 0x48);

struct PlayerShadowParamsBlob
{
    u32 a;
    u32 b;
    u32 c;
    u32 d;
};

void fn_800A3AF0(PlayerShadowTriHit* hits, int count, f32 offsX, f32 offsZ, GameObject* obj);
void playerShadow_setMode(u8 v);
void playerShadow_renderObject(GameObject* obj);
void playerShadow_func03_nop(void);
void playerShadow_release(void);
void playerShadow_initialise(void);

#endif
