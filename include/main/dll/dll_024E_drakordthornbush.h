#ifndef MAIN_DLL_DLL_024E_DRAKORDTHORNBUSH_H_
#define MAIN_DLL_DLL_024E_DRAKORDTHORNBUSH_H_

#include "types.h"
#include "main/game_object.h"
#include "global.h"

struct ModelLightStruct;

typedef struct DrakordThornbushPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 spawnHealth;  /* 0x19: initial hit points */
    s16 regrowDelay; /* 0x1A: frames before regrow (0 = no respawn) */
    s16 baseRadius;  /* 0x1C: base hit-sphere radius */
    u8 pad1E[0x20 - 0x1E];
} DrakordThornbushPlacement;

typedef struct DrakordThornbushState
{
    s32 health; /* 0x00: hit points; 0 = dormant */
    u8 pad4[0x8 - 0x4];
    s32 lastHitObj;                   /* 0x08: most recent attacker, debounces re-hits */
    f32 growth;                       /* 0x0C: regrow timer / scale driver */
    f32 regrowTimer;                  /* 0x10: hit/regrow countdown */
    void* lightningEntries[3];
    u8 pad20[0x64 - 0x20];
    struct ModelLightStruct* light; /* 0x64: model light handle (lightning variant) */
    f32 lightScale;                   /* 0x68: lightning scale, accumulates over time */
    void* hitTable;                   /* 0x6C: hit-reaction table pointer */
    f32 baseScale;                    /* 0x70: per-variant init scale constant */
    s32 radius;                       /* 0x74 */
    u8 tail78[0x7c - 0x78];           /* 0x78: holds DrakorFlags byte at 0x79 */
} DrakordThornbushState;

STATIC_ASSERT(offsetof(DrakordThornbushPlacement, spawnHealth) == 0x19);
STATIC_ASSERT(offsetof(DrakordThornbushPlacement, regrowDelay) == 0x1A);
STATIC_ASSERT(offsetof(DrakordThornbushPlacement, baseRadius) == 0x1C);
STATIC_ASSERT(sizeof(DrakordThornbushPlacement) == 0x20);
STATIC_ASSERT(offsetof(DrakordThornbushState, regrowTimer) == 0x10);
STATIC_ASSERT(offsetof(DrakordThornbushState, light) == 0x64);
STATIC_ASSERT(offsetof(DrakordThornbushState, lightScale) == 0x68);
STATIC_ASSERT(offsetof(DrakordThornbushState, hitTable) == 0x6C);
STATIC_ASSERT(offsetof(DrakordThornbushState, baseScale) == 0x70);
STATIC_ASSERT(offsetof(DrakordThornbushState, radius) == 0x74);
STATIC_ASSERT(sizeof(DrakordThornbushState) == 0x7c);

int drakord_thornbush_getExtraSize(void);
int drakord_thornbush_getObjectTypeId(void);
void drakord_thornbush_free(int obj);
void drakord_thornbush_render(int p1, int p2, int p3, int p4, int p5, s8 vis);
void drakord_thornbush_hitDetect(int obj);
void drakord_thornbush_update(GameObject* obj);
void drakord_thornbush_init(GameObject* obj, u8* init);
void drakord_thornbush_release(void);
void drakord_thornbush_initialise(void);

#endif
