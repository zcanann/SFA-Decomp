#ifndef MAIN_DLL_DLL_016B_MAGICLIGHT_H_
#define MAIN_DLL_DLL_016B_MAGICLIGHT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct MagicLightPlacement
{
    ObjPlacement base;
    s8 initialRotX;
    u8 pad19;
    s16 subtype;
} MagicLightPlacement;

typedef struct MagicLightState
{
    f32 triggerRadius; /* preset by subtype */
    s16 lifetime; /* rand(200,600) at init */
    s16 enterAction; /* L-action when the player enters the radius */
    s16 leaveAction; /* L-action when the player leaves radius + hysteresis */
    u8 pad0A;
    s8 inRange; /* hysteresis latch */
    s8 subtype; /* params+0x1A */
    u8 pad0D[3];
    s16 unk10; /* 301 at init */
    u8 pad12[2];
} MagicLightState;

STATIC_ASSERT(offsetof(MagicLightPlacement, initialRotX) == 0x18);
STATIC_ASSERT(offsetof(MagicLightPlacement, subtype) == 0x1A);
STATIC_ASSERT(sizeof(MagicLightPlacement) == 0x1C);
STATIC_ASSERT(offsetof(MagicLightState, lifetime) == 0x04);
STATIC_ASSERT(offsetof(MagicLightState, enterAction) == 0x06);
STATIC_ASSERT(offsetof(MagicLightState, leaveAction) == 0x08);
STATIC_ASSERT(offsetof(MagicLightState, inRange) == 0x0B);
STATIC_ASSERT(offsetof(MagicLightState, subtype) == 0x0C);
STATIC_ASSERT(offsetof(MagicLightState, unk10) == 0x10);
STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

extern ObjectDescriptor gMagicLightObjDescriptor;

int MagicLight_getExtraSize(GameObject* obj);
int MagicLight_getObjectTypeId(void);
void MagicLight_free(GameObject* obj);
void MagicLight_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void MagicLight_hitDetect(void);
void MagicLight_update(GameObject* obj);
void MagicLight_init(GameObject* obj, MagicLightPlacement* placement);
int MagicLight_SeqFn(GameObject* obj);
void MagicLight_release(void);
void MagicLight_initialise(void);

#endif /* MAIN_DLL_DLL_016B_MAGICLIGHT_H_ */
