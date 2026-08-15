#ifndef MAIN_DLL_DLL_023F_DBEGG_H_
#define MAIN_DLL_DLL_023F_DBEGG_H_

#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

extern ObjectDescriptor12 gDB_eggObjDescriptor;

typedef struct DbeggPlacement
{
    ObjPlacement base;    /* 0x00 */
    u8 pad18;             /* 0x18 */
    u8 forceRadiusByte;   /* 0x19 */
    u8 speedScaleByte;    /* 0x1A: root-motion scale in 1/64 units */
    u8 facingAngleByte;   /* 0x1B: initial anim.rotX (<<8) */
    s16 triggerGameBit;   /* 0x1C: set once the egg is delivered; also selects the start mode */
    s16 secondaryGameBit; /* 0x1E: set when the egg reaches its target */
    s16 unk20;            /* 0x20 */
    u8 pad22[0x24 - 0x22];
    s16 activateGameBit;  /* 0x24: gates the launch mode */
    u8 behaviorMode;      /* 0x26 */
    u8 pad27[0x2B - 0x27];
    u8 unk2B;             /* 0x2B */
    s16 counterGameBit;   /* 0x2C: bit incremented on delivery (>0 = active) */
    s8 unk2E;             /* 0x2E */
} DbeggPlacement;

STATIC_ASSERT(offsetof(DbeggPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(DbeggPlacement, forceRadiusByte) == 0x19);
STATIC_ASSERT(offsetof(DbeggPlacement, speedScaleByte) == 0x1A);
STATIC_ASSERT(offsetof(DbeggPlacement, facingAngleByte) == 0x1B);
STATIC_ASSERT(offsetof(DbeggPlacement, triggerGameBit) == 0x1C);
STATIC_ASSERT(offsetof(DbeggPlacement, secondaryGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DbeggPlacement, unk20) == 0x20);
STATIC_ASSERT(offsetof(DbeggPlacement, activateGameBit) == 0x24);
STATIC_ASSERT(offsetof(DbeggPlacement, behaviorMode) == 0x26);
STATIC_ASSERT(offsetof(DbeggPlacement, unk2B) == 0x2B);
STATIC_ASSERT(offsetof(DbeggPlacement, counterGameBit) == 0x2C);
STATIC_ASSERT(offsetof(DbeggPlacement, unk2E) == 0x2E);
STATIC_ASSERT(sizeof(DbeggPlacement) == 0x30);

int dbegg_setLaunchVelocity(GameObject* obj, f32* velocity);
int dbegg_isActive(GameObject* obj);
int dbegg_getExtraSize(void);
int dbegg_getObjectTypeId(void);
void dbegg_free(GameObject* obj);
void dbegg_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void dbegg_hitDetect(GameObject* obj);
void dbegg_update(GameObject* obj);
void dbegg_init(GameObject* obj);
void dbegg_release(void);
void dbegg_initialise(void);

void dbegg_setupFromDef(GameObject* obj, u8* state);

#endif /* MAIN_DLL_DLL_023F_DBEGG_H_ */
