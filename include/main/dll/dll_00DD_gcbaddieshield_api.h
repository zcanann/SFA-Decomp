#ifndef MAIN_DLL_DLL_00DD_GCBADDIESHIELD_API_H_
#define MAIN_DLL_DLL_00DD_GCBADDIESHIELD_API_H_

#include "types.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct GCbaddieShieldPlacement
{
    ObjPlacement base;
    s16 unk18;
    s16 lifetime;
} GCbaddieShieldPlacement;

typedef struct GCbaddieShieldState
{
    f32 remainingLifetime;
    u32 unk4;
} GCbaddieShieldState;

STATIC_ASSERT(sizeof(GCbaddieShieldPlacement) == 0x1C);
STATIC_ASSERT(offsetof(GCbaddieShieldPlacement, lifetime) == 0x1A);
STATIC_ASSERT(sizeof(GCbaddieShieldState) == 0x8);

extern ObjectDescriptor gGCbaddieShieldObjDescriptor;

void GCbaddieShield_free(void);
int GCbaddieShield_getExtraSize(void);
int GCbaddieShield_getObjectTypeId(void);
void GCbaddieShield_hitDetect(void);
void GCbaddieShield_init(GameObject* obj, GCbaddieShieldPlacement* placement);
void GCbaddieShield_initialise(void);
void GCbaddieShield_release(void);
void GCbaddieShield_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void GCbaddieShield_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_00DD_GCBADDIESHIELD_API_H_ */
