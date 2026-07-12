#ifndef MAIN_DLL_DLL_0294_WCTEMPLE_H
#define MAIN_DLL_DLL_0294_WCTEMPLE_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct WCTempleSetup
{
    ObjPlacement base;
    s8 type;
    u8 pad19[0x24 - 0x19];
} WCTempleSetup;

typedef struct WCTempleState
{
    f32 timer;
    u8 triggerSlot;
    u8 pad05[3];
} WCTempleState;

STATIC_ASSERT(sizeof(WCTempleState) == 8);
STATIC_ASSERT(sizeof(WCTempleSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTempleState, timer) == 0x00);
STATIC_ASSERT(offsetof(WCTempleState, triggerSlot) == 0x04);
STATIC_ASSERT(offsetof(WCTempleSetup, type) == 0x18);

extern ObjectDescriptor gWCTempleObjDescriptor;
extern f32 lbl_803E6E20;
extern f32 lbl_803E6E24;

int wctemple_getExtraSize(void);
int wctemple_getObjectTypeId(void);
void wctemple_free(void);
void wctemple_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemple_hitDetect(void);
void wctemple_update(GameObject* obj);
void wctemple_init(GameObject* obj, WCTempleSetup* setup);
void wctemple_release(void);
void wctemple_initialise(void);

#endif /* MAIN_DLL_DLL_0294_WCTEMPLE_H */
