#ifndef MAIN_DLL_WC_DLL_0292_WCTREXSTATU_H
#define MAIN_DLL_WC_DLL_0292_WCTREXSTATU_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct WCTrexStatueSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[0x1E - 0x1A];
    s16 raisedBit;
    u8 pad20[0x24 - 0x20];
} WCTrexStatueSetup;

STATIC_ASSERT(sizeof(WCTrexStatueSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTrexStatueSetup, type) == 0x18);
STATIC_ASSERT(offsetof(WCTrexStatueSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCTrexStatueSetup, raisedBit) == 0x1E);

extern ObjectDescriptor gWCTrexStatuObjDescriptor;
extern f32 lbl_803E6E10;
extern f32 lbl_803E6E14;

int wctrexstatu_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int wctrexstatu_getExtraSize(void);
int wctrexstatu_getObjectTypeId(GameObject* obj);
void wctrexstatu_free(void);
void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctrexstatu_hitDetect(GameObject* obj);
void wctrexstatu_update(void);
void wctrexstatu_init(GameObject* obj, WCTrexStatueSetup* setup, int fromLoad);
void wctrexstatu_release(void);
void wctrexstatu_initialise(void);

#endif /* MAIN_DLL_WC_DLL_0292_WCTREXSTATU_H */
