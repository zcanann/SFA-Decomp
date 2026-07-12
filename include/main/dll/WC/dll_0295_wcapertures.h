#ifndef MAIN_DLL_WC_DLL_0295_WCAPERTURES_H
#define MAIN_DLL_WC_DLL_0295_WCAPERTURES_H

#include "global.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct WCAperturesSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[4];
    s16 openBit;
    s16 armBit;
    u8 pad22[2];
} WCAperturesSetup;

typedef struct WCAperturesState
{
    ModelLight* light;
    s16 targetAlpha;
    u8 mode;
    u8 flags;
} WCAperturesState;

STATIC_ASSERT(sizeof(WCAperturesState) == 8);
STATIC_ASSERT(sizeof(WCAperturesSetup) == 0x24);
STATIC_ASSERT(offsetof(WCAperturesState, light) == 0x00);
STATIC_ASSERT(offsetof(WCAperturesState, targetAlpha) == 0x04);
STATIC_ASSERT(offsetof(WCAperturesState, mode) == 0x06);
STATIC_ASSERT(offsetof(WCAperturesState, flags) == 0x07);
STATIC_ASSERT(offsetof(WCAperturesSetup, type) == 0x18);
STATIC_ASSERT(offsetof(WCAperturesSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCAperturesSetup, openBit) == 0x1E);
STATIC_ASSERT(offsetof(WCAperturesSetup, armBit) == 0x20);

extern ObjectDescriptor gWCApertureSObjDescriptor;
extern f32 lbl_803E6E28;
extern f32 lbl_803E6E2C;
extern f32 lbl_803E6E30;
extern f32 lbl_803E6E34;
extern f32 lbl_803E6E38;
extern f32 lbl_803E6E3C;
extern f32 lbl_803E6E40;

int wcapertures_getExtraSize(void);
int wcapertures_getObjectTypeId(GameObject* obj);
void wcapertures_free(GameObject* obj);
void wcapertures_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wcapertures_hitDetect(GameObject* obj);
void wcapertures_release(void);
void wcapertures_initialise(void);
int wcapertures_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void wcapertures_init(GameObject* obj, WCAperturesSetup* setup);
void wcapertures_update(GameObject* obj);

#endif /* MAIN_DLL_WC_DLL_0295_WCAPERTURES_H */
