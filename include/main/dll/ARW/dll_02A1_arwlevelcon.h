#ifndef MAIN_DLL_ARW_DLL_02A1_ARWLEVELCON_H
#define MAIN_DLL_ARW_DLL_02A1_ARWLEVELCON_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objseq.h"

typedef union ARWLevelConSetup
{
    ObjPlacement base;
    struct
    {
        u8 pad00[0x14];
        int routeSignature;
    };
} ARWLevelConSetup;

typedef struct ARWLevelConState
{
    f32 sequenceParam0;
    f32 sequenceParam1;
    f32 sequenceParam2;
    f32 sequenceParam3;
    u8 pad10[4];
    s16 sequenceSlot;
    s16 sequenceCameraId;
    u8 skyConfigured;
    u8 sequenceStarted;
    u8 ringChoiceTriggered;
    u8 alternateRoute;
    int streamId;
    u16 ringChoiceTriggerId;
    u8 pad22[2];
} ARWLevelConState;

STATIC_ASSERT(sizeof(ARWLevelConSetup) == 0x18);
STATIC_ASSERT(offsetof(ARWLevelConSetup, routeSignature) == 0x14);
STATIC_ASSERT(sizeof(ARWLevelConState) == 0x24);
STATIC_ASSERT(offsetof(ARWLevelConState, sequenceSlot) == 0x14);
STATIC_ASSERT(offsetof(ARWLevelConState, sequenceCameraId) == 0x16);
STATIC_ASSERT(offsetof(ARWLevelConState, skyConfigured) == 0x18);
STATIC_ASSERT(offsetof(ARWLevelConState, sequenceStarted) == 0x19);
STATIC_ASSERT(offsetof(ARWLevelConState, ringChoiceTriggered) == 0x1A);
STATIC_ASSERT(offsetof(ARWLevelConState, alternateRoute) == 0x1B);
STATIC_ASSERT(offsetof(ARWLevelConState, streamId) == 0x1C);
STATIC_ASSERT(offsetof(ARWLevelConState, ringChoiceTriggerId) == 0x20);

extern ObjectDescriptor gARWLevelConObjDescriptor;
extern f32 lbl_803E70E0;
extern f32 lbl_803E70E4;
extern f32 lbl_803E70E8;
extern f32 lbl_803E70EC;
extern f32 lbl_803E70F0;
extern f32 lbl_803E70F4;

void arwlevelcon_onSeqFree(GameObject* obj);
int arwlevelcon_SeqFn(GameObject* obj, int unused, ObjSeqState* seq);
int arwlevelcon_getExtraSize(void);
int arwlevelcon_getObjectTypeId(void);
void arwlevelcon_free(void);
void arwlevelcon_render(int obj, int p2, int p3, int p4, int p5);
void arwlevelcon_hitDetect(void);
void arwlevelcon_update(GameObject* obj);
void arwlevelcon_init(GameObject* obj, ARWLevelConSetup* setup);
void arwlevelcon_release(void);
void arwlevelcon_initialise(void);

#endif /* MAIN_DLL_ARW_DLL_02A1_ARWLEVELCON_H */
