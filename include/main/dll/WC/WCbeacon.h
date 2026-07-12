#ifndef MAIN_DLL_WC_WCBEACON_H_
#define MAIN_DLL_WC_WCBEACON_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct WCBeaconSetup
{
    ObjPlacement base;
    s8 type;
    s8 modelIndex;
    u8 pad1A[4];
    s16 solvedBit;
    s16 armBit;
    u8 pad22[2];
} WCBeaconSetup;

typedef struct WCBeaconState
{
    f32 timer;
    u8 phase;
    u8 acceptedInteraction;
    u8 pad06[2];
} WCBeaconState;

STATIC_ASSERT(sizeof(WCBeaconState) == 8);
STATIC_ASSERT(sizeof(WCBeaconSetup) == 0x24);
STATIC_ASSERT(offsetof(WCBeaconState, timer) == 0x00);
STATIC_ASSERT(offsetof(WCBeaconState, phase) == 0x04);
STATIC_ASSERT(offsetof(WCBeaconState, acceptedInteraction) == 0x05);
STATIC_ASSERT(offsetof(WCBeaconSetup, type) == 0x18);
STATIC_ASSERT(offsetof(WCBeaconSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCBeaconSetup, solvedBit) == 0x1E);
STATIC_ASSERT(offsetof(WCBeaconSetup, armBit) == 0x20);

extern ObjectDescriptor gWCBeaconObjDescriptor;
extern f32 lbl_803E6DE0;
extern f32 lbl_803E6DE4;
extern f32 lbl_803E6DE8;

int wcbeacon_aButtonCallback(GameObject* obj);
int wcbeacon_getExtraSize(void);
int wcbeacon_getObjectTypeId(GameObject* obj);
void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcbeacon_init(GameObject* obj, WCBeaconSetup* setup);
void wcbeacon_update(GameObject* obj);

#endif /* MAIN_DLL_WC_WCBEACON_H_ */
