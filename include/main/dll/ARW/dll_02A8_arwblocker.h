#ifndef MAIN_DLL_ARW_DLL_02A8_ARWBLOCKER_H_
#define MAIN_DLL_ARW_DLL_02A8_ARWBLOCKER_H_

#include "main/game_object.h"
#include "global.h"
#include "main/obj_placement.h"

extern f32 lbl_803E7218;
extern f32 lbl_803E721C;
extern f32 lbl_803E7220;

typedef struct ARWBlockerSetup
{
    ObjPlacement base;
    s8 rotZ;
    u8 sequenceMode;
    u8 pad1A[0x24 - 0x1A];
} ARWBlockerSetup;

typedef struct ARWBlockerState
{
    u8 sequenceMode;
    u8 sequenceLocked;
} ARWBlockerState;

STATIC_ASSERT(sizeof(ARWBlockerState) == 0x2);
STATIC_ASSERT(sizeof(ARWBlockerSetup) == 0x24);
STATIC_ASSERT(offsetof(ARWBlockerState, sequenceMode) == 0x00);
STATIC_ASSERT(offsetof(ARWBlockerState, sequenceLocked) == 0x01);
STATIC_ASSERT(offsetof(ARWBlockerSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(ARWBlockerSetup, sequenceMode) == 0x19);

int ARWBlocker_SeqFn(GameObject* obj);
int ARWBlocker_getExtraSize(void);
int ARWBlocker_getObjectTypeId(void);
void ARWBlocker_free(void);
void ARWBlocker_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void ARWBlocker_hitDetect(void);
void ARWBlocker_update(GameObject* obj);
void ARWBlocker_init(GameObject* obj, int setup);
void ARWBlocker_release(void);
void ARWBlocker_initialise(void);

#endif /* MAIN_DLL_ARW_DLL_02A8_ARWBLOCKER_H_ */
