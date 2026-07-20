#ifndef MAIN_DLL_MMP_DLL_0183_MMPGYSERVENT_H_
#define MAIN_DLL_MMP_DLL_0183_MMPGYSERVENT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct MmpGyserventPlacement
{
    ObjPlacement base;
    u8 pad18[0x1E - 0x18];
    s16 disableBit; /* 0x1E: gamebit that switches the vent off */
    u8 unk20;       /* 0x20 */
    u8 pad21[0x3A - 0x21];
    u8 reachScale;
    u8 speed;
    u8 pad3C;
    u8 rotX;
    u8 rotY;
} MmpGyserventPlacement;

STATIC_ASSERT(offsetof(MmpGyserventPlacement, disableBit) == 0x1E);
STATIC_ASSERT(offsetof(MmpGyserventPlacement, reachScale) == 0x3A);
STATIC_ASSERT(offsetof(MmpGyserventPlacement, speed) == 0x3B);
STATIC_ASSERT(offsetof(MmpGyserventPlacement, rotX) == 0x3D);
STATIC_ASSERT(offsetof(MmpGyserventPlacement, rotY) == 0x3E);

int mmp_gyservent_getExtraSize(void);
int mmp_gyservent_getObjectTypeId(void);
void mmp_gyservent_free(void);
void mmp_gyservent_render(void);
void mmp_gyservent_hitDetect(void);
void mmp_gyservent_update(GameObject* obj);
void mmp_gyservent_init(GameObject* obj);
void mmp_gyservent_release(void);
void mmp_gyservent_initialise(void);

extern ObjectDescriptor gMMP_gyserventObjDescriptor;

#endif /* MAIN_DLL_MMP_DLL_0183_MMPGYSERVENT_H_ */
