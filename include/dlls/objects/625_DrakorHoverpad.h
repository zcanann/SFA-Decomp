#ifndef DLLS_OBJECTS_625_DRAKORHOVERPAD_H_
#define DLLS_OBJECTS_625_DRAKORHOVERPAD_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/dll/rom_curve_def.h"
#include "main/dll/curve_walker.h"

typedef struct DrakorHoverpadFlags {
    u8 bit80 : 1;
    u8 b40 : 1;
    u8 bit20 : 1;
    u8 state : 4;
    u8 b01 : 1;
} DrakorHoverpadFlags;

typedef struct DrakorHoverpadPathFlags {
    u8 p0 : 1;
    u8 p1 : 1;
    u8 p2 : 1;
    u8 f10 : 1;
    u8 f08 : 1;
    u8 f04 : 1;
    u8 p6 : 1;
    u8 p7 : 1;
} DrakorHoverpadPathFlags;

void drakorhoverpad_resetPendingMotion(GameObject* obj);
int drakorhoverpad_handlePathPointEvent(GameObject* obj, u8 eventCode, u8 subCode, int* out);
int drakorhoverpad_advanceToNextSegment(RomCurveWalker* curve, int maxIndex);

extern f32 gDrakorHoverpadMtx[];
extern f32 gDrakorHoverpadCameraOffsetY;
extern f32 gDrakorHoverpadCameraOffsetZ;
extern f32 gDrakorHoverpadSteerMaxSpeed;
extern s16 gDrakorHoverpadRollScale;

typedef struct DrakorHoverpadPlacement {
    ObjPlacement base;
    s8 rotXByte;
    u8 pad19[0x1a - 0x19];
    s16 unk1a;
    u8 pad1c[0x20 - 0x1c];
    s16 activateGameBit;
    u8 pad22[0x28 - 0x22];
} DrakorHoverpadPlacement;

typedef struct DrakorHoverpadState {
    f32 commandSpeed;
    RomCurveWalker curve; /* 0x004 */
    u8 pad10C[4];
    f32 speed;       /* 0x110 */
    f32 targetSpeed; /* 0x114 */
    f32 unk118;
    f32 unk11C;
    f32 unk120;
    u8 pad124[0x30];
    f32 particleEmitAX; /* 0x154 */
    f32 particleEmitAY; /* 0x158 */
    f32 particleEmitAZ; /* 0x15c */
    f32 particleEmitBX; /* 0x160 */
    f32 particleEmitBY; /* 0x164 */
    f32 particleEmitBZ; /* 0x168 */
    u8 pad16C[4];
    int unk170;
    s16 anglePhase;
    s16 frameCounter;
    DrakorHoverpadFlags flags;         /* 0x178 */
    DrakorHoverpadPathFlags pathFlags; /* 0x179 */
    u8 pad17A[2];
} DrakorHoverpadState;

STATIC_ASSERT(sizeof(DrakorHoverpadState) == 0x17c);
STATIC_ASSERT(offsetof(DrakorHoverpadState, curve) == 0x4);
STATIC_ASSERT(offsetof(DrakorHoverpadState, speed) == 0x110);
STATIC_ASSERT(offsetof(DrakorHoverpadState, flags) == 0x178);
STATIC_ASSERT(offsetof(DrakorHoverpadState, pathFlags) == 0x179);
STATIC_ASSERT(offsetof(DrakorHoverpadPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DrakorHoverpadPlacement, unk1a) == 0x1A);
STATIC_ASSERT(offsetof(DrakorHoverpadPlacement, activateGameBit) == 0x20);

int drakorhoverpad_canMount(GameObject* obj);
int drakorhoverpad_canDismount(GameObject* obj);
void drakorhoverpad_getPlayerAnim(int obj, f32* outFloat, int* outFlag);
void drakorhoverpad_getRiderPosition(GameObject* obj, f32* ox, f32* oy, f32* oz);
f32 drakorhoverpad_getNormalizedSpeed(int obj, f32* out);
void drakorhoverpad_free(GameObject* obj);
void drakorhoverpad_getLookTargetYaw(GameObject* obj, int sel, int* out);
void drakorhoverpad_getCameraPosition(GameObject* obj, f32* ox, f32* oy, f32* oz);
void drakorhoverpad_handleRiderScale(GameObject* obj, f32 scale);
int drakorhoverpad_getExtraSize(void);
int drakorhoverpad_getObjectTypeId(void);
void drakorhoverpad_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible);
void drakorhoverpad_hitDetect(void);
void drakorhoverpad_updateMain(GameObject* obj);
void drakorhoverpad_initMain(GameObject* obj, void* desc);
void drakorhoverpad_release(void);
void drakorhoverpad_initialise(void);
int drakorhoverpad_updateDirection(GameObject* obj);

#define DRAKORHOVERPAD_OBJGROUP 0x46

void drakorhoverpad_resetToRomListPosition(void);
int drakorhoverpad_getRacePosition(void);
void drakorhoverpad_setMountState(void);
int drakorhoverpad_getMountState(void);
int drakorhoverpad_getDismountSide(void);
int drakorhoverpad_getMountSide(void);
int drakorhoverpad_pickMaskedNextPoint(RomCurveDef* pad, int exclude, int maxIndex);
int drakorhoverpad_pickUnmaskedNextPoint(RomCurveDef* pad, int exclude, int maxIndex);

extern ObjectDescriptor24 gDrakorHoverPadObjDescriptor;

#endif /* DLLS_OBJECTS_625_DRAKORHOVERPAD_H_ */
