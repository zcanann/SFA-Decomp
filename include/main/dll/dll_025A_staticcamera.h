#ifndef MAIN_DLL_DLL_025A_STATICCAMERA_H_
#define MAIN_DLL_DLL_025A_STATICCAMERA_H_

#include "global.h"
#include "main/game_object.h"

typedef struct StaticCameraState
{
    u8 setupParam; /* 0x00: from placement byte 0x19 */
    u8 unk1;       /* 0x01: cleared at init */
    u8 pad2[2];
    f32 unk4; /* 0x04: placement byte 0x1a as float */
} StaticCameraState;

typedef struct StaticCameraPlacement
{
    u8 pad00[0x19];
    u8 setupParam; /* 0x19 */
    u8 unkByte1A;  /* 0x1A: stored into extra as float */
    u8 pad1B;
    s16 rotX; /* 0x1C: negated into anim.rotX */
    s16 rotY; /* 0x1E: negated into anim.rotY */
    s16 rotZ; /* 0x20: negated into anim.rotZ */
} StaticCameraPlacement;

STATIC_ASSERT(offsetof(StaticCameraPlacement, setupParam) == 0x19);
STATIC_ASSERT(offsetof(StaticCameraPlacement, unkByte1A) == 0x1A);
STATIC_ASSERT(offsetof(StaticCameraPlacement, rotX) == 0x1C);
STATIC_ASSERT(offsetof(StaticCameraPlacement, rotY) == 0x1E);
STATIC_ASSERT(offsetof(StaticCameraPlacement, rotZ) == 0x20);

int StaticCamera_getExtraSize(void);
int StaticCamera_getObjectTypeId(void);
void StaticCamera_free(int obj);
void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void StaticCamera_hitDetect(void);
void StaticCamera_update(void);
void StaticCamera_init(GameObject* obj, StaticCameraPlacement* params, int deferAdd);
void StaticCamera_release(void);
void StaticCamera_initialise(void);

#endif /* MAIN_DLL_DLL_025A_STATICCAMERA_H_ */
