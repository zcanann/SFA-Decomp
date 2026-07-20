#ifndef MAIN_DLL_MMP_MMP_BARREL_H_
#define MAIN_DLL_MMP_MMP_BARREL_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_internal.h"
#include "main/obj_placement.h"

extern ObjectDescriptor14 gWaveAnimatorObjDescriptor;
extern ObjectDescriptor gAlphaAnimatorObjDescriptor;
extern ObjectDescriptor14 gGroundAnimatorObjDescriptor;
extern ObjectDescriptor gHitAnimatorObjDescriptor;

#define HITANIMATOR_DLL_ID            0x0139
#define HITANIMATOR_CLASS_ID          0x004B
#define HITANIMATOR_DEF_ID            0x04BC
#define HITANIMATOR_OBJECT_DEF_BYTES  0xA0
#define HITANIMATOR_PLACEMENT_BYTES   0x20
#define HITANIMATOR_EXTRA_STATE_BYTES 0x04

#define HITANIMATOR_SETUP_FLAG_INITIAL_INVERT 0x01
#define HITANIMATOR_SETUP_FLAG_AFFECT_SHADERS 0x02
#define HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE   0x04
#define HITANIMATOR_SETUP_FLAG_SOUND          0x08
#define HITANIMATOR_SETUP_FLAG_SKIP_POLYS     0x10

#define HITANIMATOR_STATE_FLAG_TOGGLE_PENDING       0x01
#define HITANIMATOR_STATE_FLAG_SOUND_PENDING        0x02
#define HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING 0x04

#define HITANIMATOR_OBJECT_FLAGS_ENABLED 0x6000

typedef struct HitAnimatorPlacement
{
    ObjPlacement head;
    s16 gameBit;
    u8 toggleMode;
    u8 blockEffectId;
    u8 flags;
    u8 soundId;
    u8 pad1E[HITANIMATOR_PLACEMENT_BYTES - 0x1E];
} HitAnimatorPlacement;

typedef struct HitAnimatorState
{
    s8 activeBit;
    u8 flags;
    u8 gameBitValue;
    u8 previousGameBitValue;
} HitAnimatorState;

typedef struct HitAnimatorObject
{
    ObjAnimComponent objAnim;
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    HitAnimatorState* state;
} HitAnimatorObject;

STATIC_ASSERT(sizeof(HitAnimatorPlacement) == HITANIMATOR_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(HitAnimatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(HitAnimatorPlacement, toggleMode) == 0x1A);
STATIC_ASSERT(offsetof(HitAnimatorPlacement, blockEffectId) == 0x1B);
STATIC_ASSERT(offsetof(HitAnimatorPlacement, flags) == 0x1C);
STATIC_ASSERT(offsetof(HitAnimatorPlacement, soundId) == 0x1D);
STATIC_ASSERT(sizeof(HitAnimatorState) == HITANIMATOR_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(HitAnimatorState, activeBit) == 0x00);
STATIC_ASSERT(offsetof(HitAnimatorState, flags) == 0x01);
STATIC_ASSERT(offsetof(HitAnimatorState, gameBitValue) == 0x02);
STATIC_ASSERT(offsetof(HitAnimatorState, previousGameBitValue) == 0x03);
STATIC_ASSERT(offsetof(HitAnimatorObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(HitAnimatorObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(HitAnimatorObject, state) == 0xB8);

#define WALLANIMATOR_DONE_TIMER 3000

void waveanimator_modelMtxFn(GameObject* obj, int a, int b, int c);
void waveanimator_func0B(int* obj);
void waveanimator_setScale(int* obj, f32 fval);
int waveanimator_getExtraSize(void);
int waveanimator_getObjectTypeId(void);
void waveanimator_free(int* obj);
void waveanimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void waveanimator_hitDetect(int* obj);
void waveanimator_update(void);
void waveanimator_init(int* obj, int* desc);
void waveanimator_release(void);
void waveanimator_initialise(void);

int AlphaAnimator_getExtraSize(void);
int AlphaAnimator_getObjectTypeId(void);
void AlphaAnimator_free(int* obj);
void AlphaAnimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void AlphaAnimator_hitDetect(void);
void AlphaAnimator_update(int* obj);
void AlphaAnimator_init(int* obj);
void AlphaAnimator_release(void);
void AlphaAnimator_initialise(void);

u8 groundanimator_modelMtxFn(int* obj);
u8 groundanimator_isFullySunk(int* obj);
f32 groundanimator_setScale(int* obj, int* target);
int groundanimator_getExtraSize(void);
void groundanimator_free(int* obj, int flag);
void groundanimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void groundanimator_update(int* obj);
void groundanimator_init(int* obj, int* desc);

int HitAnimator_getExtraSize(void);
void HitAnimator_update(HitAnimatorObject* obj);
void HitAnimator_init(HitAnimatorObject* obj, HitAnimatorPlacement* desc);

#endif /* MAIN_DLL_MMP_MMP_BARREL_H_ */
