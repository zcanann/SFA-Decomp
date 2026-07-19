#ifndef MAIN_OBJPRINT_CHARACTER_API_H_
#define MAIN_OBJPRINT_CHARACTER_API_H_

#include "global.h"
#include "main/game_object.h"

typedef struct CharacterEyeAnimState
{
    s8 lookAtActive; /* external look-at request gate */
    u8 pad01[3];
    f32 lookAtPosX;
    f32 lookAtPosY;
    f32 lookAtPosZ;
    f32 headTrackBlend; /* 1.0 -> 0.0 decay */
    s16 headYaw;
    s16 headYawStart; /* lerp source */
    u8 pad18[2];
    s16 headTrackMode;  /* low byte = state 0..6, high byte = far-flag */
    s16 headTrackTimer; /* -= framesThisStep */
    s8 blinkState;
    s8 blinkTimer;
    s8 movementTimer;
    u8 pad21;
    s16 movementStep;
    s32 movementTarget;
} CharacterEyeAnimState;

STATIC_ASSERT(sizeof(CharacterEyeAnimState) == 0x28);
STATIC_ASSERT(offsetof(CharacterEyeAnimState, headYaw) == 0x14);
STATIC_ASSERT(offsetof(CharacterEyeAnimState, headTrackMode) == 0x1A);
STATIC_ASSERT(offsetof(CharacterEyeAnimState, headTrackTimer) == 0x1C);

/* one tracked rotation channel; a joint uses a pair (yaw then pitch, 0x60 total) */
typedef struct ObjJointTrackChannel
{
    u8 pad00[0x14];
    s16 angle;      /* current/target angle */
    s16 angleStart; /* lerp start */
    u8 pad18[0x30 - 0x18];
} ObjJointTrackChannel;

typedef struct ObjJointTrackPair
{
    ObjJointTrackChannel yaw;
    ObjJointTrackChannel pitch;
} ObjJointTrackPair;

STATIC_ASSERT(sizeof(ObjJointTrackChannel) == 0x30);
STATIC_ASSERT(sizeof(ObjJointTrackPair) == 0x60);

void characterDoEyeAnims(GameObject* obj, CharacterEyeAnimState* state);
void fn_8003A230(GameObject* obj, CharacterEyeAnimState* state, f32 scale);
void fn_8003B0D0(GameObject* obj, GameObject* target, CharacterEyeAnimState* state, int maxAngle);
void fn_8003B228(GameObject* obj, void* state);
void fn_8003ADC4(GameObject* obj, void* target, void* state, int limit, u8 inverted, int mode);

#define characterDoEyeAnimsState(obj, state) characterDoEyeAnims((obj), (CharacterEyeAnimState*)(state))

#endif /* MAIN_OBJPRINT_CHARACTER_API_H_ */
