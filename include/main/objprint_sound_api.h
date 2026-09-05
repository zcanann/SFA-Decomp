#ifndef MAIN_OBJPRINT_SOUND_API_H_
#define MAIN_OBJPRINT_SOUND_API_H_

#include "global.h"
#include "game/objects/object.h"

typedef struct ObjSoundState
{
    s8 justStarted; /* skip the first mouth-update playback check after starting a sound */
    u8 pad01[3];
    f32 blendWeight;
    u8 pad08[4];
    f32 timer;
    u8 pad10[4];
    s16 mouthAngle; /* signed rotation target for the mouth joint, not audio pitch */
    u8 pad16[0x1a];
} ObjSoundState;

typedef struct ObjSoundDef
{
    s16 sfxId;
    s16 mouthOpenAngle;
    u8 blendCount;
    u8 pad05;
} ObjSoundDef;

typedef struct ObjKfAnimState
{
    s32 frame;
    s32 frameCount;
    f32 timer;
    f32 timerStep;
    int* keyframes;
    u16 sfxId;
} ObjKfAnimState;

STATIC_ASSERT(sizeof(ObjSoundState) == 0x30);
STATIC_ASSERT(offsetof(ObjSoundState, justStarted) == 0);
STATIC_ASSERT(offsetof(ObjSoundState, timer) == 0x0c);
STATIC_ASSERT(offsetof(ObjSoundState, mouthAngle) == 0x14);
STATIC_ASSERT(sizeof(ObjSoundDef) == 6);
STATIC_ASSERT(offsetof(ObjSoundDef, mouthOpenAngle) == 2);
STATIC_ASSERT(sizeof(ObjKfAnimState) == 0x18);
STATIC_ASSERT(offsetof(ObjKfAnimState, keyframes) == 0x10);
STATIC_ASSERT(offsetof(ObjKfAnimState, sfxId) == 0x14);

void objSoundStart(GameObject* obj, void* state, u16 sfxId);
void objSoundStartTimed(GameObject* obj, ObjSoundState* state, u16 sfx, int mouthOpenAngle, int duration, u8 force);
void objSoundStartFromDef(GameObject* obj, ObjSoundState* state, ObjSoundDef* soundDef, u8 force);
void objKfAnimStop(ObjKfAnimState* state);
void objKfAnimUpdate(GameObject* obj, ObjKfAnimState* state);

#endif /* MAIN_OBJPRINT_SOUND_API_H_ */
