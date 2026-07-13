#ifndef MAIN_OBJPRINT_SOUND_API_H_
#define MAIN_OBJPRINT_SOUND_API_H_

#include "global.h"
#include "main/game_object.h"

typedef struct ObjSoundState
{
    u8 active;
    u8 pad01[3];
    f32 blendWeight;
    u8 pad08[4];
    f32 timer;
    u8 pad10[4];
    s16 pitch;
    u8 pad16[0x1a];
} ObjSoundState;

typedef struct ObjSoundDef
{
    s16 sfxId;
    s16 pitch;
    u8 blendCount;
    u8 pad05;
} ObjSoundDef;

STATIC_ASSERT(sizeof(ObjSoundState) == 0x30);
STATIC_ASSERT(offsetof(ObjSoundState, timer) == 0x0c);
STATIC_ASSERT(offsetof(ObjSoundState, pitch) == 0x14);
STATIC_ASSERT(sizeof(ObjSoundDef) == 6);

void objAudioFn_80039270(u32 obj, void* state, u16 sfxId);
void objAudioFn_800393f8(GameObject* obj, ObjSoundState* state, u16 sfx, int pitch, int volume, u8 force);
void objSoundFn_800392f0(GameObject* obj, ObjSoundState* state, ObjSoundDef* soundDef, u8 force);
void fn_80039264(s32* state);
void objModelAndSoundFn_80039118(int obj, int state);

#define objAudioFn_800393f8Legacy(obj, state, sfx, pitch, volume, force)                                         \
    ((void (*)(GameObject*, ObjSoundState*, int, int, int, int))objAudioFn_800393f8)(                             \
        (GameObject*)(obj), (ObjSoundState*)(state), (sfx), (pitch), (volume), (force))

#endif /* MAIN_OBJPRINT_SOUND_API_H_ */
