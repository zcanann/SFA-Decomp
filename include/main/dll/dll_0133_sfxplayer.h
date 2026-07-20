#ifndef MAIN_DLL_DLL_0133_SFXPLAYER_H_
#define MAIN_DLL_DLL_0133_SFXPLAYER_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

#define SFXPLAYER_OBJECT_FLAGS 0x6000
#define SFXPLAYER_MODE_GAMEBIT 0
#define SFXPLAYER_MODE_LOOPED 1
#define SFXPLAYER_MODE_RANDOM_DELAY 2
#define SFXPLAYER_RUNTIME_ACTIVE_FLAG 0x01

typedef struct SfxplayerObjState
{
    union
    {
        int gameBitState;
        f32 delayTimer;
    };
    u8 flags;
    u8 pad05[3];
} SfxplayerObjState;

typedef struct SfxplayerPlacement
{
    ObjPlacement base;
    s16 gameBit;
    u16 primarySfxId;
    u8 flags;
    u8 mode;
    u8 randomDelayMin;
    u8 randomDelayMax;
    s8 romCurveChannel;
    u8 pad21;
    u16 secondarySfxId;
} SfxplayerPlacement;

STATIC_ASSERT(offsetof(SfxplayerObjState, flags) == 0x04);
STATIC_ASSERT(sizeof(SfxplayerObjState) == 0x08);
STATIC_ASSERT(offsetof(SfxplayerPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(SfxplayerPlacement, primarySfxId) == 0x1A);
STATIC_ASSERT(offsetof(SfxplayerPlacement, flags) == 0x1C);
STATIC_ASSERT(offsetof(SfxplayerPlacement, mode) == 0x1D);
STATIC_ASSERT(offsetof(SfxplayerPlacement, randomDelayMin) == 0x1E);
STATIC_ASSERT(offsetof(SfxplayerPlacement, romCurveChannel) == 0x20);
STATIC_ASSERT(offsetof(SfxplayerPlacement, secondarySfxId) == 0x22);
STATIC_ASSERT(sizeof(SfxplayerPlacement) == 0x24);

#define SFXPLAYER_FLAG_FORCE_POINT      0x1
#define SFXPLAYER_FLAG_TRIGGER_ON_SET   0x2
#define SFXPLAYER_FLAG_TRIGGER_ON_CLEAR 0x4
#define SFXPLAYER_FLAG_ROM_CURVE        0x8
#define SFXPLAYER_FLAG_AT_OBJECT        0x10

void sfxplayerObj_init(GameObject* obj, SfxplayerPlacement* placement);
void sfxplayerObj_free(GameObject* obj);
void sfxplayerObj_update(GameObject* obj);
int sfxplayerObj_getExtraSize(void);

extern ObjectDescriptor gSfxplayerObjDescriptor;

#endif /* MAIN_DLL_DLL_0133_SFXPLAYER_H_ */
