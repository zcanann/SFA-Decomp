#ifndef MAIN_DLL_DLL_0266_KYTESMUM_H_
#define MAIN_DLL_DLL_0266_KYTESMUM_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_internal.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/objprint.h"

typedef int (*KytesMumUpdateCallback)(int obj);

typedef struct KytesMumMoveSet
{
    s16 moves[6];
} KytesMumMoveSet;

typedef struct KytesMumSetup
{
    ObjPlacement base;
    s8 yaw;
    s8 mode;
    s16 interactionRange;
    u8 pad1C[0x1e - 0x1c];
    s16 completionGameBit;
    u8 pad20[0x24 - 0x20];
} KytesMumSetup;

typedef struct KytesMumRuntime
{
    u8 pad000[0x654];
    u8 eyeAnimState[0x684 - 0x654];
    ObjSoundState modelSoundState;
    u8 animEvents[0x6d0 - 0x6b4];
    ObjSoundDef* idleSfxTable;
    KytesMumUpdateCallback updateCallback;
    s16* eventSfxTable;
    KytesMumMoveSet* moveSet;
    f32 animSpeed;
    s16 idleSfxTimer;
    u8 questComplete;
} KytesMumRuntime;

typedef struct KytesMumObject
{
    union
    {
        ObjAnimComponent anim;
        struct
        {
            s16 yaw;
            u8 pad02[0x4c - 0x2];
            KytesMumSetup* setup;
            u8 pad50[0xa0 - 0x50];
            s16 currentMove;
            u8 padA2[0xaf - 0xa2];
            u8 flagsAF;
        };
    };
    u16 objectFlags;
    u8 padB2[0xb8 - 0xb2];
    KytesMumRuntime* runtime;
    void* interactionCallback;
} KytesMumObject;

STATIC_ASSERT(sizeof(KytesMumSetup) == 0x24);
STATIC_ASSERT(offsetof(KytesMumSetup, yaw) == 0x18);
STATIC_ASSERT(offsetof(KytesMumSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(KytesMumSetup, interactionRange) == 0x1A);
STATIC_ASSERT(offsetof(KytesMumSetup, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(KytesMumObject, anim) == 0x00);
STATIC_ASSERT(offsetof(KytesMumObject, yaw) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(KytesMumObject, setup) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(KytesMumObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(KytesMumObject, flagsAF) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(KytesMumObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(KytesMumObject, runtime) == 0xB8);
STATIC_ASSERT(offsetof(KytesMumObject, interactionCallback) == 0xBC);

int kytesmum_getExtraSize(void);
int kytesmum_getObjectTypeId(void);
void kytesmum_hitDetect(void);
void kytesmum_initialise(void);
void kytesmum_release(void);
void kytesmum_update(GameObject* obj);
int kytesmum_idleCallback(void);
void kytesmum_render(void* obj, int p2, int p3, int p4, int p5, char visible);
void kytesmum_free(int obj);
int kytesmum_spawnInteractionCallback(GameObject* obj);
int kytesmum_updateInteractionRangeCallback(GameObject* obj, int unused, u8* arg);
int kytesmum_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate);
void kytesmum_init(GameObject* obj, KytesMumSetup* setup);
int kytesmum_updateNearPlayerCallback(GameObject* obj, int unused, u8* arg);
int kytesmum_updateQuestStateCallback(GameObject* obj, int unused, u8* arg);
void kytesmum_playAnimationEventSfx(int obj, u8* arg, s16* sfxData);

#endif /* MAIN_DLL_DLL_0266_KYTESMUM_H_ */
