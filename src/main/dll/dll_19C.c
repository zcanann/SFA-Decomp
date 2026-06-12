#include "main/dll/dll_19C.h"
#include "main/dll/DF/DFlantern.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/obj_placement.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

typedef struct SpiritPrizePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} SpiritPrizePlacement;


extern u32 randomGetRange(int min, int max);
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 SH_LevelControl_runBloopEvent();

extern ScreenTransitionInterface** gScreenTransitionInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern MapEventInterface** gMapEventInterface;
extern f64 DOUBLE_803e5b18;
extern f64 DOUBLE_803e5b28;
extern f32 lbl_803DC074;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5AF4;
extern f32 lbl_803E5B00;
extern f32 lbl_803E5B04;
extern f32 lbl_803E5B08;
extern f32 lbl_803E5B0C;
extern f32 lbl_803E5B10;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B24;
extern f32 lbl_803E5B30;
extern f32 lbl_803E4E88;
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void objRenderFn_8003b8f4(f32 scale);
extern void objParticleFn_80099d84(int* obj, f32 scale1, int kind, f32 scale2, int light);
extern f32 timeDelta;
extern u8 lbl_803DBF60;
extern f64 lbl_803E4E80;
extern f64 lbl_803E4E90;
extern u16 lbl_80325F88[];
extern int Obj_GetPlayerObject(void);
extern void skyFn_80088c94(int skyId, int enable);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern void playerAddRemoveMagic(int player, int amount);
extern void SCGameBitLatch_UpdateInverted(void* latch, int mask, int clearIfSetBit, int setIfClearBit, int gateBit,
                                          int value);
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int setIfClearBit, int gateBit, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void GameBit_Set(int bit, int value);
extern int GameBit_Get(int bit);
extern void Music_Trigger(int musicId, int mode);
extern void gameTimerInit(int timerId, int value);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern int isGameTimerDisabled(void);
extern int ObjList_FindObjectById(int objId);
extern void fn_8014C5C0(int obj);
extern int objGetAnimStateFlags(int obj, int flag);
extern void audioStopByMask(int mask);
extern f32 lbl_803E4E8C;
extern u8 lbl_803DB411;
extern f32 lbl_803E4E9C;
extern f64 lbl_803E4EA0;
extern f64 lbl_803E4EA8;
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern void Obj_FreeObject(int obj);
extern int coordsToMapCell(f32 x, f32 z);

typedef struct DfshShrineState
{
    void* light;
    f32 rewardTimer;
    f32 idleChimeTimer;
    u8 musicLatch[4];
    s16 startDelayFrames;
    s16 transitionTimer;
    u8 pad14[0x1A - 0x14];
    u8 mode;
    u8 rewardIndex;
    u8 flags;
    u8 pad1D[0x20 - 0x1D];
} DfshShrineState;

typedef struct DfshShrinePlacement
{
    ObjPlacement base;
    s8 initialYaw;
    u8 pad19;
    s16 startDelay;
    u8 pad1C[0x24 - 0x1C];
} DfshShrinePlacement;

STATIC_ASSERT(sizeof(DfshShrinePlacement) == 0x24);
STATIC_ASSERT(offsetof(DfshShrinePlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DfshShrinePlacement, startDelay) == 0x1A);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_render
 * EN v1.0 Address: 0x801C2E68
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801C2EC8
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DfshShrineState* state;
    void* light;
    s32 isVisible;

    state = ((GameObject*)obj)->extra;
    isVisible = visible;
    if (isVisible == 0)
    {
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setEnabled((int)light, 0, lbl_803E4E88);
        }
    }
    else
    {
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setEnabled((int)light, 1, lbl_803E4E88);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4E88);
        objParticleFn_80099d84((int*)obj, lbl_803E4E88, 7, *(f32*)&lbl_803E4E88, (int)state->light);
    }
}

#define DFSH_REWARD_BIT(idx) (base[(idx)])
#define DFSH_REWARD_DELAY(idx) (base[10 + (idx)])
#define DFSH_REQUIRED_BIT(idx) (base[20 + (idx)])
#define DFSH_TARGET_OBJECT(idx) (((int *)((u8 *)base + 0x3c))[(idx)])

#define DFSH_SHRINE_FLAG_SUCCESS 0x40
#define DFSH_SHRINE_FLAG_OPENED_BY_SEQUENCE 0x80

void dfsh_shrine_update(int obj)
{
    u16* base = lbl_80325F88;
    int player;
    DfshShrineState* state;
    s16 i;
    u8 anyMissing;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct(obj, player, 0x78, 0);
            getEnvfxAct(obj, player, 0x79, 0);
            getEnvfxAct(obj, player, 0x222, 0);
        }
    }
    fn_801C2914(obj);
    if (lbl_803DBF60 != 0)
    {
        ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
        playerAddRemoveMagic(player, 0x14);
        GameBit_Set(0x1d7, 1);
        lbl_803DBF60 = 0;
    }
    SCGameBitLatch_UpdateInverted(state->musicLatch, 1, -1, -1, 0xcbb, 8);
    SCGameBitLatch_Update(state->musicLatch, 4, -1, -1, 0xcbb, 0xc4);
    if ((f32)(s32)state->transitionTimer > lbl_803E4E8C
    )
    {
        state->transitionTimer = (s16)(s32)((f32)(s32)state->transitionTimer - timeDelta);
        if ((f32)(s32)state->transitionTimer <= lbl_803E4E8C
        )
        {
            state->transitionTimer = 0;
        }
        return;
    }

    switch (state->mode)
    {
    case 0:
        state->idleChimeTimer -= timeDelta;
        if (state->idleChimeTimer <= lbl_803E4E8C)
        {
            Sfx_PlayFromObject(obj, 0x343);
            state->idleChimeTimer = (f32)(s32)
            randomGetRange(500, 1000);
        }
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
        {
            GameBit_Set(0x589, 0);
            state->mode = 5;
            Music_Trigger(0xd8, 1);
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            GameBit_Set(0x129, 0);
        }
        break;
    case 1:
        if ((s8)state->flags < 0)
        {
            state->mode = 2;
            GameBit_Set(0xb76, 1);
            gameTimerInit(0x19, 0xd2);
            timerSetToCountUp();
        }
        break;
    case 2:
        if (state->rewardIndex < 10)
        {
            state->rewardTimer -= timeDelta;
            if (state->rewardTimer <= lbl_803E4E8C)
            {
                GameBit_Set(DFSH_REWARD_BIT(state->rewardIndex), 1);
                state->rewardTimer = (f32)(u32)DFSH_REWARD_DELAY(state->rewardIndex);
                state->rewardIndex++;
            }
        }
        anyMissing = 0;
        for (i = 0; i < 10; i++)
        {
            if (GameBit_Get(DFSH_REQUIRED_BIT(i)) == 0)
            {
                anyMissing = 1;
                i = 10;
            }
        }
        if (anyMissing == 0)
        {
            state->mode = 7;
            state->flags = (state->flags & ~DFSH_SHRINE_FLAG_SUCCESS) | DFSH_SHRINE_FLAG_SUCCESS;
            gameTimerStop();
        }
        else if (isGameTimerDisabled() != 0)
        {
            state->mode = 7;
            state->flags &= ~DFSH_SHRINE_FLAG_SUCCESS;
            state->transitionTimer = 0x78;
            for (i = 0; i < 10; i++)
            {
                int targetId;
                int targetObj;

                targetId = DFSH_TARGET_OBJECT(i);
                if (targetId != -1)
                {
                    targetObj = ObjList_FindObjectById(targetId);
                    if (targetObj != 0)
                    {
                        fn_8014C5C0(targetObj);
                    }
                }
            }
        }
        break;
    case 3:
        if (objGetAnimStateFlags(player, 1) == 0 && GameBit_Get(0xbfd) == 0)
        {
            if (((state->flags >> 6) & 1) == 0)
            {
                state->mode = 4;
                GameBit_Set(0xb70, 1);
            }
            else
            {
                state->mode = 4;
                audioStopByMask(3);
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            }
        }
        else
        {
            state->mode = 4;
        }
        GameBit_Set(0x129, 1);
        GameBit_Set(0xb76, 0);
        break;
    case 4:
        state->mode = 0;
        state->flags &= ~DFSH_SHRINE_FLAG_OPENED_BY_SEQUENCE;
        state->rewardIndex = 0;
        state->rewardTimer = lbl_803E4E8C;
        GameBit_Set(0x129, 1);
        GameBit_Set(0xb70, 0);
        GameBit_Set(0xb71, 0);
        GameBit_Set(0xb76, 0);
        GameBit_Set(0x589, 1);
        for (i = 0; i < 10; i++)
        {
            GameBit_Set(DFSH_REQUIRED_BIT(i), 0);
            GameBit_Set(DFSH_REWARD_BIT(i), 0);
        }
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        break;
    case 5:
        state->transitionTimer = 0x1f;
        (*gScreenTransitionInterface)->step(0x1e, 1);
        state->mode = 1;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    case 6:
        state->mode = 3;
        break;
    case 7:
        state->mode = 6;
        state->transitionTimer = 0x23;
        (*gScreenTransitionInterface)->start(0x1e, 1);
        break;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801c3134
 * EN v1.0 Address: 0x801C3134
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801C321C
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801c3a9c
 * EN v1.0 Address: 0x801C3A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C3ABC
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801c3aa0
 * EN v1.0 Address: 0x801C3AA0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801C3BDC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dfsh_shrine_hitDetect(void)
{
}

void dfsh_shrine_release(void)
{
}

void dfsh_shrine_initialise(void)
{
}

extern int mapGetDirIdx(int id);
extern void unlockLevel(int idx, int a, int b);
extern void* objCreateLight(int* obj, int v);

typedef struct DfshShrineFlags
{
    u8 openedBySequence : 1;
    u8 unused1 : 1;
    u8 unused2 : 1;
    u8 unused3 : 1;
    u8 unused4 : 1;
    u8 unused5 : 1;
    u8 unused6 : 1;
    u8 unused7 : 1;
} DfshShrineFlags;

void dfsh_shrine_init(int* obj, DfshShrinePlacement* init)
{
    DfshShrineState* state;

    state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)(init->initialYaw << 8);
    state->startDelayFrames = 0xa;
    if (init->startDelay > 0)
    {
        state->startDelayFrames = (s16)((s32)init->startDelay >> 8);
    }
    state->mode = 4;
    ((DfshShrineFlags*)&state->flags)->openedBySequence = 0;
    state->transitionTimer = 0;
    ((GameObject*)obj)->animEventCallback = (void*)dfsh_shrine_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    state->rewardIndex = 0;
    state->rewardTimer = lbl_803E4E8C;
    unlockLevel(mapGetDirIdx(0x1f), 1, 0);
    if (state->light == NULL)
    {
        state->light = objCreateLight(NULL, 1);
    }
    ((GameObject*)obj)->unkF4 = 1;
    GameBit_Set(0xe70, 1);
    GameBit_Set(0xefa, 1);
}

void SpiritPrize_hitDetect(void)
{
}

void SpiritPrize_release(void)
{
}

void SpiritPrize_initialise(void)
{
}

extern void ModelLightStruct_free(void* light);

typedef struct SpiritPrizeState
{
    u8 pad00[0x24];
    f32 spawnScale;
    s32 triggerHandle;
    u8 pad2C[0x57 - 0x2C];
    u8 prizeId;
    u8 pad58[0x6A - 0x58];
    s16 mapParam1A;
    u8 pad6C[0x6E - 0x6C];
    s16 targetObjectId;
    u8 pad70[0x81 - 0x70];
    u8 queuedActions[0x8B - 0x81];
    u8 queuedActionCount;
    u8 pad8C[0x140 - 0x8C];
    void* light;
    u8 useDetachedLight;
    u8 pad145[0x148 - 0x145];
    f32 sfxTimer;
} SpiritPrizeState;

void SpiritPrize_free(int obj)
{
    SpiritPrizeState* state;
    void* light;

    state = ((GameObject*)obj)->extra;
    light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
        state->light = NULL;
        state->useDetachedLight = 0;
    }
    (*gObjectTriggerInterface)->freeState((u8*)state);
}

extern void modelLightStruct_setLightKind(void* light, int v);
extern void modelLightStruct_setDiffuseColor(void* light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 a, f32 b);
extern f32 lbl_803E4E98;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EB4;

void SpiritPrize_init(int* obj, u8* init)
{
    SpiritPrizeState* state;

    state = ((GameObject*)obj)->extra;
    if (*(u32*)(init + 0x14) == 0x4ca62) return;
    state->mapParam1A = *(s16*)(init + 0x1a);
    state->targetObjectId = -1;
    state->spawnScale = lbl_803E4E98 / (lbl_803E4E98 + (f32)(u32)
    init[0x24]
    )
    ;
    state->triggerHandle = -1;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        if (*(s16*)(init + 0x18) != 1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, init);
            ((GameObject*)obj)->unkF4 = *(s16*)(init + 0x18) + 1;
        }
    }
    else
    {
        if (*(s16*)(init + 0x18) != ((GameObject*)obj)->unkF4 - 1)
        {
            (*gObjectTriggerInterface)->freeState((u8*)state);
            if (*(s16*)(init + 0x18) != -1)
            {
                (*gObjectTriggerInterface)->loadAnimData((u8*)state, init);
            }
            ((GameObject*)obj)->unkF4 = *(s16*)(init + 0x18) + 1;
        }
    }
    if (((GameObject*)obj)->anim.seqId != 0x1d9)
    {
        state->useDetachedLight = 1;
    }
    if (state->light == NULL)
    {
        state->light = objCreateLight(state->useDetachedLight != 0 ? NULL : obj, 1);
        if (state->light != NULL)
        {
            modelLightStruct_setLightKind(state->light, 2);
            modelLightStruct_setDiffuseColor(state->light, 0x96, 0x32, 0xff, 0xff);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E4EB0, lbl_803E4EB4);
        }
    }
    ((GameObject*)obj)->anim.alpha = 0;
    *(u8*)((char*)obj + 0x37) = 0;
    state->sfxTimer = (f32)(s32)
    randomGetRange(0xb4, 0xf0);
}

void dfsh_objcreator_free(void)
{
}

void dfsh_objcreator_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int SpiritPrize_getExtraSize(void) { return 0x14c; }
int SpiritPrize_getObjectTypeId(void) { return 0x8; }
int dfsh_objcreator_getExtraSize(void) { return 0x4; }
int dfsh_objcreator_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4EB8;

void dfsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4EB8);
}

void SpiritPrize_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritPrizeState* state;
    s32 v;
    state = ((GameObject*)obj)->extra;
    v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4E98);
        if (state->useDetachedLight != 0)
        {
            objParticleFn_80099d84(obj, lbl_803E4E98, 7, *(f32*)&lbl_803E4E98, (int)state->light);
        }
        else
        {
            objParticleFn_80099d84(obj, lbl_803E4E98, 7, *(f32*)&lbl_803E4E98, 0);
        }
    }
}

void SpiritPrize_update(int obj)
{
    u8* params;
    SpiritPrizeState* state;
    int childObj;
    int objectCount;
    int objectIndex;
    int* objects;
    int i;

    params = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (params == NULL || ((SpiritPrizePlacement*)params)->unk18 == -1 || ((SpiritPrizePlacement*)params)->unk14 ==
        0x4ca62)
    {
        return;
    }

    for (i = 0; i < state->queuedActionCount; i++)
    {
        switch (state->queuedActions[i])
        {
        case 1:
            state->useDetachedLight = 0;
            break;
        case 2:
            state->useDetachedLight = 1;
            break;
        }
    }

    objectIndex = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)lbl_803DB411);
    if (objectIndex != 0 && ((GameObject*)obj)->seqIndex == -2)
    {
        int matchingObj;
        int prizeId;
        int duplicateCount;

        prizeId = *(s8*)&((SpiritPrizeState*)state)->prizeId;
        matchingObj = 0;
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        duplicateCount = 0;
        objectIndex = 0;
        while (objectIndex < objectCount)
        {
            childObj = objects[objectIndex];
            if (*(s16*)(childObj + 0xb4) == prizeId)
            {
                matchingObj = childObj;
            }
            if (*(s16*)(childObj + 0xb4) == -2 && *(s16*)(childObj + 0x44) == 0x10 &&
                prizeId == (s8)((SpiritPrizeState*)*(int*)(childObj + 0xb8))->prizeId)
            {
                duplicateCount++;
            }
            objectIndex++;
        }
        if (duplicateCount <= 1 && (void*)matchingObj != NULL && *(s16*)(matchingObj + 0xb4) != -1)
        {
            *(s16*)(matchingObj + 0xb4) = -1;
            (*gObjectTriggerInterface)->endSequence(prizeId);
        }
        ((GameObject*)obj)->seqIndex = -1;
        Obj_FreeObject(obj);
    }

    state->sfxTimer -= timeDelta;
    if (state->sfxTimer < lbl_803E4E9C)
    {
        int player;

        player = Obj_GetPlayerObject();
        state->sfxTimer = (f32)(s32)
        randomGetRange(0xb4, 0xf0);
        if (((GameObject*)obj)->anim.mapEventSlot == -1 &&
            ((void*)player == NULL || coordsToMapCell(*(f32*)(player + 0xc), *(f32*)(player + 0x14)) == 0xb))
        {
            Sfx_PlayFromObject(obj, 0x4a0);
        }
    }
}
