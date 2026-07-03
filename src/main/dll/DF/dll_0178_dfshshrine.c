/*
 * DragonRock Shrine lantern (DLL 0x178; "DFSH_Shrine") - the shrine's
 * floating lantern object: it orbits and sways (sin-driven), animates its
 * model light, and once activated triggers the level unlock, music change
 * and screen transition.
 */
#include "main/mapEvent.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/DF/DFlantern.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
extern void objRenderFn_8003b8f4(int* obj);
extern void ModelLightStruct_free(void* light);
extern void gameTimerStop(void);
extern int mapGetDirIdx(int idx);
extern int unlockLevel(s32 val, int idx, int flag);
extern void Music_Trigger(int id, int arg);
extern void fn_80296518(void* obj, int arg, int enable);
extern int getAngle(float y, float x);
extern f32 Vec_xzDistance(void* a, void* b);
extern float mathSinf(float x);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
extern f32 timeDelta;
extern f32 lbl_803E4E50;
extern f32 lbl_803E4E54;
extern f32 lbl_803E4E58;
extern f32 lbl_803E4E5C;
extern f32 gDfShShrinePi;
extern f32 lbl_803E4E64;
extern f32 lbl_803E4E68;
extern f32 lbl_803E4E6C;
extern f32 lbl_803E4E70;
extern f32 gDfShShrineFadeDistance;
extern f32 lbl_803E4E78;
extern f32 lbl_803E4E88;

typedef struct DFlanternShrineState
{
    void* light;
    u8 pad04[0x14 - 0x04];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad1a[0x1c - 0x1a];
    u8 flags;
} DFlanternShrineState;

extern int randomGetRange(int lo, int hi);
extern void objParticleFn_80099d84(int* obj, f32 scale1, int kind, f32 scale2, int light);
extern u8 gDfShShrinePendingReward;
extern u16 gDfShShrineRewardTable[];
extern void skyFn_80088c94(int flags, int mode);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void playerAddRemoveMagic(int obj, int amount);
extern void SCGameBitLatch_UpdateInverted(void* latch, int mask, int clearIfSetBit, int setIfClearBit, int gateBit,
                                          int value);
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int setIfClearBit, int gateBit, int value);

extern void gameTimerInit(s8 flags, int minutes);
extern void timerSetToCountUp(void);
extern int isGameTimerDisabled(void);
extern void* ObjList_FindObjectById(int objId);
extern void fn_8014C5C0(void* obj);
extern int objGetAnimStateFlags(int obj, int flag);
extern void audioStopByMask(int mask);
extern const f32 lbl_803E4E8C;
extern void* objCreateLight(int* obj, int v);

void fn_801C2914(int obj)
{
    extern u8* Obj_GetPlayerObject(void);
    int def;
    DFlanternShrineState* state;
    u8* player;
    f32 trigA;
    f32 trigB;
    f32 distance;
    int angleDelta;
    int turnStep;
    u8 animEvents[32];

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        ((GameObject*)obj)->anim.rotX = 0;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        return;
    }

    state->orbitA += (s32)(lbl_803E4E50 * timeDelta);
    state->orbitB += (s32)(lbl_803E4E54 * timeDelta);
    state->orbitC += (s32)(lbl_803E4E58 * timeDelta);

    ((GameObject*)obj)->anim.localPosY =
        lbl_803E4E5C +
        (((ObjPlacement*)def)->posY +
            mathSinf((gDfShShrinePi * state->orbitA) / lbl_803E4E64));

    trigA = mathSinf((gDfShShrinePi * state->orbitB) / lbl_803E4E64);
    trigB = mathSinf((gDfShShrinePi * state->orbitA) / lbl_803E4E64);
    trigB = trigB + trigA;
    ((GameObject*)obj)->anim.rotZ = lbl_803E4E68 * trigB;

    trigA = mathSinf((gDfShShrinePi * state->orbitC) / lbl_803E4E64);
    trigB = mathSinf((gDfShShrinePi * state->orbitA) / lbl_803E4E64);
    trigB = trigB + trigA;
    ((GameObject*)obj)->anim.rotY = lbl_803E4E68 * trigB;

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E4E6C, timeDelta,
                                                                 (ObjAnimEventList*)animEvents);
    if (player != NULL)
    {
        angleDelta =
        ((u16)getAngle(((GameObject*)obj)->anim.worldPosX - ((GameObject*)player)->anim.worldPosX,
                       ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)player)->anim.worldPosZ) -
            ((u16)((GameObject*)obj)->anim.rotX));
        if (angleDelta > 0x8000)
        {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xffff;
        }
        turnStep = (s32)(((f32)angleDelta * timeDelta) / lbl_803E4E70);
        ((GameObject*)obj)->anim.rotX += turnStep;

        distance = Vec_xzDistance((void*)(obj + 0x18), player + 0x18);
        if (distance <= gDfShShrineFadeDistance)
        {
            ((GameObject*)obj)->anim.alpha = (u8)(s32)(lbl_803E4E78 * (distance / gDfShShrineFadeDistance));
        }
        else
        {
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
    }
}

typedef struct LanternFlagBits
{
    u8 on : 1;
    u8 rest : 7;
} LanternFlagBits;

int dfsh_shrine_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern u8* Obj_GetPlayerObject(void);
    int objLocal;
    DFlanternShrineState* state;
    u8* player;
    int i;
    u8 cmd;

    objLocal = obj;
    state = (DFlanternShrineState*)((GameObject*)objLocal)->extra;
    player = Obj_GetPlayerObject();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        cmd = animUpdate->eventIds[i];
        if (cmd != 0)
        {
            switch (cmd)
            {
            case 3:
                ((LanternFlagBits*)&state->flags)->on = 1;
                break;
            case 7:
                fn_80296518(player, 1, 1);
                GameBit_Set(0xbfd, 1);
                GameBit_Set(0x956, 1);
                (*gMapEventInterface)->setMapAct(0xb, 2);
                break;
            case 0xe:
                ((GameObject*)objLocal)->anim.flags = (s16)(((GameObject*)objLocal)->anim.flags | OBJANIM_FLAG_HIDDEN);
                if (state->light != NULL)
                {
                    modelLightStruct_setEnabled((int)state->light, 0, lbl_803E4E88);
                }
                break;
            case 0xf:
                ((GameObject*)objLocal)->anim.flags = (s16)(((GameObject*)objLocal)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
                if (state->light != NULL)
                {
                    modelLightStruct_setEnabled((int)state->light, 0, lbl_803E4E88);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

int dfsh_shrine_getExtraSize(void)
{
    return 0x20;
}

int dfsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void dfsh_shrine_free(int obj)
{
    void** state;

    state = ((GameObject*)obj)->extra;
    if (*state != NULL)
    {
        ModelLightStruct_free(*state);
        *state = NULL;
    }
    gameTimerStop();
    unlockLevel(mapGetDirIdx(0x1f), 1, 0);
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
}

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
#define DFSH_REQUIRED_BIT(idx) (((u16 *)((u8 *)base + 40))[(idx)])
#define DFSH_TARGET_OBJECT(idx) (((int *)((u8 *)base + 0x3c))[(idx)])

typedef struct DfshShrineFlagsBits
{
    u8 openedBySequence : 1;
    u8 success : 1;
    u8 b2 : 1;
    u8 b3 : 1;
    u8 b4 : 1;
    u8 b5 : 1;
    u8 b6 : 1;
    u8 b7 : 1;
} DfshShrineFlagsBits;

#define DFSH_FLAGS(state) ((DfshShrineFlagsBits*)&(state)->flags)

void dfsh_shrine_update(int objArg)
{

    extern int Obj_GetPlayerObject(void);
    u16* base;
    DfshShrineState* state;
    int player;
    s16 i;
    u8 anyMissing;
    u16* required;
    GameObject* obj = (GameObject*)objArg;

    base = gDfShShrineRewardTable;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (obj->unkF4 != 0)
    {
        obj->unkF4 = obj->unkF4 - 1;
        if (obj->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct((int)obj, player, 0x78, 0);
            getEnvfxAct((int)obj, player, 0x79, 0);
            getEnvfxAct((int)obj, player, 0x222, 0);
        }
    }
    fn_801C2914((int)obj);
    if (gDfShShrinePendingReward != 0)
    {
        obj->anim.worldPosX = obj->anim.localPosX;
        obj->anim.worldPosY = obj->anim.localPosY;
        obj->anim.worldPosZ = obj->anim.localPosZ;
        playerAddRemoveMagic(player, 0x14);
        GameBit_Set(0x1d7, 1);
        gDfShShrinePendingReward = 0;
    }
    SCGameBitLatch_UpdateInverted(state->musicLatch, 1, -1, -1, 0xcbb, 8);
    SCGameBitLatch_Update(state->musicLatch, 4, -1, -1, 0xcbb, 0xc4);
    if ((f32)(s32)state->transitionTimer > lbl_803E4E8C
    )
    {
        state->transitionTimer = (f32)(s32)state->transitionTimer - timeDelta;
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
        {
            f32 t = state->idleChimeTimer - timeDelta;
            state->idleChimeTimer = t;
            if (t <= lbl_803E4E8C)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_spirit_voice);
                state->idleChimeTimer = (f32)(s32)
                randomGetRange(500, 1000);
            }
        }
        if ((*(u8*)&obj->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            GameBit_Set(0x589, 0);
            state->mode = 5;
            Music_Trigger(MUSICTRIG_DIM_Snow, 1);
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            GameBit_Set(0x129, 0);
        }
        break;
    case 5:
        state->transitionTimer = 0x1f;
        (*gScreenTransitionInterface)->step(0x1e, 1);
        state->mode = 1;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    case 1:
        if (DFSH_FLAGS(state)->openedBySequence == 1)
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
            if (GameBit_Get(*(u16*)((u8*)&base[20] + i * 2)) == 0u)
            {
                anyMissing = 1;
                i = 10;
            }
        }
        if (anyMissing == 0)
        {
            state->mode = 7;
            DFSH_FLAGS(state)->success = 1;
            gameTimerStop();
        }
        else if (isGameTimerDisabled() != 0)
        {
            state->mode = 7;
            DFSH_FLAGS(state)->success = 0;
            state->transitionTimer = 0x78;
            for (i = 0; i < 10; i++)
            {
                int targetId;
                void* targetObj;

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
    case 7:
        state->mode = 6;
        state->transitionTimer = 0x23;
        (*gScreenTransitionInterface)->start(0x1e, 1);
        break;
    case 6:
        state->mode = 3;
        break;
    case 3:
        if (objGetAnimStateFlags(player, 1) != 0 || GameBit_Get(0xbfd) != 0u)
        {
            state->mode = 4;
        }
        else if (DFSH_FLAGS(state)->success == 0)
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
        GameBit_Set(0x129, 1);
        GameBit_Set(0xb76, 0);
        break;
    case 4:
        state->mode = 0;
        DFSH_FLAGS(state)->openedBySequence = 0;
        state->rewardIndex = 0;
        state->rewardTimer = lbl_803E4E8C;
        GameBit_Set(0x129, 1);
        GameBit_Set(0xb70, 0);
        GameBit_Set(0xb71, 0);
        GameBit_Set(0xb76, 0);
        GameBit_Set(0x589, 1);
        required = (u16*)((u8*)base + 40);
        for (i = 0; i < 10; i++)
        {
            GameBit_Set(*required, 0);
            GameBit_Set(*base, 0);
            required++;
            base++;
        }
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        break;
    }
}

void dfsh_shrine_hitDetect(void)
{
}

void dfsh_shrine_release(void)
{
}

void dfsh_shrine_initialise(void)
{
}

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
    ((GameObject*)obj)->anim.rotX = (s16)(init->initialYaw << 8);
    state->startDelayFrames = 0xa;
    if (init->startDelay > 0)
    {
        state->startDelayFrames = (s16)((s32)init->startDelay >> 8);
    }
    state->mode = 4;
    ((DfshShrineFlags*)&state->flags)->openedBySequence = 0;
    state->transitionTimer = 0;
    ((GameObject*)obj)->animEventCallback = dfsh_shrine_SeqFn;
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

void SpiritPrize_hitDetect(void);
