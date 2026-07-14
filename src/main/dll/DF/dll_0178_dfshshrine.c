/*
 * DragonRock Shrine lantern (DLL 0x178; "DFSH_Shrine") - the shrine's
 * floating lantern object: it orbits and sways (sin-driven), animates its
 * model light, and once activated triggers the level unlock, music change
 * and screen transition.
 */
#include "main/mapEvent.h"
#include "main/dll/objfx_api.h"
#include "main/game_timer_control_api.h"
#include "main/sky_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/object_render_legacy.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/model_light.h"
#include "main/vecmath.h"
#include "main/render.h"
#include "main/gamebit_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/object_api.h"
#include "main/dll/DF/DFlantern.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/obj_list.h"
#include "main/obj_message.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/object_descriptor.h"

u8 gDfShShrinePendingReward = 1;

typedef struct DFlanternShrineState
{
    ModelLightStruct* light;
    u8 pad04[0x14 - 0x04];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad1a[0x1c - 0x1a];
    u8 flags;
} DFlanternShrineState;

typedef struct LanternFlagBits
{
    u8 on : 1;
    u8 rest : 7;
} LanternFlagBits;

typedef struct DfshShrineState
{
    ModelLightStruct* light;
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

STATIC_ASSERT(sizeof(DfshShrinePlacement) == 0x24);
STATIC_ASSERT(offsetof(DfshShrinePlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DfshShrinePlacement, startDelay) == 0x1A);

#define DFSHSHRINE_MAP_SHRINE 0xb

/* shrine-lantern state machine (state->mode) */
#define DFSH_SHRINE_ENVFX_A 0x78
#define DFSH_SHRINE_ENVFX_B 0x79
#define DFSH_SHRINE_ENVFX_C 0x222

#define DFSHRINE_MODE_IDLE          0 /* orbit/chime; wait for player activation */
#define DFSHRINE_MODE_AWAIT_OPEN    1 /* wait for the open sequence to finish */
#define DFSHRINE_MODE_GRANT_REWARDS 2 /* timed reward-bit granting loop */
#define DFSHRINE_MODE_POST_FINISH   3 /* run success/fail follow-up, then reset */
#define DFSHRINE_MODE_RESET         4 /* clear latches/bits, return to idle */
#define DFSHRINE_MODE_BEGIN_TRANS   5 /* start the intro screen transition */
#define DFSHRINE_MODE_AFTER_FINISH  6 /* one frame after the finish transition */
#define DFSHRINE_MODE_FINISH        7 /* start the finishing screen transition */

#define DFSH_REWARD_BIT(idx)    (base[0][(idx)])
#define DFSH_REWARD_DELAY(idx)  (base[0][10 + (idx)])
#define DFSH_REQUIRED_BIT(idx)  (((u16*)((u8*)base[0] + 40))[(idx)])
#define DFSH_TARGET_OBJECT(idx) (((int*)((u8*)base[0] + 0x3c))[(idx)])

#define DFSH_FLAGS(state) ((DfshShrineFlagsBits*)&(state)->flags)

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
extern u8 gDfShShrinePendingReward;
u16 gDfShShrineRewardTable[50] = {
    246, 2997,  247, 2998,  248,  249,   250,  251,   2995, 2996,  60,   60,    60,   60,    600,   600,   600,
    600, 600,   600, 3000,  3008, 3001,  3009, 3002,  3003, 3004,  3005, 3006,  3007, 4,     36948, 4,     37071,
    4,   37054, 4,   37083, 4,    37063, 4,    37065, 4,    37066, 4,    37067, 4,    37068, 4,     37070,
};
extern const f32 lbl_803E4E8C;

extern void objSetAnimStateFlags(void* obj, int arg, int enable);
extern void playerAddRemoveMagic(int obj, int amount);
extern int objGetAnimStateFlags(int obj, int flag);

void fn_801C2914(int obj)
{
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
    player = (u8*)Obj_GetPlayerObject();
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
        lbl_803E4E5C + (((ObjPlacement*)def)->posY + mathSinf((gDfShShrinePi * state->orbitA) / lbl_803E4E64));

    trigA = mathSinf((gDfShShrinePi * state->orbitB) / lbl_803E4E64);
    trigB = mathSinf((gDfShShrinePi * state->orbitA) / lbl_803E4E64);
    trigB = trigB + trigA;
    ((GameObject*)obj)->anim.rotZ = lbl_803E4E68 * trigB;

    trigA = mathSinf((gDfShShrinePi * state->orbitC) / lbl_803E4E64);
    trigB = mathSinf((gDfShShrinePi * state->orbitA) / lbl_803E4E64);
    trigB = trigB + trigA;
    ((GameObject*)obj)->anim.rotY = lbl_803E4E68 * trigB;

    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E4E6C, timeDelta,
                                                                 (ObjAnimEventList*)animEvents);
    if (player != NULL)
    {
        angleDelta = ((u16)getAngle(((GameObject*)obj)->anim.worldPosX - ((GameObject*)player)->anim.worldPosX,
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

        distance = Vec_xzDistance((f32*)(obj + 0x18), (f32*)(player + 0x18));
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

int DFSH_Shrine_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int objLocal;
    DFlanternShrineState* state;
    u8* player;
    int i;
    u8 cmd;

    objLocal = obj;
    state = (DFlanternShrineState*)((GameObject*)objLocal)->extra;
    player = (u8*)Obj_GetPlayerObject();
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
                objSetAnimStateFlags(player, 1, 1);
                mainSetBits(GAMEBIT_ITEM_TestCombatSpirit_Got, 1);
                mainSetBits(GAMEBIT_FlewToPlanet, 1);
                (*gMapEventInterface)->setMapAct(DFSHSHRINE_MAP_SHRINE, 2);
                break;
            case 0xe:
                ((GameObject*)objLocal)->anim.flags = (s16)(((GameObject*)objLocal)->anim.flags | OBJANIM_FLAG_HIDDEN);
                if (state->light != NULL)
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4E88);
                }
                break;
            case 0xf:
                ((GameObject*)objLocal)->anim.flags = (s16)(((GameObject*)objLocal)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
                if (state->light != NULL)
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4E88);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

int DFSH_Shrine_getExtraSize(void)
{
    return 0x20;
}

int DFSH_Shrine_getObjectTypeId(void)
{
    return 0;
}

void DFSH_Shrine_free(GameObject* obj)
{
    ModelLightStruct** state;

    state = obj->extra;
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
    mainSetBits(GAMEBIT_ECSH_InShrine, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, 1);
}

void DFSH_Shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DfshShrineState* state;
    ModelLightStruct* light;
    s32 isVisible;

    state = ((GameObject*)obj)->extra;
    isVisible = visible;
    if (isVisible == 0)
    {
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setEnabled(light, 0, lbl_803E4E88);
        }
    }
    else
    {
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setEnabled(light, 1, lbl_803E4E88);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4E88);
        objParticleFn_80099d84((GameObject*)obj, lbl_803E4E88, 7, *(f32*)&lbl_803E4E88,
                               (ModelLightStruct*)state->light);
    }
}

void DFSH_Shrine_update(int objArg);
void DFSH_Shrine_hitDetect(void);
void DFSH_Shrine_release(void);
void DFSH_Shrine_initialise(void);
void DFSH_Shrine_init(int* obj, DfshShrinePlacement* init);

ObjectDescriptor gDFSH_ShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFSH_Shrine_initialise,
    (ObjectDescriptorCallback)DFSH_Shrine_release,
    0,
    (ObjectDescriptorCallback)DFSH_Shrine_init,
    (ObjectDescriptorCallback)DFSH_Shrine_update,
    (ObjectDescriptorCallback)DFSH_Shrine_hitDetect,
    (ObjectDescriptorCallback)DFSH_Shrine_render,
    (ObjectDescriptorCallback)DFSH_Shrine_free,
    (ObjectDescriptorCallback)DFSH_Shrine_getObjectTypeId,
    DFSH_Shrine_getExtraSize,
};

void DFSH_Shrine_update(int objArg)
{

    u16* base[1];
    DfshShrineState* state;
    int player;
    s16 i;
    u8 anyMissing;
    u16* required;
    GameObject* obj = (GameObject*)objArg;

    base[0] = gDfShShrineRewardTable;
    state = obj->extra;
    player = (int)Obj_GetPlayerObject();
    if (obj->unkF4 != 0)
    {
        obj->unkF4 = obj->unkF4 - 1;
        if (obj->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxActInt((int)obj, player, DFSH_SHRINE_ENVFX_A, 0);
            getEnvfxActInt((int)obj, player, DFSH_SHRINE_ENVFX_B, 0);
            getEnvfxActInt((int)obj, player, DFSH_SHRINE_ENVFX_C, 0);
        }
    }
    fn_801C2914((int)obj);
    if (gDfShShrinePendingReward != 0)
    {
        obj->anim.worldPosX = obj->anim.localPosX;
        obj->anim.worldPosY = obj->anim.localPosY;
        obj->anim.worldPosZ = obj->anim.localPosZ;
        playerAddRemoveMagic(player, 0x14);
        mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);
        gDfShShrinePendingReward = 0;
    }
    SCGameBitLatch_UpdateInverted((SCGameBitLatchState*)state->musicLatch, 1, -1, -1, 0xcbb, 8);
    SCGameBitLatch_Update((SCGameBitLatchState*)state->musicLatch, 4, -1, -1, 0xcbb, 0xc4);
    if ((f32)(s32)state->transitionTimer > lbl_803E4E8C)
    {
        state->transitionTimer = (f32)(s32)state->transitionTimer - timeDelta;
        if ((f32)(s32)state->transitionTimer <= lbl_803E4E8C)
        {
            state->transitionTimer = 0;
        }
        return;
    }

    switch (state->mode)
    {
    case DFSHRINE_MODE_IDLE:
    {
        f32 t = state->idleChimeTimer - timeDelta;
        state->idleChimeTimer = t;
        if (t <= lbl_803E4E8C)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_spirit_voice);
            state->idleChimeTimer = (f32)(s32)randomGetRange(500, 1000);
        }
    }
        if ((*(u8*)&obj->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            mainSetBits(0x589, 0);
            state->mode = DFSHRINE_MODE_BEGIN_TRANS;
            Music_Trigger(MUSICTRIG_DIM_Snow, 1);
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
        }
        break;
    case DFSHRINE_MODE_BEGIN_TRANS:
        state->transitionTimer = 0x1f;
        (*gScreenTransitionInterface)->step(0x1e, 1);
        state->mode = DFSHRINE_MODE_AWAIT_OPEN;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    case DFSHRINE_MODE_AWAIT_OPEN:
        if (DFSH_FLAGS(state)->openedBySequence == 1)
        {
            state->mode = DFSHRINE_MODE_GRANT_REWARDS;
            mainSetBits(0xb76, 1);
            gameTimerInit(0x19, 0xd2);
            timerSetToCountUp();
        }
        break;
    case DFSHRINE_MODE_GRANT_REWARDS:
        if (state->rewardIndex < 10)
        {
            state->rewardTimer -= timeDelta;
            if (state->rewardTimer <= lbl_803E4E8C)
            {
                mainSetBits(DFSH_REWARD_BIT(state->rewardIndex), 1);
                state->rewardTimer = (f32)(u32)DFSH_REWARD_DELAY(state->rewardIndex);
                state->rewardIndex++;
            }
        }
        anyMissing = 0;
        for (i = 0; i < 10; i++)
        {
            if (mainGetBit(*(u16*)((u8*)&base[0][20] + i * 2)) == 0u)
            {
                anyMissing = 1;
                i = 10;
            }
        }
        if (anyMissing == 0)
        {
            state->mode = DFSHRINE_MODE_FINISH;
            DFSH_FLAGS(state)->success = 1;
            gameTimerStop();
        }
        else if (isGameTimerDisabled() != 0)
        {
            state->mode = DFSHRINE_MODE_FINISH;
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
                        fn_8014C5C0((GameObject*)targetObj);
                    }
                }
            }
        }
        break;
    case DFSHRINE_MODE_FINISH:
        state->mode = DFSHRINE_MODE_AFTER_FINISH;
        state->transitionTimer = 0x23;
        (*gScreenTransitionInterface)->start(0x1e, 1);
        break;
    case DFSHRINE_MODE_AFTER_FINISH:
        state->mode = DFSHRINE_MODE_POST_FINISH;
        break;
    case DFSHRINE_MODE_POST_FINISH:
        if (objGetAnimStateFlags(player, 1) != 0 || mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0u)
        {
            state->mode = DFSHRINE_MODE_RESET;
        }
        else if (DFSH_FLAGS(state)->success == 0)
        {
            state->mode = DFSHRINE_MODE_RESET;
            mainSetBits(0xb70, 1);
        }
        else
        {
            state->mode = DFSHRINE_MODE_RESET;
            audioStopByMask(3);
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
        mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
        mainSetBits(0xb76, 0);
        break;
    case DFSHRINE_MODE_RESET:
        state->mode = DFSHRINE_MODE_IDLE;
        DFSH_FLAGS(state)->openedBySequence = 0;
        state->rewardIndex = 0;
        state->rewardTimer = lbl_803E4E8C;
        mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
        mainSetBits(0xb70, 0);
        mainSetBits(0xb71, 0);
        mainSetBits(0xb76, 0);
        mainSetBits(0x589, 1);
        {
            s16 j;
            for (j = 0, required = (u16*)((u8*)base[0] + 40); j < 10; j++)
            {
                mainSetBits(*required, 0);
                mainSetBits(*base[0], 0);
                required++;
                base[0]++;
            }
        }
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        break;
    }
}

void DFSH_Shrine_hitDetect(void)
{
}

void DFSH_Shrine_release(void)
{
}

void DFSH_Shrine_initialise(void)
{
}

void DFSH_Shrine_init(int* obj, DfshShrinePlacement* init)
{
    DfshShrineState* state;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(init->initialYaw << 8);
    state->startDelayFrames = 0xa;
    if (init->startDelay > 0)
    {
        state->startDelayFrames = (s16)((s32)init->startDelay >> 8);
    }
    state->mode = DFSHRINE_MODE_RESET;
    ((DfshShrineFlags*)&state->flags)->openedBySequence = 0;
    state->transitionTimer = 0;
    ((GameObject*)obj)->animEventCallback = DFSH_Shrine_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    state->rewardIndex = 0;
    state->rewardTimer = lbl_803E4E8C;
    unlockLevel(mapGetDirIdx(0x1f), 1, 0);
    if (state->light == NULL)
    {
        state->light = objCreateLight(NULL, 1);
    }
    ((GameObject*)obj)->unkF4 = 1;
    mainSetBits(GAMEBIT_MMP_EnteredKrazoaShrine, 1);
    mainSetBits(GAMEBIT_ECSH_InShrine, 1);
}
