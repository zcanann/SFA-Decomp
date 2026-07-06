/*
 * DLL 0x18F - ECSH Krazoa Spirit Shrine: the "Test of Observation". ("ECSH" is
 * the retail prefix for this shrine - one of the MMSH/ECSH/DFSH/DBSH/GPSH Krazoa
 * shrine family; the "EC" area code is unidentified, so it's left undecoded.)
 *
 * This is a 3-round cup shell-game. The Krazoa Spirit hides in one of 6 cups
 * (the golden urns; the cup objects themselves are DLL 0x190 ECSH_Cup). Each
 * round the cups shuffle around the player - faster and with more shuffle
 * patterns each round - and the player walks up to a cup to make their guess.
 * A wrong guess teleports the player out; a correct guess advances to the next
 * round; 3 correct guesses in a row obtains the spirit (sets
 * GAMEBIT_K1_SPIRIT_COLLECTED via anim-event 7 in ecsh_shrine_SeqFn).
 *
 * Drives the floating shrine object: a bobbing model that orbits/wobbles
 * toward the player (ecsh_shrine_updateMotion) and fades with distance, plus its
 * anim-event callback (ecsh_shrine_SeqFn) which reacts to torch signals, sets camera vars, and
 * toggles the model light.
 *
 * ecsh_shrine_update is the main state machine. The puzzle working set lives in
 * a shared scratch buffer (EcshPuzzleState at gEcShShrinePuzzleState - the 6
 * cups' (x,z) positions plus current/next slot->cup maps that are rotated or
 * swapped per shuffle step). It sequences the screen transitions, object
 * sequences and looping SFX as the test advances through its phases.
 *
 * Helpers, all reaching the active instance through the gEcShShrineActiveObject
 * singleton: ecsh_shrine_getPhaseAndSpiritCup (outputs animState + spiritCup),
 * ecsh_shrine_checkCupPick (the PICK CHECK: sets matchFlag = guess==spiritCup,
 * called from ecsh_cup_update), ecsh_shrine_getCupPos / ecsh_shrine_setCupPos
 * (read/write a cup's (x,z) via the slot->cup map gEcShShrineCupSlotMap), plus
 * modelMtxFn and setScale.
 *
 * The DLL owns a cluster of GameBits set on init/free/transition (0xefa,
 * 0xcbb, 0xa7f, 0xb9d, 0x129, 0x143, ...). It also reads the entrance-intro
 * trigger GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER (0x58b), set by the shrine's
 * entrance trigger volume, and on the first frame it sees it set plays the
 * "found your way into a KRAZOA SHRINE" dialogue (0x285), latching
 * introTextLatch (live-verified; it is NOT a torch signal).
 */
#include "main/game_object.h"
#include "main/dll/mmshrineanimobj_struct.h"
#include "main/objseq.h"
#include "main/dll/mmshrine/ecsh_shrine_state.h"
#include "main/dll/mmshrine/ecsh_shrine.h"
#include "main/game_ui_interface.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"

extern void ecsh_creator_getExtraSize(void);
extern void gpsh_shrine_getExtraSize(void);

extern void ecsh_creator_getObjectTypeId(void);
extern void gpsh_shrine_getObjectTypeId(void);

extern void ecsh_creator_free(void);
extern void gpsh_shrine_free(void);

extern void ecsh_creator_render(void);
extern void gpsh_shrine_render(void);

extern void ecsh_creator_hitDetect(void);
extern void gpsh_shrine_hitDetect(void);

extern void ecsh_creator_update(void);
extern void gpsh_shrine_update(void);

extern void ecsh_creator_init(void);
extern void gpsh_shrine_init(void);

extern void ecsh_creator_release(void);
extern void gpsh_shrine_release(void);

extern void ecsh_creator_initialise(void);
extern void gpsh_shrine_initialise(void);

#define ECSHSHRINE_OBJGROUP 0xb

typedef struct EcshIntPair
{
    int a;
    int b;
} EcshIntPair;


extern f32 Vec_xzDistance(f32* a, f32* b);

extern f32 gEcShShrineOrbitSpeedA;
extern f32 gEcShShrineOrbitSpeedB;
extern f32 gEcShShrineOrbitSpeedC;
extern f32 lbl_803E4F9C;
extern f32 gEcShShrinePi;
extern f32 gEcShShrineAngleUnitScale;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FAC;
extern f32 lbl_803E4FB0;
extern f32 gEcShShrineFadeDistance;
extern f32 gEcShShrineFadeAlphaMax;
extern f32 lbl_803E4FC8;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;
extern f32 lbl_803E4FD4;
extern f32 lbl_803E4FD8;
extern f32 lbl_803E4FDC;
extern f32 lbl_803E4FE0;
extern f32 lbl_803E4FE4;
extern f32 lbl_803E4FE8;
extern f32 lbl_803E4FEC;
extern f32 lbl_803E4FF0;
extern int lbl_803DDBC0;
extern EcshIntPair lbl_803E8470;
extern void Music_Trigger(int id, int arg);
extern void ModelLightStruct_free(void* p);
extern int objCreateLight(int a, int b);
extern void skyFn_80088c94(int flags, int mode);
extern void getEnvfxAct(s16* obj, int* target, int id, int p);
extern int objIsCurModelNotZero(void* obj);
extern void fn_80295CF4(int* player, int a);
extern void SCGameBitLatch_Update(u8* latch, int mask, int a, int b, int bit, int c);
extern void SCGameBitLatch_UpdateInverted(u8* latch, int mask, int a, int b, int bit, int c);
extern void audioStopByMask(int mask);
extern int objGetAnimStateFlags(int* player, int flags);
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
extern void Sfx_PlayFromObject(s16* obj, int sfxId);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(void* obj, int group);
extern int ObjMsg_Pop(void* obj, int* msg, int* a, int* b);
extern void ObjMsg_AllocQueue(void* obj, int capacity);

typedef struct MmShrineAnimState
{
    int light;
    u8 pad04[0x24];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad2E[0x2];
    u8 hasTorchSignal;
} MmShrineAnimState;

typedef struct MmShrineAnimEvents
{
    u8 pad00[0x56];
    u8 eventStatus;
    u8 pad57[0x19];
    s16 eventModel;
    u8 pad72[0xF];
    u8 events[10];
    u8 eventCount;
} MmShrineAnimEvents;

typedef struct EcshRenderPair
{
    f32 a;
    f32 b;
} EcshRenderPair;

/*
 * The shell-game working set: the 6 cups' (x,z) positions (see EcshPuzzleState
 * in ecsh_shrine_update - the slot->cup maps that follow it in memory are
 * gEcShShrineCupSlotMap below).
 */
EcshRenderPair gEcShShrinePuzzleState[6] = { 0 };

/* Current slot->cup index map for the 6 cups, followed by next round's map. */
s16 gEcShShrineCupSlotMap[] = {
    0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5,
};

/* descriptor/ptr table auto 0x80326250-0x8032629C */
u32 gECSH_ShrineObjDescriptor[19] = { 0x00000000, 0x00000000, 0x00000000, 0x000e0000, (u32)ecsh_shrine_initialise, (u32)ecsh_shrine_release, 0x00000000, (u32)ecsh_shrine_init, (u32)ecsh_shrine_update, (u32)ecsh_shrine_hitDetect, (u32)ecsh_shrine_render, (u32)ecsh_shrine_free, (u32)ecsh_shrine_getObjectTypeId, (u32)ecsh_shrine_getExtraSize, (u32)ecsh_shrine_setScale, (u32)ecsh_shrine_getCupPos, (u32)ecsh_shrine_getPhaseAndSpiritCup, (u32)ecsh_shrine_setCupPos, (u32)ecsh_shrine_checkCupPick };

void ecsh_shrine_updateMotion(MmShrineAnimObj* obj)
{
    extern int getAngle(float y, float x);
    u8* config;
    MmShrineAnimState* state;
    void* player;
    f32 trigA;
    f32 trigB;
    f32 distance;
    s32 angleDelta;
    ObjAnimEventList animEvents;

    config = obj->config;
    state = (MmShrineAnimState*)obj->state;
    player = Obj_GetPlayerObject();

    if ((obj->flags & MMSHRINE_FLAG_POSE_LOCKED) != 0)
    {
        obj->yaw = 0;
        obj->posY = *(f32*)(config + 0xC);
        return;
    }

    state->orbitA = (s16)(state->orbitA + (s32)(gEcShShrineOrbitSpeedA * timeDelta));
    state->orbitB = (s16)(state->orbitB + (s32)(gEcShShrineOrbitSpeedB * timeDelta));
    state->orbitC = (s16)(state->orbitC + (s32)(gEcShShrineOrbitSpeedC * timeDelta));

    obj->posY = lbl_803E4F9C +
    (*(f32*)(config + 0xC) +
        mathSinf((gEcShShrinePi * state->orbitA) / gEcShShrineAngleUnitScale));

    trigA = mathSinf((gEcShShrinePi * state->orbitB) / gEcShShrineAngleUnitScale);
    trigB = mathSinf((gEcShShrinePi * state->orbitA) / gEcShShrineAngleUnitScale);
    trigB = trigB + trigA;
    obj->roll = lbl_803E4FA8 * trigB;

    trigA = mathSinf((gEcShShrinePi * state->orbitC) / gEcShShrineAngleUnitScale);
    trigB = mathSinf((gEcShShrinePi * state->orbitA) / gEcShShrineAngleUnitScale);
    trigB = trigB + trigA;
    obj->pitch = lbl_803E4FA8 * trigB;

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4FAC, timeDelta,
                                                                 &animEvents);

    if (player != NULL)
    {
        angleDelta = (u16)getAngle(obj->posX - ((GameObject*)player)->anim.worldPosX,
                                   obj->posZ - ((GameObject*)player)->anim.worldPosZ) -
            (u16)obj->yaw;
        if (angleDelta > 0x8000)
        {
            angleDelta -= 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xFFFF;
        }

        obj->yaw = (s16)(*(s16*)(int)&obj->yaw + (s32)(((f32)angleDelta * timeDelta) / lbl_803E4FB0));
        distance = Vec_xzDistance((f32*)((int)&obj->posX), (f32*)((int)player + 0x18));
        if (distance <= gEcShShrineFadeDistance)
        {
            obj->fadeAlpha = (u8)(s32)(gEcShShrineFadeAlphaMax * (distance / gEcShShrineFadeDistance));
        }
        else
        {
            obj->fadeAlpha = 0xFF;
        }
    }
}

int ecsh_shrine_SeqFn(void* objArg, int unused, void* eventListArg)
{
    extern void fn_80296518(void* obj, int arg, int enable);
    extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
    MmShrineAnimObj* obj;
    MmShrineAnimState* state;
    MmShrineAnimEvents* eventList;
    void* player;
    int i;
    u8 event;

    (void)unused;
    obj = (MmShrineAnimObj*)objArg;
    eventList = (MmShrineAnimEvents*)eventListArg;
    state = (MmShrineAnimState*)obj->state;
    player = Obj_GetPlayerObject();
    eventList->eventModel = -1;
    eventList->eventStatus = 0;

    for (i = 0; i < eventList->eventCount; i++)
    {
        event = eventList->events[i];
        if (event != 0)
        {
            switch (event)
            {
            case 3:
                state->hasTorchSignal = 1;
                break;
            case 7:
                fn_80296518(player, 8, 1);
                GameBit_Set(0x143, 1);
                GameBit_Set(GAMEBIT_K1_SPIRIT_COLLECTED, 1);
                break;
            case 13:
                (*gObjectTriggerInterface)->setCamVars(0x48, 100, 0, 0x50);
                break;
            case 14:
                obj->flags |= MMSHRINE_FLAG_POSE_LOCKED;
                if ((void*)state->light != NULL)
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4FC8);
                }
                break;
            case 15:
                obj->flags &= ~MMSHRINE_FLAG_POSE_LOCKED;
                if ((void*)state->light != NULL)
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4FC8);
                }
                break;
            }
        }
        eventList->events[i] = 0;
    }

    return 0;
}

void ecsh_shrine_getPhaseAndSpiritCup(int* outAnimState, u8* outSpiritCup)
{
    extern int gEcShShrineActiveObject;
    int* obj = (int*)gEcShShrineActiveObject;
    int* inner;
    if (obj == NULL) return;
    inner = ((GameObject*)obj)->extra;
    *outSpiritCup = ((EcshShrineState*)inner)->spiritCup;
    *outAnimState = ((EcshShrineState*)inner)->animState;
}

void ecsh_shrine_checkCupPick(u8 cupIndex)
{
    extern int gEcShShrineActiveObject;
    int* obj = (int*)gEcShShrineActiveObject;
    int* inner;
    if (obj == NULL) return;
    inner = ((GameObject*)obj)->extra;
    if ((u32)(u8)cupIndex == ((EcshShrineState*)inner)->spiritCup)
    {
        ((EcshShrineState*)inner)->matchFlag = 1;
    }
    else
    {
        ((EcshShrineState*)inner)->matchFlag = 0;
    }
}

void ecsh_shrine_setCupPos(u8 cupIndex, f32 x, f32 z)
{
    extern int gEcShShrineActiveObject;
    int slot;
    if ((int*)gEcShShrineActiveObject == NULL) return;
    slot = gEcShShrineCupSlotMap[cupIndex];
    gEcShShrinePuzzleState[slot].a = x;
    gEcShShrinePuzzleState[slot].b = z;
}

void ecsh_shrine_getCupPos(u8 cupIndex, f32* outX, f32* outZ)
{
    extern void* gEcShShrineActiveObject;
    int slot;
    if (gEcShShrineActiveObject == NULL) return;
    slot = gEcShShrineCupSlotMap[cupIndex];
    *outX = *(f32*)((char*)gEcShShrinePuzzleState + slot * 8);
    slot = gEcShShrineCupSlotMap[cupIndex];
    *outZ = *(f32*)((char*)gEcShShrinePuzzleState + slot * 8 + 4);
}

void ecsh_shrine_setScale(s16* out)
{
    extern void* gEcShShrineActiveObject;
    int* obj = gEcShShrineActiveObject;
    int* state;
    if (obj == NULL) return;
    state = ((GameObject*)obj)->extra;
    *out = ((EcshShrineState*)state)->unk20;
}

int ecsh_shrine_getExtraSize(void)
{
    return 0x38;
}

int ecsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void ecsh_shrine_hitDetect(void)
{
}

void ecsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objParticleFn_80099d84(int obj, f32 a, int kind, f32 b, int h);
    extern void objRenderModelAndHitVolumes(int p1, int p2, int p3, int p4, int p5, f32 scale);
    extern void modelLightStruct_setEnabled(int handle, int flag, f32 v);
    void** inner = ((GameObject*)obj)->extra;
    if (visible == 0)
    {
        if (*inner != NULL)
        {
            modelLightStruct_setEnabled((int)*inner, 0, lbl_803E4FC8);
        }
        return;
    }
    if (*inner != NULL)
    {
        modelLightStruct_setEnabled((int)*inner, 1, lbl_803E4FC8);
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4FC8);
    objParticleFn_80099d84(obj, lbl_803E4FC8, 7, *(f32*)&lbl_803E4FC8, (int)*inner);
}

void ecsh_shrine_free(int* obj)
{
    int* inner = ((GameObject*)obj)->extra;
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MUSICTRIG_krazoa_doors_open, 0);
    if (*(void**)inner != NULL)
    {
        ModelLightStruct_free(*(void**)inner);
        *(void**)inner = NULL;
    }
    ObjGroup_RemoveObject((int)obj, ECSHSHRINE_OBJGROUP);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
    GameBit_Set(0xa7f, 1);
}

/* Number of cups in the shuffle puzzle (cupSlotMap[6], cupPos holds 6 (x,z) pairs). */
#define ECSHSHRINE_CUP_COUNT 6

typedef struct EcshPuzzleState
{
    f32 cupPos[12]; /* 0x00: the 6 cups' (x,z) positions */
    s16 cupSlotMap[6]; /* 0x30: current slot->cup index map (== gEcShShrineCupSlotMap) */
    s16 nextCupSlotMap[7]; /* 0x3c: next round's slot->cup map */
} EcshPuzzleState;

/*
 * Main state machine.
 *
 * Outer phase = the raw byte sub[0x2F] (== EcshShrineState.testPhase):
 *   0  idle / waiting for player to engage
 *   1  intro screen transition
 *   2  spirit hides + pick the target cup (spiritCup = randomGetRange(0,5))
 *   3  round 1 (5 shuffles, pattern randomGetRange(0,1))
 *   4  round 2 (7 shuffles, pattern randomGetRange(0,5))
 *   5  round 3 (9 shuffles, pattern randomGetRange(0,7))
 *   6  win cutscene (all 3 rounds passed)
 *   7  reset step
 *   8  reset step (clears state back to idle)
 *   10 fail / teleport player out
 *
 * Inner shuffle-animation state = EcshShrineState.animState (0x24), values 0-9:
 *   drives the per-step cup shuffle animation and SFX; transitions cycle
 *   8->2->5/0->1->4->2 etc. as each shuffle iteration plays out, with 7/9
 *   used as round-entry/exit and 5 as the guess-resolution state.
 */
#pragma opt_strength_reduction off
void ecsh_shrine_update(s16* obj)
{
    extern void* Obj_GetPlayerObject(void);
    extern void ecsh_shrine_updateMotion(s16 * obj);
    f32 t[2];
    int msgC;
    int msgA;
    int msgB;
    EcshPuzzleState* ps;
    u8* sub;
    int* player;
    u8 gv;
    int pick;
    int n;
    s16 sc;
    f32 z;
    f32 fv;

    ps = (EcshPuzzleState*)gEcShShrinePuzzleState;
    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    *(EcshIntPair*)&t[0] = *(EcshIntPair*)&lbl_803E8470;
    if (sub[0x32] == 0)
    {
        gv = GameBit_Get(GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER);
        sub[0x32] = gv;
        if (sub[0x32] != 0)
        {
            (*gGameUIInterface)->showNpcDialogue(0x285, 0x14, 0x8c, 1);
        }
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct(obj, player, 0x221, 0);
            getEnvfxAct(obj, player, 0x220, 0);
            getEnvfxAct(obj, player, 0x222, 0);
        }
    }
    ecsh_shrine_updateMotion(obj);
    if (player != NULL && objIsCurModelNotZero(player) == 0)
    {
        fn_80295CF4(player, 0);
    }
    msgC = 0;
    while (ObjMsg_Pop(obj, &msgA, &msgB, &msgC) != 0)
    {
    }
    SCGameBitLatch_Update(sub + 0x34, 2, -1, -1, 0xb9d, 0xd);
    SCGameBitLatch_UpdateInverted(sub + 0x34, 1, -1, -1, 0xcbb, 8);
    SCGameBitLatch_Update(sub + 0x34, 0x10, -1, -1, 0xcbb, 0xc4);
    if (((EcshShrineState*)sub)->cooldownTimer > (z = *(f32*)&lbl_803E4FCC))
    {
        ((EcshShrineState*)sub)->cooldownTimer = ((EcshShrineState*)sub)->cooldownTimer - timeDelta;
        if (((EcshShrineState*)sub)->cooldownTimer <= z)
        {
            ((EcshShrineState*)sub)->cooldownTimer = z;
        }
    }
    else
    {
        /*
         * Raw byte accesses below (kept raw to preserve codegen):
         *   sub[0x2e] = EcshShrineState.spiritCup        (target cup, 0-5)
         *   sub[0x2f] = EcshShrineState.testPhase        (outer phase, see above)
         *   sub[0x30] = EcshShrineState.transitionReady  (intro transition done)
         *   sub[0x31] = pad31 scratch flag (one-shot "near-miss SFX played" latch
         *               for the current shuffle step; no named field in the struct)
         */
        switch (sub[0x2f])
        {
        case 0:
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            fv = *(f32*)(sub + 0x10) - timeDelta;
            *(f32*)(sub + 0x10) = fv;
            if (fv <= z)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice);
                *(f32*)(sub + 0x10) = (f32)(int)
                randomGetRange(500, 1000);
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
            {
                sub[0x2f] = 1;
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                Music_Trigger(MUSICTRIG_DIM_Snow, 1);
                {
                    f32 fz = lbl_803E4FCC;
                    ps->cupPos[0] = fz;
                    ps->cupPos[1] = fz;
                    ps->cupPos[2] = fz;
                    ps->cupPos[3] = fz;
                    ps->cupPos[4] = fz;
                    ps->cupPos[5] = fz;
                    ps->cupPos[6] = fz;
                    ps->cupPos[7] = fz;
                    ps->cupPos[8] = fz;
                    ps->cupPos[9] = fz;
                    ps->cupPos[10] = fz;
                    ps->cupPos[11] = fz;
                }
                ps->cupSlotMap[0] = ps->nextCupSlotMap[0];
                ps->cupSlotMap[1] = ps->nextCupSlotMap[1];
                ps->cupSlotMap[2] = ps->nextCupSlotMap[2];
                ps->cupSlotMap[3] = ps->nextCupSlotMap[3];
                ps->cupSlotMap[4] = ps->nextCupSlotMap[4];
                ps->cupSlotMap[5] = ps->nextCupSlotMap[5];
                ps->nextCupSlotMap[0] = ps->nextCupSlotMap[6];
            }
            break;
        case 1:
            if (sub[0x30] == 1)
            {
                sub[0x2f] = 2;
                ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FD0;
                ((EcshShrineState*)sub)->animState = 6;
                Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                ((EcshShrineState*)sub)->animTimer = lbl_803E4FCC;
                GameBit_Set(0xb9d, 1);
                (*gScreenTransitionInterface)->step(0x78, 1);
            }
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            break;
        case 2:
            sub[0x2f] = 3;
            ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FD4;
            ((EcshShrineState*)sub)->animState = 8;
            ((EcshShrineState*)sub)->animTimer = lbl_803E4FD8;
            ((EcshShrineState*)sub)->shuffleCount = 5;
            gv = randomGetRange(0, 5);
            sub[0x2e] = gv;
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
            break;
        case 3:
        case 4:
        case 5:
            if (((EcshShrineState*)sub)->animTimer > (fv = lbl_803E4FCC))
            {
                if (((EcshShrineState*)sub)->animState == 1 && sub[0x31] == 0
                    && ((EcshShrineState*)sub)->animTimer < *(f32*)(sub + 0x14))
                {
                    if ((int)randomGetRange(0, 10) > 7)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice_var);
                    }
                    sub[0x31] = 1;
                }
                ((EcshShrineState*)sub)->animTimer = ((EcshShrineState*)sub)->animTimer - timeDelta;
                if (((EcshShrineState*)sub)->animTimer < lbl_803E4FCC)
                {
                    ((EcshShrineState*)sub)->animTimer = *(f32*)&lbl_803E4FCC;
                }
            }
            else
            {
                switch (((EcshShrineState*)sub)->animState)
                {
                case 8:
                    ((EcshShrineState*)sub)->animState = 2;
                    ((EcshShrineState*)sub)->animTimer = lbl_803E4FD8;
                    ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FDC;
                    break;
                case 9:
                    ((EcshShrineState*)sub)->animState = 8;
                    ((EcshShrineState*)sub)->animTimer = lbl_803E4FD8;
                    ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FDC;
                    break;
                case 7:
                    ((EcshShrineState*)sub)->animState = 3;
                    ((EcshShrineState*)sub)->animTimer = lbl_803E4FD8;
                    ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FDC;
                    break;
                case 2:
                    ((EcshShrineState*)sub)->shuffleCount -= 1;
                    if (((EcshShrineState*)sub)->shuffleCount <= 0)
                    {
                        Sfx_PlayFromObject(0, SFXTRIG_commsbleep);
                        ((EcshShrineState*)sub)->animState = 5;
                        if (sub[0x2f] == 3)
                        {
                            *(f32*)(sub + 0xc) = lbl_803E4FA8;
                        }
                        else if (sub[0x2f] == 4)
                        {
                            *(f32*)(sub + 0xc) = lbl_803E4FA8;
                        }
                        else
                        {
                            *(f32*)(sub + 0xc) = lbl_803E4FA8;
                        }
                    }
                    else
                    {
                        sub[0x31] = 0;
                        *(f32*)(sub + 0x14) = (f32)(int)
                        randomGetRange(0x28, 0x3c);
                        Sfx_PlayFromObject(obj, SFXTRIG_spirit_basketspin);
                        ((EcshShrineState*)sub)->animState = 0;
                        ((EcshShrineState*)sub)->animTimer = lbl_803E4FE0;
                        if (sub[0x2f] == 3)
                        {
                            pick = randomGetRange(0, 1);
                        }
                        else if (sub[0x2f] == 4)
                        {
                            pick = randomGetRange(0, 5);
                        }
                        else
                        {
                            pick = randomGetRange(0, 7);
                        }
                        if (pick == 0)
                        {
                            for (n = 0; n < ECSHSHRINE_CUP_COUNT; n++)
                            {
                                ps->cupSlotMap[n] += 1;
                                if (ps->cupSlotMap[n] > 5)
                                {
                                    ps->cupSlotMap[n] = 0;
                                }
                            }
                        }
                        else if (pick == 1)
                        {
                            for (n = 0; n < ECSHSHRINE_CUP_COUNT; n++)
                            {
                                ps->cupSlotMap[n] -= 1;
                                if (ps->cupSlotMap[n] < 0)
                                {
                                    ps->cupSlotMap[n] = 5;
                                }
                            }
                        }
                        else if (pick == 2)
                        {
                            sc = ps->cupSlotMap[0];
                            ps->cupSlotMap[0] = ps->cupSlotMap[2];
                            ps->cupSlotMap[2] = ps->cupSlotMap[4];
                            ps->cupSlotMap[4] = sc;
                        }
                        else if (pick == 3)
                        {
                            sc = ps->cupSlotMap[4];
                            ps->cupSlotMap[4] = ps->cupSlotMap[0];
                            ps->cupSlotMap[0] = ps->cupSlotMap[2];
                            ps->cupSlotMap[2] = sc;
                        }
                        else if (pick == 4)
                        {
                            sc = ps->cupSlotMap[1];
                            ps->cupSlotMap[1] = ps->cupSlotMap[3];
                            ps->cupSlotMap[3] = ps->cupSlotMap[5];
                            ps->cupSlotMap[5] = sc;
                        }
                        else if (pick == 5)
                        {
                            sc = ps->cupSlotMap[5];
                            ps->cupSlotMap[5] = ps->cupSlotMap[1];
                            ps->cupSlotMap[1] = ps->cupSlotMap[3];
                            ps->cupSlotMap[3] = sc;
                        }
                        else if (pick == 6)
                        {
                            t[0] = ps->cupPos[2];
                            t[1] = ps->cupPos[3];
                            ps->cupPos[2] = ps->cupPos[4];
                            ps->cupPos[3] = ps->cupPos[5];
                            ps->cupPos[4] = ps->cupPos[8];
                            ps->cupPos[5] = ps->cupPos[9];
                            ps->cupPos[8] = ps->cupPos[10];
                            ps->cupPos[9] = ps->cupPos[11];
                            ps->cupPos[10] = t[0];
                            ps->cupPos[11] = t[1];
                        }
                        else if (pick == 7)
                        {
                            t[0] = ps->cupPos[10];
                            t[1] = ps->cupPos[11];
                            ps->cupPos[10] = ps->cupPos[8];
                            ps->cupPos[11] = ps->cupPos[9];
                            ps->cupPos[8] = ps->cupPos[4];
                            ps->cupPos[9] = ps->cupPos[5];
                            ps->cupPos[4] = ps->cupPos[2];
                            ps->cupPos[5] = ps->cupPos[3];
                            ps->cupPos[2] = t[0];
                            ps->cupPos[3] = t[1];
                        }
                    }
                    break;
                case 0:
                    ((EcshShrineState*)sub)->animState = 1;
                    ((EcshShrineState*)sub)->animTimer = lbl_803E4FE4;
                    break;
                case 1:
                    ((EcshShrineState*)sub)->animState = 4;
                    ((EcshShrineState*)sub)->animTimer = fv;
                    break;
                case 4:
                    ((EcshShrineState*)sub)->animState = 2;
                    ((EcshShrineState*)sub)->animTimer = fv;
                    break;
                case 5:
                    Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_commsbleep);
                    if (((EcshShrineState*)sub)->matchFlag == 0)
                    {
                        (*gScreenTransitionInterface)->start(0x1e, 1);
                        ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FE8;
                        ((EcshShrineState*)sub)->animState = 7;
                        Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                        sub[0x2f] = 10;
                    }
                    else if (((EcshShrineState*)sub)->matchFlag == 1)
                    {
                        if (sub[0x2f] == 3)
                        {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 4;
                            ((EcshShrineState*)sub)->animState = 9;
                            ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FEC;
                            ((EcshShrineState*)sub)->animTimer = lbl_803E4FB0;
                            ((EcshShrineState*)sub)->shuffleCount = 7;
                            ((EcshShrineState*)sub)->matchFlag = -1;
                            Sfx_PlayFromObject(obj, SFXTRIG_sc_menuups16k);
                            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                        }
                        else if (sub[0x2f] == 4)
                        {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 5;
                            ((EcshShrineState*)sub)->animState = 9;
                            ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FEC;
                            ((EcshShrineState*)sub)->animTimer = lbl_803E4FB0;
                            ((EcshShrineState*)sub)->shuffleCount = 9;
                            ((EcshShrineState*)sub)->matchFlag = -1;
                            Sfx_PlayFromObject(obj, SFXTRIG_sc_menuups16k);
                            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                        }
                        else
                        {
                            ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FE8;
                            (*gScreenTransitionInterface)->start(0x1e, 1);
                            sub[0x2f] = 6;
                            ((EcshShrineState*)sub)->animState = 3;
                            ((EcshShrineState*)sub)->matchFlag = 0;
                            ((EcshShrineState*)sub)->animState = 7;
                            Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
                            Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                        }
                    }
                    else
                    {
                        *(f32*)(sub + 0xc) = *(f32*)(sub + 0xc) - timeDelta;
                        if (*(f32*)(sub + 0xc) <= lbl_803E4FCC)
                        {
                            sub[0x2f] = 10;
                            (*gScreenTransitionInterface)->start(0x1e, 1);
                            ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FE8;
                            ((EcshShrineState*)sub)->animState = 7;
                            Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                        }
                    }
                    break;
                }
            }
            break;
        case 10:
            GameBit_Set(0xa6f, 1);
            sub[0x2f] = 8;
            break;
        case 6:
            GameBit_Set(0xb9d, 0);
            audioStopByMask(3);
            if (objGetAnimStateFlags(player, 8) != 0)
            {
                GameBit_Set(0x129, 1);
                sub[0x2f] = 7;
            }
            else
            {
                sub[0x2f] = 7;
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            }
            break;
        case 7:
            GameBit_Set(0x129, 0);
            sub[0x2f] = 8;
            break;
        case 8:
            sub[0x2f] = 0;
            ((EcshShrineState*)sub)->animTimer = z;
            ((EcshShrineState*)sub)->unk20 = 0;
            ((EcshShrineState*)sub)->shuffleCount = 0;
            ((EcshShrineState*)sub)->animState = 0;
            ((EcshShrineState*)sub)->matchFlag = -1;
            sub[0x2e] = 0;
            sub[0x30] = 0;
            ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FF0;
            GameBit_Set(0x129, 1);
            GameBit_Set(0xb9d, 0);
            GameBit_Set(0xa6d, 0);
            GameBit_Set(0xa6f, 0);
            GameBit_Set(0xa70, 0);
            GameBit_Set(0x143, 0);
            sub[0x30] = 0;
            ((EcshShrineState*)sub)->matchFlag = -1;
            break;
        }
    }
}
#pragma opt_strength_reduction reset

/* 4 unreferenced zero bytes sit between ecsh_shrine_update's jump tables and
 * gECSH_CreatorObjDescriptor in retail .data (0x80326324); nothing references
 * them. The declspec keeps this 4-byte filler out of .sdata so the section
 * layout matches. */
__declspec(section ".data") int gEcShShrineUnused[1] = { 0 };

void ecsh_shrine_release(void)
{
}

void ecsh_shrine_initialise(void)
{
}

void ecsh_shrine_init(s16* obj, s8* def)
{
    extern s16* gEcShShrineActiveObject;
    int* sub = ((GameObject*)obj)->extra;
    u8 gv;
    lbl_803DDBC0 = 0;
    gEcShShrineActiveObject = 0;
    *obj = (s16)((s32)def[0x18] << 8);
    ((EcshShrineState*)sub)->testPhase = 0;
    ((EcshShrineState*)sub)->transitionReady = 0;
    ((EcshShrineState*)sub)->animTimer = lbl_803E4FCC;
    ((EcshShrineState*)sub)->unk20 = 0;
    ((EcshShrineState*)sub)->shuffleCount = 0;
    ((EcshShrineState*)sub)->animState = 0;
    ((EcshShrineState*)sub)->matchFlag = -1;
    ((EcshShrineState*)sub)->spiritCup = 0;
    ((EcshShrineState*)sub)->gameBitLatchState = 0;
    ((GameObject*)obj)->animEventCallback = ecsh_shrine_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0xba5, 1);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x143, 0);
    ((EcshShrineState*)sub)->unk18 = 0xc;
    ((EcshShrineState*)sub)->unk1C = 0x1e;
    ((EcshShrineState*)sub)->cooldownTimer = lbl_803E4FD0;
    ((EcshShrineState*)sub)->unk1A = 0;
    ((EcshShrineState*)sub)->unk1E = 0;
    gv = GameBit_Get(GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER);
    ((EcshShrineState*)sub)->introTextLatch = gv;
    gEcShShrineActiveObject = obj;
    ObjGroup_AddObject(obj, ECSHSHRINE_OBJGROUP);
    ((GameObject*)obj)->unkF4 = 1;
    if (*(void**)sub == NULL)
    {
        *(int*)sub = objCreateLight(0, 1);
    }
    GameBit_Set(0xefa, 1);
}

/* descriptor/ptr table auto 0x80326328-0x80326398 */
u32 gECSH_CreatorObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)ecsh_creator_initialise, (u32)ecsh_creator_release, 0x00000000, (u32)ecsh_creator_init, (u32)ecsh_creator_update, (u32)ecsh_creator_hitDetect, (u32)ecsh_creator_render, (u32)ecsh_creator_free, (u32)ecsh_creator_getObjectTypeId, (u32)ecsh_creator_getExtraSize };
u32 gGPSH_ShrineObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)gpsh_shrine_initialise, (u32)gpsh_shrine_release, 0x00000000, (u32)gpsh_shrine_init, (u32)gpsh_shrine_update, (u32)gpsh_shrine_hitDetect, (u32)gpsh_shrine_render, (u32)gpsh_shrine_free, (u32)gpsh_shrine_getObjectTypeId, (u32)gpsh_shrine_getExtraSize };
