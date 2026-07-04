/*
 * mmshshrine (DLL 0x18C) - the Krazoa shrine object in the MMSH map
 * (the shrine whose sway/test sequence rewards a Krazoa spirit).
 *
 * The shrine drives a small phase machine (runtime->phase 0..5): idle
 * SFX while waiting, then on activation runs object-trigger sequence 0,
 * lights the shrine model (flags06 & MMSH_SHRINE_FLAG_LIT), and on
 * completion runs the result sequences and grants the Krazoa game bit
 * (0x12a). A load-trigger countdown enables the sky and env fx once the
 * map has settled, and three SCGameBitLatch updates gate the open /
 * music-lock / completion ambient state from world game bits. The
 * sequence callback (MMSH_Shrine_SeqFn) interprets per-frame command
 * opcodes that toggle the light and drive the model sway parameters.
 */
#include "main/dll/dll_018C_mmshshrine.h"
#include "main/game_object.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"
extern void modelLightStruct_setEnabled(int p1, int p2, f32 f);
extern void ModelLightStruct_free(void* p);
extern int objCreateLight(int arg, int addToList);
extern int Obj_GetPlayerObject(void);
extern void fn_8011F6D4(u32 x);
extern int fn_801C49B8(int obj);
extern void fn_80296518(int obj, int flag, int set);
extern void Music_Trigger(int id, int arg);
extern void objParticleFn_80099d84(int p1, f32 f1, int p2, f32 f2, int p3);

extern int getEnvfxAct(int a, int b, u16 idx, int d);



extern int objGetAnimStateFlags(int obj, int flag);

extern void fn_801C4664(int obj);
extern int randomGetRange(int lo, int hi);
extern void objRenderFn_8003b8f4(int p1, u32 p2, u32 p3, u32 p4, u32 p5, f32 f);
extern f32 timeDelta;
extern f32 lbl_803E4F40;
extern f32 lbl_803E4F50;
extern f32 lbl_803E4F54;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4F60;

#define MMSH_SHRINE_FLAG_LIT 0x4000
#define MMSH_SHRINE_LOAD_MAP_DIR 0x20
#define MMSH_SHRINE_LOAD_TRIGGER_TIMER 0xf4
#define MMSH_SHRINE_LATCH_FLAG_OPEN_READY 0x1
#define MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE 0x2
#define MMSH_SHRINE_LATCH_FLAG_CHECK_COMPLETE 0x4
#define MMSH_SHRINE_LATCH_FLAG_AMBIENT_LOCK 0x8
#define MMSH_SHRINE_LATCH_FLAG_MUSIC_LOCK 0x10
#define MMSH_SHRINE_LATCH_FLAG_SWAY_RESET 0x20
#define MMSH_SHRINE_SEQ_RESULT_COMPLETE 4
#define MMSH_SHRINE_SEQ_MAP_DIR 0xb
#define MMSH_SHRINE_SEQ_MAP_EVENT 3
#define MMSH_SHRINE_SEQ_GB_KRYSTAL 0x12a
#define MMSH_SHRINE_SEQ_GB_UNKNOWN_FF 0xff
#define MMSH_SHRINE_SEQ_GB_RESET0 0xe82
#define MMSH_SHRINE_SEQ_GB_RESET1 0xe83
#define MMSH_SHRINE_SEQ_GB_RESET2 0xe84
#define MMSH_SHRINE_SEQ_GB_RESET3 0xe85
#define MMSH_SHRINE_GB_OPEN 0xae6
#define MMSH_SHRINE_GB_COMPLETE 0xae4
#define MMSH_SHRINE_GB_RESET_A 0x12b
#define MMSH_SHRINE_GB_RESET_B 0xae5
#define MMSH_SHRINE_GB_MUSIC_LOCK 0xcbb
#define MMSH_SHRINE_SFX_IDLE 0x343
#define MMSH_SHRINE_MUSIC_RUMBLE 0xd8
#define MMSH_SHRINE_MUSIC_RUMBLE_STOP 0xd9
#define MMSH_SHRINE_MUSIC_STOP_8 0x8
#define MMSH_SHRINE_MUSIC_STOP_A 0xa
#define MMSH_SHRINE_GB_EFA 0xefa
#define MMSH_SHRINE_GB_12D 0x12d
#define MMSH_SHRINE_GB_F07 0xf07

enum MMSHShrinePhase
{
    MMSH_SHRINE_PHASE_IDLE       = 0, /* idle SFX, wait for activation flag  */
    MMSH_SHRINE_PHASE_ACTIVATING = 1, /* wait for open-ready latch, then lit */
    MMSH_SHRINE_PHASE_LIT        = 2, /* shrine lit, await player test anim  */
    MMSH_SHRINE_PHASE_RESULT     = 3, /* end sway seq, run result sequence   */
    MMSH_SHRINE_PHASE_COMPLETE   = 4, /* grant completion game bit           */
    MMSH_SHRINE_PHASE_RESET      = 5  /* clear flags, return to idle         */
};

typedef struct MMSHShrineRuntime
{
    void* light;
    f32 swayBase;
    f32 swayAccel;
    f32 swayVelocity;
    f32 swayTarget;
    f32 idleSfxTimer;
    SCGameBitLatchState latch;
    s16 initCount;
    u8 pad1E[0x24 - 0x1E];
    u8 phase;
    u8 pad25[3];
} MMSHShrineRuntime;

typedef struct MMSHShrineObject
{
    s16 yaw;
    u8 pad02[0x06 - 0x02];
    s16 flags06;
    u8 pad08[0x0C - 0x08];
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 prevPosX;
    f32 prevPosY;
    f32 prevPosZ;
    u8 pad24[0xAF - 0x24];
    u8 objectFlags;
    u8 padB0[0xB4 - 0xB0];
    s16 triggerHandle;
    u8 padB6[0xB8 - 0xB6];
    MMSHShrineRuntime* runtime;
    u8 padBC[MMSH_SHRINE_LOAD_TRIGGER_TIMER - 0xBC];
    s32 loadTriggerTimer;
} MMSHShrineObject;

int MMSH_Shrine_SeqFn(int objArg, u32 unused, MMSHShrineSequenceState* seq)
{
    MMSHShrineRuntime* runtime;
    u8 command;
    int playerObj;
    int i;

    runtime = ((MMSHShrineObject*)objArg)->runtime;
    playerObj = Obj_GetPlayerObject();
    seq->targetObject = -1;
    seq->activeCommand = 0;

    for (i = 0; i < (int)(u32)seq->commandCount; i++)
    {
        command = seq->commands[i];
        if (command != 0)
        {
            switch (command)
            {
            case 7:
                fn_80296518(playerObj, 4, 1);
                GameBit_Set(MMSH_SHRINE_SEQ_GB_KRYSTAL, 1);
                GameBit_Set(MMSH_SHRINE_SEQ_GB_UNKNOWN_FF, 1);
                (*gMapEventInterface)->setMapAct(MMSH_SHRINE_SEQ_MAP_DIR,MMSH_SHRINE_SEQ_MAP_EVENT);
                break;
            case 0xe:
                ((MMSHShrineObject*)objArg)->flags06 |= MMSH_SHRINE_FLAG_LIT;
                if (runtime->light != NULL)
                {
                    modelLightStruct_setEnabled((int)runtime->light, 0, lbl_803E4F50);
                }
                break;
            case 0xf:
                ((MMSHShrineObject*)objArg)->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
                if (runtime->light != NULL)
                {
                    modelLightStruct_setEnabled((int)runtime->light, 0, lbl_803E4F50);
                }
                break;
            case 1:
                runtime->latch.activeMask |= MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE;
                break;
            case 2:
                runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE;
                if ((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_RESET) != 0)
                {
                    fn_8011F6D4(0);
                    runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_SWAY_RESET;
                }
                break;
            case 3:
                runtime->swayTarget = lbl_803E4F54;
                break;
            case 4:
                runtime->swayTarget = lbl_803E4F58;
                break;
            case 5:
                runtime->swayTarget = -runtime->swayTarget;
                runtime->swayVelocity = -runtime->swayTarget;
                break;
            case 6:
                runtime->swayTarget *= lbl_803E4F5C;
                break;
            case 8:
                runtime->swayTarget *= lbl_803E4F60;
                break;
            }
        }
        seq->commands[i] = 0;
    }

    if (((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE) != 0) &&
        ((u8)fn_801C49B8(objArg) != 0))
    {
        fn_8011F6D4(0);
        runtime->latch.activeMask &= ~(MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE |
            MMSH_SHRINE_LATCH_FLAG_SWAY_RESET);
        runtime->phase = MMSH_SHRINE_PHASE_RESULT;
        GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET0, 0);
        GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET1, 0);
        GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET2, 0);
        GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET3, 0);
        return MMSH_SHRINE_SEQ_RESULT_COMPLETE;
    }
    runtime->latch.activeMask |= MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
    return 0;
}

int mmsh_shrine_getExtraSize(void)
{
    return 0x28;
}

int mmsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void mmsh_shrine_hitDetect(void)
{
}

void mmsh_shrine_free(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if ((((MMSHShrineRuntime*)state)->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_RESET) != 0)
    {
        fn_8011F6D4(0);
        ((MMSHShrineRuntime*)state)->latch.activeMask = ((MMSHShrineRuntime*)state)->latch.activeMask & ~MMSH_SHRINE_LATCH_FLAG_SWAY_RESET;
    }
    if (*(void**)state != NULL)
    {
        ModelLightStruct_free(*(void**)state);
        *(int*)state = 0;
    }
    Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE_STOP, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_STOP_8, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_STOP_A, 0);
    GameBit_Set(MMSH_SHRINE_GB_EFA, 0);
    GameBit_Set(MMSH_SHRINE_GB_MUSIC_LOCK, 1);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET0, 0);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET1, 0);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET2, 0);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET3, 0);
}

void mmsh_shrine_render(int obj, u32 a2, u32 a3, u32 a4, u32 a5,
                        char visible)
{
    MMSHShrineObject* shrine = (MMSHShrineObject*)obj;
    MMSHShrineRuntime* runtime = shrine->runtime;

    if (visible == 0)
    {
        if (runtime->light != NULL)
        {
            modelLightStruct_setEnabled((int)runtime->light, 0, lbl_803E4F50);
        }
    }
    else
    {
        if (runtime->light != NULL)
        {
            modelLightStruct_setEnabled((int)runtime->light, 1, lbl_803E4F50);
        }
        objRenderFn_8003b8f4(obj, a2, a3, a4, a5, lbl_803E4F50);
        objParticleFn_80099d84(obj, lbl_803E4F50, 7, *(f32*)&lbl_803E4F50, (int)runtime->light);
    }
}

void mmsh_shrine_update(int objArg)
{
    MMSHShrineRuntime* runtime;
    MMSHShrineObject* obj;
    int playerObj;

    obj = (MMSHShrineObject*)objArg;
    runtime = obj->runtime;
    playerObj = Obj_GetPlayerObject();

    if (obj->loadTriggerTimer != 0)
    {
        obj->loadTriggerTimer--;
        if (obj->loadTriggerTimer == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct((int)obj, playerObj, 0x20d, 0);
            getEnvfxAct((int)obj, playerObj, 0x20e, 0);
            getEnvfxAct((int)obj, playerObj, 0x222, 0);
            obj->prevPosX = obj->posX;
            obj->prevPosY = obj->posY;
            obj->prevPosZ = obj->posZ;
        }
    }
    unlockLevel(mapGetDirIdx(MMSH_SHRINE_LOAD_MAP_DIR), 1, 0);
    fn_801C4664((int)obj);
    SCGameBitLatch_Update(&runtime->latch,MMSH_SHRINE_LATCH_FLAG_AMBIENT_LOCK, -1, -1,
                          MMSH_SHRINE_GB_OPEN, 0xa);
    SCGameBitLatch_UpdateInverted(&runtime->latch,MMSH_SHRINE_LATCH_FLAG_CHECK_COMPLETE, -1, -1,
                                  MMSH_SHRINE_GB_MUSIC_LOCK, 8);
    SCGameBitLatch_Update(&runtime->latch,MMSH_SHRINE_LATCH_FLAG_MUSIC_LOCK, -1, -1,
                          MMSH_SHRINE_GB_MUSIC_LOCK, 0xc4);

    switch (runtime->phase)
    {
    case MMSH_SHRINE_PHASE_IDLE:
        {
            f32 idleSfxTimer = runtime->idleSfxTimer - timeDelta;
            runtime->idleSfxTimer = idleSfxTimer;
            if (idleSfxTimer <= lbl_803E4F40)
            {
                Sfx_PlayFromObject((int)obj,MMSH_SHRINE_SFX_IDLE);
                runtime->idleSfxTimer = (f32)(s32)
                randomGetRange(500, 1000);
            }
        }
        if ((obj->objectFlags & 1) == 0)
        {
            break;
        }
        runtime->phase = MMSH_SHRINE_PHASE_ACTIVATING;
        (*gObjectTriggerInterface)->setCamVars(0x4c, 0, 0, 0);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE, 1);
        break;
    case MMSH_SHRINE_PHASE_ACTIVATING:
        if ((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_OPEN_READY) == 0)
        {
            break;
        }
        obj->flags06 |= MMSH_SHRINE_FLAG_LIT;
        obj->yaw = 0;
        runtime->phase = MMSH_SHRINE_PHASE_LIT;
        runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
        GameBit_Set(MMSH_SHRINE_GB_OPEN, 1);
        (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        break;
    case MMSH_SHRINE_PHASE_RESULT:
        (*gObjectTriggerInterface)->endSequence(obj->triggerHandle);
        (*gObjectTriggerInterface)->runSequence(3, obj, -1);
        runtime->phase = MMSH_SHRINE_PHASE_COMPLETE;
        GameBit_Set(MMSH_SHRINE_GB_OPEN, 0);
        break;
    case MMSH_SHRINE_PHASE_COMPLETE:
        runtime->phase = MMSH_SHRINE_PHASE_RESET;
        GameBit_Set(MMSH_SHRINE_GB_OPEN, 0);
        GameBit_Set(MMSH_SHRINE_GB_COMPLETE, 1);
        break;
    case MMSH_SHRINE_PHASE_LIT:
        if (objGetAnimStateFlags(playerObj, 4) == 0)
        {
            audioStopByMask(3);
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
        runtime->phase = MMSH_SHRINE_PHASE_RESET;
        GameBit_Set(MMSH_SHRINE_GB_OPEN, 0);
        break;
    case MMSH_SHRINE_PHASE_RESET:
        runtime->phase = MMSH_SHRINE_PHASE_IDLE;
        runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
        obj->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
        GameBit_Set(MMSH_SHRINE_GB_RESET_A, 0);
        GameBit_Set(MMSH_SHRINE_GB_COMPLETE, 0);
        GameBit_Set(MMSH_SHRINE_GB_RESET_B, 0);
        GameBit_Set(MMSH_SHRINE_GB_OPEN, 0);
        break;
    }
}

void mmsh_shrine_init(int obj, int def)
{
    int light;
    MMSHShrineRuntime* state;

    state = ((GameObject*)obj)->extra;
    ((MMSHShrineObject*)obj)->yaw = 0;
    ((GameObject*)obj)->animEventCallback = MMSH_Shrine_SeqFn;
    state->initCount = 10;
    state->phase = MMSH_SHRINE_PHASE_IDLE;
    if (0 < *(short*)(def + 0x1a))
    {
        state->initCount = *(short*)(def + 0x1a) >> 8;
    }
    GameBit_Set(MMSH_SHRINE_GB_RESET_A, 0);
    GameBit_Set(MMSH_SHRINE_GB_12D, 0);
    ((MMSHShrineObject*)obj)->loadTriggerTimer = 1;
    if (state->light == NULL)
    {
        light = objCreateLight(0, 1);
        state->light = (void*)light;
    }
    GameBit_Set(MMSH_SHRINE_GB_F07, 1);
    GameBit_Set(MMSH_SHRINE_GB_EFA, 1);
}

void mmsh_shrine_release(void)
{
}

void mmsh_shrine_initialise(void)
{
}
