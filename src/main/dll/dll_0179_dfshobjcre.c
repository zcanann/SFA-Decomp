/* === moved from main/dll/dll_19C.c [801C3B68-801C3BB0) (TU re-split, docs/boundary_audit.md) === */
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

#define DFSH_REWARD_BIT(idx) (base[(idx)])
#define DFSH_REWARD_DELAY(idx) (base[10 + (idx)])
#define DFSH_REQUIRED_BIT(idx) (base[20 + (idx)])
#define DFSH_TARGET_OBJECT(idx) (((int *)((u8 *)base + 0x3c))[(idx)])

#define DFSH_SHRINE_FLAG_SUCCESS 0x40
#define DFSH_SHRINE_FLAG_OPENED_BY_SEQUENCE 0x80


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
void dfsh_shrine_hitDetect(void);

void dfsh_shrine_release(void);

void dfsh_shrine_initialise(void);

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

void dfsh_shrine_init(int* obj, DfshShrinePlacement* init);

void SpiritPrize_hitDetect(void);

void SpiritPrize_release(void);

void SpiritPrize_initialise(void);

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


extern void modelLightStruct_setLightKind(void* light, int v);
extern void modelLightStruct_setDiffuseColor(void* light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 a, f32 b);
extern f32 lbl_803E4E98;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EB4;

void SpiritPrize_init(int* obj, u8* init);

void dfsh_objcreator_free(void)
{
}

void dfsh_objcreator_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int SpiritPrize_getExtraSize(void);
int SpiritPrize_getObjectTypeId(void);
int dfsh_objcreator_getExtraSize(void) { return 0x4; }
int dfsh_objcreator_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4EB8;

void dfsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4EB8);
}

void SpiritPrize_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);


/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/dll_19E.h"
#include "main/resource.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern void* FUN_80017624();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80017b00();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053754();
extern int FUN_8005b024();
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int objectId);
extern void* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, int parent);

extern undefined4 DAT_803dc071;
extern void* DAT_803de838;
extern f64 DOUBLE_803e5b38;
extern f64 DOUBLE_803e5b40;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B4C;

typedef struct DfshObjCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
} DfshObjCreatorState;

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_update
 * EN v1.0 Address: 0x801C3BB0
 * EN v1.0 Size: 740b
 * EN v1.1 Address: 0x801C3CC4
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_update(int obj)
{
    extern uint GameBit_Get(int eventId);
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    void* resource;
    u8* spawnSetup;

    if (GameBit_Get(0x589) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        return;
    }

    if (((GameObject*)obj)->unkF8 == 0 && GameBit_Get((s8)setup[0x1f] + 0xf6) != 0)
    {
        resource = Resource_Acquire(0x82, 1);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 0, 0, 1, -1, 0);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, SFXsc_gemrun1022);
        Resource_Release(resource);
        state->spawnTimerStep = 1;
        ((GameObject*)obj)->unkF8 = 1;
    }

    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer =
            (s16)(state->spawnTimer - state->spawnTimerStep * (int)timeDelta);
    }

    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = Obj_AllocObjectSetup(0x38, 0x11);
        *(f32*)(spawnSetup + 0x08) = ((ObjPlacement*)setup)->posX;
        *(f32*)(spawnSetup + 0x0c) = ((ObjPlacement*)setup)->posY;
        *(f32*)(spawnSetup + 0x10) = ((ObjPlacement*)setup)->posZ;
        *(int*)(spawnSetup + 0x14) = ((ObjPlacement*)setup)->mapId;
        spawnSetup[0x04] = setup[0x04];
        spawnSetup[0x05] = setup[0x05];
        spawnSetup[0x06] = setup[0x06];
        spawnSetup[0x07] = setup[0x07];
        spawnSetup[0x27] = 3;
        *(s16*)(spawnSetup + 0x18) = 0x1e7;
        *(s16*)(spawnSetup + 0x30) = -1;
        *(s16*)(spawnSetup + 0x1a) = -1;
        *(s16*)(spawnSetup + 0x1c) = -1;
        *(s8*)(spawnSetup + 0x2a) = (s8)(*(s16*)obj >> 8);
        spawnSetup[0x2b] = 2;
        if (GameBit_Get(0xfc) != 0)
        {
            *(s16*)(spawnSetup + 0x22) = 0x49;
        }
        else
        {
            *(s16*)(spawnSetup + 0x22) = -1;
        }
        spawnSetup[0x29] = 0xff;
        *(s8*)(spawnSetup + 0x2e) = -1;
        *(u16*)(spawnSetup + 0x34) = 0xffff;
        Obj_SetupObject(spawnSetup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        *(int*)&((GameObject*)obj)->anim.parent);
        state->spawnTimer = 100;
        state->spawnTimerStep = 0;
    }
}

/*
 * --INFO--
 *
 * Function: DFSH_LaserBeam_init
 * EN v1.0 Address: 0x801C3E94
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x801C3F28
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern ModgfxInterface** gModgfxInterface;
extern void* lbl_803DDBB8;
extern void textureFree(void* tex);


/*
 * --INFO--
 *
 * Function: FUN_801c4098
 * EN v1.0 Address: 0x801C4098
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C4130
 * EN v1.1 Size: 52b
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
 * Function: dfsh_objcreator_release
 * EN v1.0 Address: 0x801C3E34
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfsh_objcreator_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_initialise
 * EN v1.0 Address: 0x801C3E38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_initialise(void)
{
}

void dfsh_objcreator_init(int obj, s8* def)
{
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)def[0x1E] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    state->spawnTimer = 100;
    state->spawnTimerStep = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF;
    ((GameObject*)obj)->anim.alpha = 0xFF;
}

/* Trivial 4b 0-arg blr leaves. */


/* 8b "li r3, N; blr" returners. */
