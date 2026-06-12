/* === moved from main/dll/DIM/DIM2flameburst.c [801B63F4-801B6464) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/explosion_state.h"
#include "main/effect_interfaces.h"
#include "main/objseq.h"










/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */
typedef struct DimWoodDoor2State
{
    u8 burnState; /* 3 intact; 0 burned (gamebit rung) */
    u8 pad01[3];
    f32 animSpeed;
    f32 riseSpeed; /* added to obj Z, decays back to rest */
} DimWoodDoor2State;

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */
typedef struct Dll1CEState
{
    f32 openProgress; /* clamped lid coast */
    f32 openVelocity;
    u8 opened; /* 1 once triggered */
    u8 igniteCountdown; /* 1 at init; gamebit + spawn at 0 */
    u8 pad0A[2];
} Dll1CEState;

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

typedef struct ExplosionPartfxSource
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 flags;
    f32 rootMotionScale;
    f32 localPosX;
    f32 localPosY;
    f32 localPosZ;
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* parent;
    u8 pad34[2];
    u8 alpha;
    u8 pad37;
} ExplosionPartfxSource;

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped. REFERENCE-ONLY for now:
 * every consumer keeps raw derefs - retyping the state local (or adding
 * (int) casts) flips saved-reg coloring in init/update/render/fn_801B3DE4
 * (recipe #36/#77); the layout is documented here for a future pass.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern EffectInterface** gPartfxInterface;


/*
 * --INFO--
 *
 * Function: FUN_801b3de4
 * EN v1.0 Address: 0x801B3DE4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801B401C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801b40f0
 * EN v1.0 Address: 0x801B40F0
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x801B4398
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: explosion_release
 * EN v1.0 Address: 0x801B5650
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B5DB8
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma scheduling off
#pragma peephole off

#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b5b8c
 * EN v1.0 Address: 0x801B5B8C
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801B62FC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801b5d00
 * EN v1.0 Address: 0x801B5D00
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801B64D0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */













#pragma scheduling off
#pragma peephole off

/* 8b "li r3, N; blr" returners. */
int dim_levelcontrol_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E49D0;
extern f32 lbl_803E4A20;




void dim_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* conditional init/free pair. */
extern void* lbl_803DDB78;
#pragma scheduling on
#pragma peephole on

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */
extern void* Obj_GetPlayerObject(void);
extern void dimmagicbridge_scrollTextureChannels(int obj, u8* sub);

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */
#pragma scheduling off

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */
#pragma peephole off


/* explosion_free: model-light release if present. */
#pragma scheduling on
#pragma peephole on

/* explosion_getObjectTypeId: tile/index lookup capped by table count. */
#pragma scheduling off

/* dim_levelcontrol_free: gameplay music + time-of-day reset. */
extern void timeOfDayFn_80055000(void);

void dim_levelcontrol_free(int p1);

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern u8 framesThisStep;
#pragma dont_inline on
void dimmagicbridge_scrollTextureChannels(int arg1, u8* obj);
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */
#pragma peephole off

extern f32 timeDelta;

/* EN v1.0 0x801B5804  size: 380b  dimwooddoor2_update: advance the door's
 * shake anim and decay its wobble; while idle near map-cue 0x338 bleed off
 * alpha, otherwise scan the nearby objects and, if a key object is present,
 * snap the door open (reset wobble, ring the gamebit, play the open sfx). */


/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} FbWGPipe;

volatile FbWGPipe GXWGFifo : (0xCC008000);



extern f32 mathSinf(f32 x);








#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/asset_load.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIM2snowball.h"
#include "main/objanim_internal.h"

typedef struct Dll1D6Placement
{
    u8 pad0[0x1A - 0x0];
    s16 upTimer;
    s16 downTimer;
    u8 pad1E[0x20 - 0x1E];
} Dll1D6Placement;


typedef struct DimtruthhorniceObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 hitsLeft;
    s16 unk1C;
    s16 gameBit;
} DimtruthhorniceObjectDef;


typedef struct Dim2snowballObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 targetId;
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} Dim2snowballObjectDef;


typedef struct Dll1CFObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} Dll1CFObjectDef;


typedef struct Dim2pathgeneratorObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 spawnPeriod;
    s16 unk1A;
    s16 unk1C;
    u16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} Dim2pathgeneratorObjectDef;


typedef struct Dim2pathgeneratorPlacement
{
    u8 pad0[0x3 - 0x0];
    u8 unk3;
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x14 - 0x8];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u16 unk1E;
    s16 unk20;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} Dim2pathgeneratorPlacement;


/* dim2conveyor_getExtraSize == 0x14. */
typedef struct Dim2ConveyorState
{
    f32 scrollX; /* 0x00: per-area conveyor scroll vector */
    f32 scrollY; /* 0x04 */
    u8 pad08[4];
    f32 swapTimer; /* 0x0c: 0x49b23 direction-swap countdown */
    int musicHold; /* 0x10: frames left keeping music track 0xdf alive */
} Dim2ConveyorState;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

/* dll_1D6_getExtraSize == 0x20 (crusher platform). */
typedef struct Dll1D6State
{
    void* bufA; /* 0x00: mmAlloc'd 40B getTabEntry rows */
    void* bufB; /* 0x04 */
    f32 hitRangeSqA; /* 0x08 */
    f32 hitRangeSqB; /* 0x0c */
    f32 bobPhase; /* 0x10 */
    f32 bobRate; /* 0x14 */
    s16 upTimer; /* 0x18 */
    s16 downTimer; /* 0x1a */
    s8 dizzyTimer; /* 0x1c */
    u8 flags1D; /* 0x1d: 1 = raised, 2 = armed, 4 = bobbing */
    u8 hitRow; /* 0x1e */
    u8 slot; /* 0x1f: index into the lbl_803DBF20 slot table */
} Dll1D6State;

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

/* dimtruthhornice_getExtraSize == 0x8. */
typedef struct TruthHornIceState
{
    s16 gameBit; /* 0x00 */
    s8 hitsLeft; /* 0x02 */
    s8 phase; /* 0x03 */
    f32 timer; /* 0x04 */
} TruthHornIceState;

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

/* dim2snowball_getExtraSize == 0xb0 (curve walker head + roll state). */
typedef struct Dim2SnowballState
{
    u8 pad00[0x10];
    int curveCursor; /* 0x10 */
    u8 pad14[0x54];
    f32 curveX; /* 0x68 */
    f32 curveY; /* 0x6c */
    f32 curveZ; /* 0x70 */
    f32 dirX; /* 0x74 */
    u8 pad78[4];
    f32 dirZ; /* 0x7c */
    int curveMode; /* 0x80 */
    u8 pad84[0xc]; /* 0x84..0x8f: vcall outparams (address-used) */
    int curveResult; /* 0x90 */
    int evalFn; /* 0x94 */
    int coeffsFn; /* 0x98 */
    int* targetObj; /* 0x9c */
    int targetId; /* 0xa0 */
    f32 floorY; /* 0xa4 */
    int* curveData; /* 0xa8 (also address-used as a vcall outparam) */
    u8 flagsAC; /* 0xac */
    u8 padAD[3];
} Dim2SnowballState;

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */
typedef struct Dim2PathGeneratorState
{
    f32 originX; /* 0x000 */
    f32 originY; /* 0x004 */
    f32 originZ; /* 0x008 */
    f32 curveA[200]; /* 0x00c */
    f32 curveB[200]; /* 0x32c */
    f32 curveC[200]; /* 0x64c */
    f32 curveD[12]; /* 0x96c */
    u8 pad99C[2];
    s16 spawnTimer; /* 0x99e */
    s16 spawnPeriod; /* 0x9a0 */
    s16 spawnTypes[2]; /* 0x9a2: object ids, alternated via the toggle bit */
    u8 curveValid; /* 0x9a6 */
    u8 flags; /* 0x9a7: 1 = toggle, 2 = curve built, 4 = enabled */
} Dim2PathGeneratorState;

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_800067c0();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();


/*
 * --INFO--
 *
 * Function: dim_levelcontrol_update
 * EN v1.0 Address: 0x801B6464
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x801B6A18
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct DimLevelControlState
{
    f32 timer;
    int latch;
    u8 saveState;
    u8 unk9;
    s16 musicTrack;
    u8 unkC;
    u8 unkD;
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
} DimLevelControlState;

extern void getEnvfxActImmediately(int a, int b, int id, int d);
extern void getEnvfxAct(int a, int b, int id, int d);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void SCGameBitLatch_Update(int* state, int mask, int a, int b, int bit, int value);
extern int* gSHthorntailAnimationInterface;
extern f32 lbl_803E4A24;

void dim_levelcontrol_update(int obj);

/*
 * --INFO--
 *
 * Function: FUN_801b6d24
 * EN v1.0 Address: 0x801B6D24
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801B6F60
 * EN v1.1 Size: 428b
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
 * Function: FUN_801b6f88
 * EN v1.0 Address: 0x801B6F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801B71F4
 * EN v1.1 Size: 40b
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
 * Function: FUN_801b6fa8
 * EN v1.0 Address: 0x801B6FA8
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801B721C
 * EN v1.1 Size: 268b
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
 * Function: FUN_801b7314
 * EN v1.0 Address: 0x801B7314
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B7708
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7314(int param_1, undefined4 param_2, float* param_3, float* param_4)
{
    uint uVar1;
    int iVar2;
    float* pfVar3;

    pfVar3 = ((GameObject*)param_1)->extra;
    if (pfVar3[4] == 0.0)
    {
        FUN_800067c0((int*)0xdf, 1);
    }
    pfVar3[4] = 2.8026e-44;
    iVar2 = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    if (iVar2 == 0x49b23)
    {
        uVar1 = GameBit_Get(0xc5c);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5b), uVar1 == 0))
        {
            *param_3 = *pfVar3;
            *param_4 = pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5c), uVar1 == 0))
        {
            *param_3 = -*pfVar3;
            *param_4 = -pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 != 0)
        {
            GameBit_Set(0xc5c, 0);
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 == 0)
        {
            GameBit_Set(0xc5c, 1);
        }
    }
    else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9))
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    else
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801b7fcc
 * EN v1.0 Address: 0x801B7FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B8344
 * EN v1.1 Size: 1344b
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
 * Function: FUN_801b7fd0
 * EN v1.0 Address: 0x801B7FD0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B8884
 * EN v1.1 Size: 252b
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
void dll_1CF_free(void);

void dll_1CF_hitDetect(void);

void dll_1CF_update(void);

void dll_1CF_release(void);

void dll_1CF_initialise(void);

void dim_tricky_free(void);

void dim_tricky_hitDetect(void);

void dim2conveyor_hitDetect(void);

void dim2conveyor_release(void);

void dim2conveyor_initialise(void);

void dll_1D6_hitDetect(void);

void dll_1D6_release(void);

void dll_1D6_initialise(void);

void dim2snowball_free(void);

void dim2snowball_hitDetect(void);

void dim2snowball_release(void);

void dim2snowball_initialise(void);

void dim2pathgenerator_free(void)
{
}

void dim2pathgenerator_render(void)
{
}

void dim2pathgenerator_hitDetect(void)
{
}

void dim2pathgenerator_release(void)
{
}

void dim2pathgenerator_initialise(void)
{
}


/* 8b "li r3, N; blr" returners. */
int dll_1CF_getExtraSize(void);
int dll_1CF_getObjectTypeId(void);
int dim_tricky_getExtraSize(void);
int dim_tricky_getObjectTypeId(void);
int dimtruthhornice_getExtraSize(void);
int dim2conveyor_getExtraSize(void);
int dim2conveyor_getObjectTypeId(void);
int dll_1D6_getExtraSize(void);
int dll_1D6_getObjectTypeId(void);
int dim2snowball_getExtraSize(void);
int dim2snowball_getObjectTypeId(void);
int dim2pathgenerator_getExtraSize(void) { return 0x9a8; }
int dim2pathgenerator_getObjectTypeId(void) { return 0x0; }

/* 16b chained patterns. */
void dim_tricky_init(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4A30;
extern f32 lbl_803E4A58;
extern f32 lbl_803E4A78;
extern f32 lbl_803E4AA0;

void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim2snowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E4A38;
void dim_tricky_render(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void dim2conveyor_free(int x);

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */

void dim2conveyor_setScale(int* obj, int unused, f32* outX, f32* outY);

extern int ObjHits_GetPriorityHit(int obj, void** outHitObj, int* outSphereIdx, uint* outHitVolume);

/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */

extern int ObjList_FindObjectById(int id);
extern void mm_free(void* p);
extern u8 lbl_803DBF20;
extern int* getTrickyObject(void);

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */
int fn_801B6D40(int* obj, int v);

u8 dim2pathgenerator_getCurveVals(int* obj, int** p1, int** p2, int** p3, int** p4)
{
    int* state = ((GameObject*)obj)->extra;
    *p1 = (int*)((char*)state + 12);
    *p2 = (int*)((char*)state + 812);
    *p3 = (int*)((char*)state + 1612);
    if (p4 != NULL)
    {
        *p4 = (int*)((char*)state + 2412);
    }
    return ((Dim2PathGeneratorState*)state)->curveValid;
}

void dll_1D6_free(int* obj);

void dim2pathgenerator_init(int* obj, int* def)
{
    Dim2PathGeneratorState* state;
    *(s16*)obj = (s16)((u32) * (u8*)((char*)def + 28) << 8);
    state = ((GameObject*)obj)->extra;
    state->spawnPeriod = ((Dim2pathgeneratorObjectDef*)def)->spawnPeriod;
    state->spawnTimer = (s16) * (u8*)((char*)def + 29);
    state->spawnTypes[0] = (s16)((Dim2pathgeneratorObjectDef*)def)->unk1E;
    {
        s16 v = ((Dim2pathgeneratorObjectDef*)def)->unk20;
        if (v == -1)
        {
            state->spawnTypes[1] = (s16)((Dim2pathgeneratorObjectDef*)def)->unk1E;
        }
        else
        {
            state->spawnTypes[1] = v;
        }
    }
    state->flags = (u8)(state->flags | 4);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

void dimtruthhornice_init(int* obj, int* def);

void dim2snowball_init(int* obj, int* def);

void dll_1CF_init(int* obj, int* def);

extern f32 lbl_803E4A28;
extern int getSaveGameLoadStatus(void);
extern void gameBitFn_800ea2e0(u8 n);
extern void unlockLevel(int a, int b, int c);

void dim_levelcontrol_init(int obj);

void dim_tricky_update(int* obj);

extern f32 mathCosf(f32 x);
extern f32 lbl_803E4A5C;
extern f32 lbl_803E4A60;
extern f32 lbl_803E4A64;
extern f32 lbl_803E4A68;
extern f32 lbl_803E4A6C;

void dim2conveyor_init(int* obj, u8* params);

void dim2conveyor_update(int* obj);

extern void* mmAlloc(int size, int a, int b);
extern void ObjModel_SetBlendChannelTargets(int* model, int a, int b, int c, f32 w, int d);
extern void ObjModel_SetBlendChannelWeight(int* model, int a, f32 w);
extern s16 lbl_803DBF18;
extern f32 lbl_803E4A88;

void dll_1D6_init(int* obj, u8* params);

extern f32 lbl_803E4A40;
extern f32 lbl_803E4A44;

void dimtruthhornice_update(int* obj);

extern int** ObjGroup_GetObjects(int group, int* countOut);

void dim2pathgenerator_update(int* obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
    extern int Obj_AllocObjectSetup(int kind, int id);
    int* def;
    int* extra = ((GameObject*)obj)->extra;
    int toggle;
    int** objs;
    int i;
    int count;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((Dim2pathgeneratorPlacement*)def)->unk22) == 0)
    {
        return;
    }
    if ((((Dim2PathGeneratorState*)extra)->flags & 4) != 0)
    {
        if ((((Dim2PathGeneratorState*)extra)->flags & 2) == 0)
        {
            int n = 21;
            int found = (*gRomCurveInterface)->find(&n, 1, 10, ((GameObject*)obj)->anim.localPosX,
                                                    ((GameObject*)obj)->anim.localPosY,
                                                    ((GameObject*)obj)->anim.localPosZ);
            if (found != -1)
            {
                int* cv = (int*)(*gRomCurveInterface)->getById(found);
                ((void (*)(int))(*gRomCurveInterface)->slot74)((int)cv);
                ((Dim2PathGeneratorState*)extra)->curveValid =
                    ((int (*)(int*, void*, void*, void*, void*))(*gRomCurveInterface)->slot78)(
                        cv, (char*)extra + 0xc, (char*)extra + 0x32c, (char*)extra + 0x64c,
                        (char*)extra + 0x96c);
                ((Dim2PathGeneratorState*)extra)->flags |= 2;
                ((Dim2PathGeneratorState*)extra)->originX = *(f32*)((char*)cv + 8);
                ((Dim2PathGeneratorState*)extra)->originY = *(f32*)((char*)cv + 0xc);
                ((Dim2PathGeneratorState*)extra)->originZ = *(f32*)((char*)cv + 0x10);
            }
        }
    }
    else
    {
        ((Dim2PathGeneratorState*)extra)->originX = ((GameObject*)obj)->anim.localPosX;
        ((Dim2PathGeneratorState*)extra)->originY = ((GameObject*)obj)->anim.localPosY;
        ((Dim2PathGeneratorState*)extra)->originZ = ((GameObject*)obj)->anim.localPosZ;
    }
    {
        s16 t = ((Dim2PathGeneratorState*)extra)->spawnTimer - framesThisStep;
        ((Dim2PathGeneratorState*)extra)->spawnTimer = t;
        if (t > 0)
        {
            return;
        }
    }
    toggle = ((Dim2PathGeneratorState*)extra)->flags & 1;
    ((Dim2PathGeneratorState*)extra)->spawnTimer = ((Dim2PathGeneratorState*)extra)->spawnPeriod;
    ((Dim2PathGeneratorState*)extra)->flags &= ~1;
    objs = ObjGroup_GetObjects(47, &count);
    for (i = 0; i < count; i++)
    {
        if (((Dim2PathGeneratorState*)extra)->spawnTypes[toggle] == *(s16*)((char*)objs[i] + 0x46))
        {
            int* p = *(int**)((char*)objs[i] + 0x4c);
            int c2;
            int j;
            int** o2;
            *(f32*)((char*)p + 8) = ((Dim2PathGeneratorState*)extra)->originX;
            *(f32*)((char*)p + 0xc) = ((Dim2PathGeneratorState*)extra)->originY;
            *(f32*)((char*)p + 0x10) = ((Dim2PathGeneratorState*)extra)->originZ;
            *(int*)((char*)p + 0x14) = ((Dim2pathgeneratorPlacement*)def)->unk14;
            (*(void (**)(int*, int))(**(int**)((char*)objs[i] + 0x68) + 4))(objs[i], 1);
            ObjGroup_RemoveObject(objs[i], 47);
            o2 = ObjGroup_GetObjects(47, &c2);
            for (j = 0; j < c2; j++)
            {
            }
            ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
            return;
        }
    }
    if (Obj_IsLoadingLocked())
    {
        int* np = (int*)Obj_AllocObjectSetup(36, ((Dim2PathGeneratorState*)extra)->spawnTypes[toggle]);
        *(f32*)((char*)np + 8) = ((Dim2PathGeneratorState*)extra)->originX;
        *(f32*)((char*)np + 0xc) = ((Dim2PathGeneratorState*)extra)->originY;
        *(f32*)&((ObjDef*)np)->jointData = ((Dim2PathGeneratorState*)extra)->originZ;
        *(u8*)((char*)np + 4) = ((Dim2pathgeneratorPlacement*)def)->unk4;
        *(u8*)((char*)np + 6) = ((Dim2pathgeneratorPlacement*)def)->unk6;
        *(u8*)((char*)np + 5) = ((Dim2pathgeneratorPlacement*)def)->unk5;
        *(u8*)((char*)np + 7) = ((Dim2pathgeneratorPlacement*)def)->unk7;
        *(u8*)((char*)np + 7) = 255;
        *(u8*)((char*)np + 3) = ((Dim2pathgeneratorPlacement*)def)->unk3;
        *(s8*)((char*)np + 0x18) = (s8) * (u8*)((char*)def + 0x1c);
        *(s16*)((char*)np + 0x1a) = *(u8*)((char*)def + 0x1a);
        *(s16*)((char*)np + 0x1c) = *(u8*)((char*)def + 0x1b);
        *(int*)((char*)np + 0x14) = ((Dim2pathgeneratorPlacement*)def)->unk14;
        Obj_SetupObject((int)np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
        ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
    }
}

extern void mtxRotateByVec3s(f32 * mtx, s16 * ang);
extern void Matrix_TransformPoint(f32* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 lbl_803E4A7C;
extern f32 lbl_803E4A80;
extern f32 lbl_803E4A84;
extern f32 lbl_803E4A8C;
extern f32 lbl_803E4A90;

void dll_1D6_update(int* obj);

extern int Curve_AdvanceAlongPath(int* extra, f32 t);
extern void Curve_BuildHermiteCoeffs(void);
extern void Curve_EvalHermite(void);
extern void curvesMove(int* extra);
extern int** ObjList_GetObjects(int* startOut, int* countOut);
extern void objMove(int* obj, f32 dx, f32 dy, f32 dz);
extern int objBboxFn_800640cc(void* a, void* b, f32 c, int d, int e, int* f, int g, int h, int i, int j);
extern int getAngle(f32 a, f32 b);
extern int hitDetectFn_80065e50(int* obj, f32 x, f32 y, f32 z, int*** listOut, int p3, int p4);
extern void Sfx_KeepAliveLoopedObjectSound(int* obj, int sfx);
extern f32 oneOverTimeDelta;
extern f32 lbl_803E4AA4;
extern f32 lbl_803E4AA8;
extern f32 lbl_803E4AAC;
extern f32 lbl_803E4AB0;
extern f32 lbl_803E4AB4;
extern f32 lbl_803E4AB8;
extern f32 lbl_803E4ABC;
extern f32 lbl_803E4AC0;
extern f64 lbl_803E4AC8;
extern f32 lbl_803E4AD0;

void dim2snowball_update(int* obj);
