/* === moved from main/dll/DIM/DIM2snowball.c [801B8798-801B8860) (TU re-split, docs/boundary_audit.md) === */
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"













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

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();

extern EffectInterface** gPartfxInterface;

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

extern void getEnvfxActImmediately(int a, int b, int id, int d);
extern void getEnvfxAct(int a, int b, int id, int d);
extern void Music_Trigger(int id, int value);
extern f32 timeDelta;


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






















void dll_1DA_free(void);

/* 8b "li r3, N; blr" returners. */
int dimtruthhornice_getExtraSize(void);
int dll_1DA_getExtraSize(void);
int dll_1DA_getObjectTypeId(void);

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4A30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4AD8;





void dll_1DA_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E4A38;

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */
extern void Music_Trigger(int trackId, int restart);


extern int ObjHits_GetPriorityHit(int obj, void** outHitObj, int* outSphereIdx, uint* outHitVolume);
extern float Vec_distance(float* a, float* b);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E4ADC;

/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */
void dll_1DA_hitDetect(int obj);

extern int ObjList_FindObjectById(int id);
extern u8 lbl_803DBF20;

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */







extern int getSaveGameLoadStatus(void);






extern void* mmAlloc(int size, int a, int b);




extern u8 framesThisStep;




extern void Curve_BuildHermiteCoeffs(void);


/* segment pragma-stack balance (re-split): */
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

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2projrock.h"
#include "main/objanim_internal.h"

typedef struct Dim2lavacontrolPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 unk19;
    u8 unk1A;
    u8 unk1B;
    s16 unk1C;
    s16 unk1E;
} Dim2lavacontrolPlacement;


typedef struct Dim2iciclePlacement
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 unkC;
    u8 pad10[0x1E - 0x10];
    s16 unk1E;
} Dim2iciclePlacement;


typedef struct Dll1DAState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} Dll1DAState;


typedef struct Dll1DFState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x24 - 0x7];
    f32 unk24;
} Dll1DFState;


typedef struct Dll1DBPlacement
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 unkC;
    u8 pad10[0x1E - 0x10];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} Dll1DBPlacement;


typedef struct Dim2lavacontrolState
{
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s8 unk2;
    u8 pad3[0x24 - 0x3];
    f32 unk24;
} Dim2lavacontrolState;


typedef struct Dll1DBState
{
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s8 unk2;
    u8 pad3[0x4 - 0x3];
    u8 unk4;
    u8 pad5[0x24 - 0x5];
    f32 unk24;
} Dll1DBState;


extern undefined4 ObjHits_AddContactObject();
extern int ObjHits_GetPriorityHit();


/*
 * --INFO--
 *
 * Function: FUN_801b8c60
 * EN v1.0 Address: 0x801B8C60
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B8D60
 * EN v1.1 Size: 48b
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
 * Function: FUN_801b9728
 * EN v1.0 Address: 0x801B9728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B9578
 * EN v1.1 Size: 576b
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
 * Function: FUN_801b972c
 * EN v1.0 Address: 0x801B972C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801B97B8
 * EN v1.1 Size: 524b
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
 * Function: FUN_801b9cc4
 * EN v1.0 Address: 0x801B9CC4
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801B9DC4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9cc4(int param_1)
{
    char* pcVar1;
    int iVar2;

    pcVar1 = ((GameObject*)param_1)->extra;
    if ((pcVar1[2] & 1U) == 0)
    {
        iVar2 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0'))
        {
            pcVar1[2] = pcVar1[2] | 1;
            GameBit_Set((int)*(short*)(iVar2 + 0x1e), 1);
        }
    }
    return;
}


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_1DA_release(void);

void dll_1DA_initialise(void);

void dll_1DB_free(void);

void dll_1DB_hitDetect(void);

void dll_1DB_release(void);

void dll_1DB_initialise(void);

void dim2icefloe_free(void);

void dim2icefloe_hitDetect(void);

void dim2icefloe_release(void);

void dim2icefloe_initialise(void);

void dim2icicle_free(void);

void dim2icicle_hitDetect(void);

void dim2icicle_release(void);

void dim2icicle_initialise(void);

extern u32 GameBit_Get(int id);
extern f32 lbl_803E4B80;

void dim2icicle_init(int obj, s8* p);

/* dim2icefloe: per-frame curve-follow update + path-param init. */
typedef struct
{
    u8 finished : 1;
    u8 rest : 7;
} IceFloeFlags;

extern void Curve_BuildHermiteCoeffs();
extern void fn_80296D20(void* player, int obj);
extern f32 lbl_803E4B34;
extern f32 lbl_803E4B38;
extern f32 lbl_803E4B3C;

void dim2icefloe_update(int obj);

extern f32 lbl_803E4B48;
extern f32 lbl_803E4B4C;
extern f32 lbl_803E4B50;
extern f32 lbl_803E4B54;
extern f32 lbl_803E4B58;

void dim2icefloe_init(int obj, int p);

/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */
extern WaterfxInterface** gWaterfxInterface;
extern f32 lbl_803E4B6C;
extern f32 lbl_803E4B70;
extern f32 lbl_803E4B74;
extern f32 lbl_803E4B78;
extern f32 lbl_803E4B7C;

void dim2icicle_update(int obj);

/* dll_1DB_update: geyser state machine driven by player standing on it. */
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 lbl_803E4B0C;
extern f32 lbl_803E4B10;
extern f32 lbl_803E4B14;
extern f32 lbl_803E4B18;
extern f32 lbl_803E4B1C;
extern f32 lbl_803E4B20;
extern f32 lbl_803E4B24;

void dll_1DB_update(int obj);

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */
extern f32 sqrtf(f32 x);
extern void saveGame_saveObjectPos(int obj);
extern f32 lbl_803E4AE0;
extern f32 lbl_803E4AE4;
extern f32 lbl_803E4AE8;
extern f32 lbl_803E4AEC;
extern f32 lbl_803E4AF0;
extern f32 lbl_803E4AF4;
extern f32 lbl_803E4AF8;
extern f32 lbl_803E4AFC;
extern f32 lbl_803E4B00;
extern const f32 lbl_803E4B04;

typedef struct
{
    int hit[7];
    f32 nx;
    f32 ny;
    f32 nz;
    int pad[8];
} RockHitInfo;

void dll_1DA_update(int obj);

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */
extern int* gBaddieControlInterface;
extern int* gPlayerInterface;
extern u8 lbl_803DDB84;
extern u8 lbl_80325960[];
extern u8 gDIMbossAnimController[];
extern int fn_801BC2D8(int a, int obj);
extern f32 lbl_803E4BB8;

typedef void (*BaddieQueryFn)(int a, int objId, int n, u16* anim, u16* pad, u16* dist);
typedef u8 (*BaddieCheckFn)(int a, int obj, f32 d);
typedef void (*PlayerAnimFn)(int a, int obj, int animId);

typedef struct
{
    u8 pad[0x168];
    s16 surprised[6]; /* 0x168 */
    s16 group3[8]; /* 0x174 */
    s16 group2[8]; /* 0x184 */
    s16 group1[8]; /* 0x194 */
} DimAnimTable;

int fn_801B9ECC(int a, int obj);

void dll_1DF_free(void)
{
}

void dll_1DF_hitDetect(void)
{
}

void dll_1DF_release(void)
{
}

void dll_1DF_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dll_1DB_getExtraSize(void);
int dll_1DB_getObjectTypeId(void);
int dim2icefloe_getExtraSize(void);
int dim2icefloe_getObjectTypeId(void);
int dim2icicle_getExtraSize(void);
int dim2icicle_getObjectTypeId(void);
int dim2lavacontrol_getExtraSize(void);
int dll_1DF_getExtraSize(void) { return 0x28; }
int dll_1DF_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4B08;
extern f32 lbl_803E4B30;
extern f32 lbl_803E4B68;
extern f32 lbl_803E4B90;
extern f32 lbl_803E4B98;

void dll_1DB_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B98);
}

/* dll_1DA_init: stash obj->f10 into *(obj->p_B8), then bump obj->f10 by a constant step. */
void dll_1DA_init(void* obj);

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */
extern f32 lbl_803E4BA8;
extern f32 lbl_803E4BAC;

void dll_1DF_init(void* obj, void* p)
{
    u32 flag;
    void* p50;
    void* p64;
    ((GameObject*)obj)->anim.rotZ = (s16)((u32) * (u8*)((char*)p + 0x18) << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((u32) * (u8*)((char*)p + 0x19) << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((u32) * (u8*)((char*)p + 0x1A) << 8);
    flag = *(u8*)((char*)p + 0x1B);
    if (flag != 0)
    {
        p50 = *(void**)&((GameObject*)obj)->anim.modelInstance;
        ((GameObject*)obj)->anim.rootMotionScale = ((ObjDef*)p50)->rootMotionScaleBase * ((f32)flag / lbl_803E4BA8);
    }
    *(f32*)((char*)*(void**)&((GameObject*)obj)->extra + 0x10) = lbl_803E4BAC;
    p64 = *(void**)&((GameObject*)obj)->anim.modelState;
    if (p64 != 0)
    {
        ((ObjModelState*)p64)->flags |= 0x810;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */
void dim2lavacontrol_setScale(void* obj);

/* dim2lavacontrol_free: stop lava sfx, kill the lava music track, refresh time-of-day. */
extern void fn_8004C1E4(int sfxId, f32 vol);
extern void timeOfDayFn_80055000(void);

void dim2lavacontrol_free(void);

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern f32 lbl_803E4B9C, lbl_803E4BA0, lbl_803E4BA4;

void dll_1DF_update(void* obj)
{
    extern void* objFindTexture(void* obj, int a, int b);
    void* sub = ((GameObject*)obj)->extra;
    void* tex;
    void* player;
    f32 dist;
    f32 t;

    tex = objFindTexture(obj, 0, 0);
    if (tex != 0)
    {
        if (((GameObject*)obj)->anim.seqId == 209)
        {
            f32 v = lbl_803E4B9C;
            *(u8*)((char*)tex + 0xC) = v;
            *(u8*)((char*)tex + 0xD) = v;
            *(u8*)((char*)tex + 0xE) = v;
        }
        else
        {
            f32 v = lbl_803E4B9C;
            *(u8*)((char*)tex + 0xC) = v;
            *(u8*)((char*)tex + 0xD) = v;
            *(u8*)((char*)tex + 0xE) = v;
        }
    }
    player = Obj_GetPlayerObject();
    dist = vec3f_distanceSquared(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
    if (dist < lbl_803E4BA0)
    {
        t = ((Dll1DFState*)sub)->unk24 - timeDelta;
        ((Dll1DFState*)sub)->unk24 = t;
        if (t < lbl_803E4B9C)
        {
            (*gPartfxInterface)->spawnObject(obj, 525, NULL, 2, -1, NULL);
            ((Dll1DFState*)sub)->unk24 = lbl_803E4BA4;
        }
    }
}

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */
void dll_1DB_init(void* obj, void* p);

extern void envFxActFn_800887f8(int a);
extern u8 lbl_803DBF28[8];

void dim2lavacontrol_init(int obj, int param2);

extern int fn_802966D4(void* obj, f32* out);
extern void SCGameBitLatch_UpdateInverted(void* p, int mask, int a, int b, int e1, int e2);

void dim2lavacontrol_update(int obj);
