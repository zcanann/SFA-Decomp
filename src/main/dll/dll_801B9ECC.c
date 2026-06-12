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

extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);


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























/* 8b "li r3, N; blr" returners. */

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */






/* render-with-fn(lbl) (no visibility check). */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */



/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */

extern u8 lbl_803DBF20;

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */













extern void* mmAlloc(int size, int a, int b);










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
















/* dim2icefloe: per-frame curve-follow update + path-param init. */





/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */


/* dll_1DB_update: geyser state machine driven by player standing on it. */


/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */



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

int fn_801B9ECC(int a, int obj)
{
    DimAnimTable* base;
    u16 pad;
    u16 dist;
    u16 anim[2];

    base = (DimAnimTable*)lbl_80325960;
    if (*(s8*)(obj + 0x346) != 0 || *(s8*)(obj + 0x27b) != 0)
    {
        (*(BaddieQueryFn)*(int*)(*gBaddieControlInterface + 0x14))(a, *(int*)(obj + 0x2d0), 0x10,
                                                                   anim, &pad, &dist);
        *(u8*)(obj + 0x346) = 0;
        if (dist < 0x5a)
        {
            if (dist > 0x1e &&
                ((u16)(anim[0] - 3) <= 1 || anim[0] == 0xb || anim[0] == 0xc))
            {
                (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(a, obj, 2);
            }
            else
            {
                (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(a, obj, 9);
            }
        }
        else if (anim[0] == 0 || anim[0] == 0xf)
        {
            *(u8*)(obj + 0x346) = 0;
            if (dist > 0x1a9 &&
                ((*(BaddieCheckFn)*(int*)(*gBaddieControlInterface + 0x18))(a, obj, lbl_803E4BB8) &
                    1) != 0)
            {
                (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(
                    a, obj, base->surprised[randomGetRange(0, 5)]);
            }
            else if (dist < 0xfa)
            {
                (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(a, obj, 3);
            }
            else
            {
                if (lbl_803DDB84 > 6)
                {
                    lbl_803DDB84 = 0;
                }
                switch (*(s8*)(obj + 0x354))
                {
                case 3:
                    (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(
                        a, obj, base->group3[lbl_803DDB84++]);
                    break;
                case 2:
                    (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(
                        a, obj, base->group2[lbl_803DDB84++]);
                    break;
                case 1:
                    (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(
                        a, obj, base->group1[lbl_803DDB84++]);
                    break;
                default:
                    (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(a, obj, 3);
                    break;
                }
            }
        }
        else
        {
            (*(PlayerAnimFn)*(int*)(*gPlayerInterface + 0x14))(a, obj, 2);
        }
    }
    if (*(s16*)(obj + 0x274) == 3 || *(s16*)(obj + 0x274) == 7)
    {
        gDIMbossAnimController[0x611] |= 1;
    }
    else
    {
        gDIMbossAnimController[0x611] &= ~1;
    }
    fn_801BC2D8(a, obj);
    return 0;
}

void dll_1DF_free(void);




/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */






/* dll_1DA_init: stash obj->f10 into *(obj->p_B8), then bump obj->f10 by a constant step. */

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */


/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */

/* dim2lavacontrol_free: stop lava sfx, kill the lava music track, refresh time-of-day. */


/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */


/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */




