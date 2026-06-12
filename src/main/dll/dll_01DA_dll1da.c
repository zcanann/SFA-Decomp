/* === moved from main/dll/DIM/DIM2snowball.c [801B8798-801B8860) (TU re-split, docs/boundary_audit.md) === */
#include "main/audio/sfx_ids.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dll1_types.h"
#include "main/dll/dim2_types.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"













/* dim2conveyor_getExtraSize == 0x14. */


STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

/* dll_1D6_getExtraSize == 0x20 (crusher platform). */


STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

/* dimtruthhornice_getExtraSize == 0x8. */


STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

/* dim2snowball_getExtraSize == 0xb0 (curve walker head + roll state). */


STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */


STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern undefined4 GameBit_Set(int eventId, int value);


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






















void dll_1DA_free(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dimtruthhornice_getExtraSize(void);
int dll_1DA_getExtraSize(void) { return 0x8; }
int dll_1DA_getObjectTypeId(void) { return 0x0; }

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4A30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4AD8;





void dll_1DA_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4AD8);
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E4A38;

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */


extern int ObjHits_GetPriorityHit(int obj, void** outHitObj, int* outSphereIdx, uint* outHitVolume);
extern float Vec_distance(float* a, float* b);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E4ADC;

/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */
void dll_1DA_hitDetect(int obj)
{
    extern int Sfx_PlayFromObject(int obj, int sfxId);
    void* hi;
    void* player;
    f32 k;
    int hit = ObjHits_GetPriorityHit(obj, &hi, NULL, NULL);
    if (hit == 0xE)
    {
        player = Obj_GetPlayerObject();
        Vec_distance((float*)&((GameObject*)obj)->anim.worldPosX, (float*)((int)player + 0x18));
        ((GameObject*)obj)->anim.velocityX = *(f32*)((int)hi + 0x24) * (k = lbl_803E4ADC);
        ((GameObject*)obj)->anim.velocityZ = *(f32*)((int)hi + 0x2c) * k;
        Sfx_PlayFromObject(obj, SFXchar_puts_out_fire);
    }
}

extern int ObjList_FindObjectById(int id);
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





typedef struct Dll1DAState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} Dll1DAState;










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
void dll_1DA_release(void)
{
}

void dll_1DA_initialise(void)
{
}

void dll_1DB_free(void);














/* dim2icefloe: per-frame curve-follow update + path-param init. */





/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */


/* dll_1DB_update: geyser state machine driven by player standing on it. */


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

void dll_1DA_update(int obj)
{
    extern int objBboxFn_800640cc(int a, int b, f32 r, int c, int* out, int obj, int d, int e, int f, int g);
    extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
    extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* out, int a, int b);
    int sub;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 len;
    f32 k;
    f32 hi;
    f32 lo;
    f32 e;
    f32 d;
    int n;
    int list;
    int p;
    int i;
    RockHitInfo out;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (((Dll1DAState*)sub)->unk4 != 0)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AE0);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AE4);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
    }
    if (((GameObject*)obj)->anim.velocityX < (hi = lbl_803E4AE8) && ((GameObject*)obj)->anim.velocityX > (lo =
            lbl_803E4AEC) &&
        ((GameObject*)obj)->anim.velocityZ < hi && ((GameObject*)obj)->anim.velocityZ > lo)
    {
        ((GameObject*)obj)->anim.velocityX = (k = lbl_803E4AF0);
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, lbl_803E4AF0,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    n = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E4AF4, 1, out.hit, obj, 8, -1, 0xff, 0);
    if (n != 0)
    {
        vx = -((GameObject*)obj)->anim.velocityX;
        vy = -((GameObject*)obj)->anim.velocityY;
        vz = -((GameObject*)obj)->anim.velocityZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (lbl_803E4AF0 != len)
        {
            f32 s = lbl_803E4AD8 / len;
            vx = vx * s;
            vy = vy * s;
            vz = vz * s;
        }
        d = lbl_803E4AF8 * (vz * out.nz + (vx * out.nx + vy * out.ny));
        ((GameObject*)obj)->anim.velocityX = out.nx * d;
        ((GameObject*)obj)->anim.velocityY = out.ny * d;
        ((GameObject*)obj)->anim.velocityZ = out.nz * d;
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - vx;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - vy;
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - vz;
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (e = lbl_803E4AFC * len);
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (lbl_803E4ADC * len);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * e;
    }
    ((GameObject*)obj)->anim.localPosY = -(lbl_803E4B00 * timeDelta - ((GameObject*)obj)->anim.localPosY);
    n = hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ, obj,
                             &list, 0, 0x11);
    ((Dll1DAState*)sub)->unk4 = 0;
    i = 0;
    p = list;
    for (; n > 0; n--)
    {
        if (((GameObject*)obj)->anim.localPosY < lbl_803E4B04 + **(f32**)p)
        {
            ((GameObject*)obj)->anim.localPosY = **(f32**)(list + i * 4);
            ObjHits_AddContactObject(*(int*)(*(int*)(list + i * 4) + 0x10), obj);
            ((Dll1DAState*)sub)->unk4 = 1;
            break;
        }
        p += 4;
        i += 1;
    }
    if (((GameObject*)obj)->anim.localPosY < *(f32*)sub)
    {
        ((GameObject*)obj)->anim.localPosY = *(f32*)sub;
    }
    saveGame_saveObjectPos(obj);
}

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */
extern int* gBaddieControlInterface;



int fn_801B9ECC(int a, int obj);





/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */






/* dll_1DA_init: stash obj->f10 into *(obj->p_B8), then bump obj->f10 by a constant step. */
void dll_1DA_init(void* obj)
{
    *(*(f32**)&((GameObject*)obj)->extra) = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E4AD8;
}

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */
extern f32 lbl_803E4BA8;

void dll_1DF_init(void* obj, void* p);

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




