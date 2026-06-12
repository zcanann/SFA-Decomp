#include "main/audio/sfx_ids.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
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

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

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























/* 8b "li r3, N; blr" returners. */

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);






/* render-with-fn(lbl) (no visibility check). */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */
extern void Music_Trigger(int trackId, int restart);


extern void* Obj_GetPlayerObject(void);

/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */


/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */







extern int getSaveGameLoadStatus(void);
















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










typedef struct Dim2lavacontrolState
{
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s8 unk2;
    u8 pad3[0x24 - 0x3];
    f32 unk24;
} Dim2lavacontrolState;






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














extern u32 GameBit_Get(int id);


/* dim2icefloe: per-frame curve-follow update + path-param init. */





/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */


/* dll_1DB_update: geyser state machine driven by player standing on it. */


/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */



/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */








/* 8b "li r3, N; blr" returners. */
int dim2lavacontrol_getExtraSize(void) { return 0x10; }
int dll_1DF_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4B90;




void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B90);
}

void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* dll_1DA_init: stash obj->f10 into *(obj->p_B8), then bump obj->f10 by a constant step. */

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */


/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */
void dim2lavacontrol_setScale(void* obj)
{
    void* sub = ((GameObject*)obj)->extra;
    if (((s32)((Dim2lavacontrolState*)sub)->unk2 & 1) == 0)
    {
        void* p = *(void**)&((GameObject*)obj)->anim.placementData;
        s8 cnt = ((Dim2lavacontrolState*)sub)->unk0;
        if ((s32)cnt > 0)
        {
            ((Dim2lavacontrolState*)sub)->unk0 = cnt - 1;
            if (((Dim2lavacontrolState*)sub)->unk0 == 0)
            {
                ((Dim2lavacontrolState*)sub)->unk2 = (s8)(*(u8*)&((Dim2lavacontrolState*)sub)->unk2 | 1);
                GameBit_Set(((Dim2lavacontrolPlacement*)p)->unk1E, 1);
            }
        }
    }
}

/* dim2lavacontrol_free: stop lava sfx, kill the lava music track, refresh time-of-day. */
extern void fn_8004C1E4(int sfxId, f32 vol);
extern void timeOfDayFn_80055000(void);

void dim2lavacontrol_free(void)
{
    fn_8004C1E4(0xC0, lbl_803E4B90);
    Music_Trigger(0xC4, 0);
    timeOfDayFn_80055000();
}

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern f32 lbl_803E4B9C, lbl_803E4BA0, lbl_803E4BA4;

void dll_1DF_update(void* obj);

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */

extern void envFxActFn_800887f8(int a);
extern u8 lbl_803DBF28[8];

void dim2lavacontrol_init(int obj, int param2)
{
    extern void gameBitFn_800ea2e0(int i);
    int state;
    int i;
    int g;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    for (i = 1; (u8)i <= 0x2d; i++)
    {
        gameBitFn_800ea2e0(i);
    }
    state = *(int*)&((GameObject*)obj)->extra;
    ((Dim2lavacontrolState*)state)->unk0 = (s8) * (s16*)(param2 + 0x1a);
    *(u8*)(state + 1) = *(u8*)&((Dim2lavacontrolState*)state)->unk0;
    if (GameBit_Get(*(s16*)(param2 + 0x1e)) != 0)
    {
        g = 1;
    }
    else
    {
        g = 0;
    }
    ((Dim2lavacontrolState*)state)->unk2 = (s8)(*(u8*)&((Dim2lavacontrolState*)state)->unk2 | g);
    *(int*)(state + 0xc) = 0xd7;
    *(u8*)(state + 4) = 0;
    if ((((Dim2lavacontrolState*)state)->unk2 & 1) != 0)
    {
        *(u8*)&((Dim2lavacontrolState*)state)->unk0 = 0;
        *(u8*)(state + 3) = lbl_803DBF28[0];
        fn_8004C1E4(lbl_803DBF28[0], lbl_803E4B90);
    }
    else
    {
        *(u8*)&((Dim2lavacontrolState*)state)->unk0 = 3;
        *(u8*)(state + 3) = lbl_803DBF28[3];
        fn_8004C1E4(lbl_803DBF28[3], lbl_803E4B90);
    }
    Music_Trigger(0xdd, 1);
    envFxActFn_800887f8(0);
}

extern int fn_802966D4(void* obj, f32* out);
extern void SCGameBitLatch_UpdateInverted(void* p, int mask, int a, int b, int e1, int e2);

void dim2lavacontrol_update(int obj)
{
    extern void SCGameBitLatch_Update(void* p, int mask, int a, int b, int e1, int e2);
    int diff;
    f32 local[3];
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((GameObject*)obj)->unkF4 == 2)
        {
            getEnvfxActImmediately(0, 0, 0x163, 0);
            getEnvfxActImmediately(0, 0, 0x166, 0);
            getEnvfxActImmediately(0, 0, 0x165, 0);
            getEnvfxActImmediately(0, 0, 0x164, 0);
        }
        else
        {
            getEnvfxAct(0, 0, 0x163, 0);
            getEnvfxAct(0, 0, 0x166, 0);
            getEnvfxAct(0, 0, 0x165, 0);
            getEnvfxAct(0, 0, 0x164, 0);
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    obj = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)(obj + 4) == 0)
    {
        if (GameBit_Get(0xacd) != 0)
        {
            GameBit_Set(0xcc3, 1);
            *(u8*)(obj + 4) = 1;
        }
    }
    diff = *(u8*)(obj + 3) - lbl_803DBF28[((Dim2lavacontrolState*)obj)->unk0];
    if (diff != 0)
    {
        if (diff > 0)
        {
            *(u8*)(obj + 3) -= 1;
        }
        else
        {
            *(u8*)(obj + 3) += 1;
        }
        fn_8004C1E4(*(u8*)(obj + 3), lbl_803E4B90);
    }
    if (fn_802966D4(Obj_GetPlayerObject(), local) != 0)
    {
        if ((*(int*)&((GameObject*)obj)->anim.rootMotionScale & 2) && *(int*)&((GameObject*)obj)->anim.localPosX !=
            0xe0)
        {
            Music_Trigger(*(int*)&((GameObject*)obj)->anim.localPosX, 0);
            *(int*)&((GameObject*)obj)->anim.localPosX = 0xe0;
            Music_Trigger(0xe0, 1);
        }
    }
    else
    {
        if ((*(int*)&((GameObject*)obj)->anim.rootMotionScale & 2) && *(int*)&((GameObject*)obj)->anim.localPosX !=
            0xd7)
        {
            Music_Trigger(*(int*)&((GameObject*)obj)->anim.localPosX, 0);
            *(int*)&((GameObject*)obj)->anim.localPosX = 0xd7;
            Music_Trigger(0xd7, 1);
        }
    }
    SCGameBitLatch_Update((char*)obj + 8, 1, -1, -1, 0xd99, 0xde);
    SCGameBitLatch_Update((char*)obj + 8, 2, -1, -1, 0xda5, *(int*)&((GameObject*)obj)->anim.localPosX);
    SCGameBitLatch_Update((char*)obj + 8, 8, -1, -1, 0xf04, 0x96);
    SCGameBitLatch_UpdateInverted((char*)obj + 8, 0x10, -1, -1, 0xf04, 0x2c);
    SCGameBitLatch_Update((char*)obj + 8, 4, -1, -1, 0xcbb, 0xc4);
}
