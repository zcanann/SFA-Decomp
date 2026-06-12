/* DLL 0x1DC - DIM2IceFloe [801B8798-801B8860) */
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

extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();


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


extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);
extern int ObjList_FindObjectById(int id);
extern u8 framesThisStep;
extern void Curve_BuildHermiteCoeffs(void);

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
#pragma scheduling on
#pragma peephole on
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
void dll_1DA_release(void);


#pragma scheduling off
#pragma peephole off
void dim2icefloe_free(void)
{
}

void dim2icefloe_hitDetect(void)
{
}

void dim2icefloe_release(void)
{
}

void dim2icefloe_initialise(void)
{
}

void dim2icicle_free(void);


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

void dim2icefloe_update(int obj)
{
    extern int Obj_FreeObject(int obj);
    extern int Curve_AdvanceAlongPath(int curve, f32 t);
    extern void curvesMove(int curves);
    extern f32 Curve_EvalHermite(f32 t, f32* values, f32* outTangent);
    int sub = *(int*)&((GameObject*)obj)->extra;
    if (*(void**)&((Dim2IceFloeState*)sub)->unk9C != NULL && (*(u16*)(((Dim2IceFloeState*)sub)->unk9C + 0xb0) & 0x40) !=
        0)
    {
        ((Dim2IceFloeState*)sub)->unkB6 &= ~1;
        ((Dim2IceFloeState*)sub)->unk9C = 0;
    }
    else
    {
        int v;
        int reached;
        if ((int)((Dim2IceFloeState*)sub)->unkB8 != 0)
        {
            return;
        }
        v = ((GameObject*)obj)->anim.alpha + framesThisStep * 4;
        if (v > 0xff)
        {
            v = 0xff;
        }
        ((GameObject*)obj)->anim.alpha = v;
        if ((((Dim2IceFloeState*)sub)->unkB6 & 1) == 0)
        {
            ((Dim2IceFloeState*)sub)->unk9C = ObjList_FindObjectById(((Dim2IceFloeState*)sub)->objectId);
            ((Dim2IceFloeState*)sub)->unk90 = (*(code*)(**(int**)(((Dim2IceFloeState*)sub)->unk9C + 0x68) + 0x20))(
                ((Dim2IceFloeState*)sub)->unk9C, sub + 0x84, sub + 0x88, sub + 0x8c, 0);
            ((Dim2IceFloeState*)sub)->unk80 = 0;
            ((Dim2IceFloeState*)sub)->unk94 = (void*)Curve_EvalHermite;
            ((Dim2IceFloeState*)sub)->unk98 = (void*)Curve_BuildHermiteCoeffs;
            curvesMove(sub);
            ((Dim2IceFloeState*)sub)->unkB6 |= 1;
        }
        Curve_AdvanceAlongPath(sub, ((Dim2IceFloeState*)sub)->unkA4);
        reached = ((Dim2IceFloeState*)sub)->unk10 >= ((Dim2IceFloeState*)sub)->unk90 - 4;
        ((GameObject*)obj)->anim.localPosX = ((Dim2IceFloeState*)sub)->unk68;
        if (!((IceFloeFlags*)(sub + 0xb9))->finished)
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E4B34 + ((Dim2IceFloeState*)sub)->unk6C;
        }
        ((GameObject*)obj)->anim.localPosZ = ((Dim2IceFloeState*)sub)->unk70;
        if (reached)
        {
            ((IceFloeFlags*)(sub + 0xb9))->finished = 1;
        }
        ((Dim2IceFloeState*)sub)->unkB4 = timeDelta * ((Dim2IceFloeState*)sub)->unkAC + (f32) * (u16*)&((
            Dim2IceFloeState*)sub)->unkB4;
        if (((IceFloeFlags*)(sub + 0xb9))->finished)
        {
            ((GameObject*)obj)->anim.localPosY = -(lbl_803E4B38 * timeDelta - ((GameObject*)obj)->anim.localPosY);
            if (((GameObject*)obj)->anim.localPosY < ((Dim2IceFloeState*)sub)->unk6C)
            {
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->objectFlags |= 0x100;
                fn_80296D20(Obj_GetPlayerObject(), obj);
            }
            if (((GameObject*)obj)->anim.localPosY < ((Dim2IceFloeState*)sub)->unk6C - lbl_803E4B3C)
            {
                Obj_FreeObject(obj);
            }
        }
    }
}

extern f32 lbl_803E4B48;
extern f32 lbl_803E4B4C;
extern f32 lbl_803E4B50;
extern f32 lbl_803E4B54;
extern f32 lbl_803E4B58;

void dim2icefloe_init(int obj, int p)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int sub = *(int*)&((GameObject*)obj)->extra;
    ((Dim2IceFloeState*)sub)->objectId = *(int*)(p + 0x14);
    ((Dim2IceFloeState*)sub)->unkA4 = (f32) * (s16*)(p + 0x1c) / lbl_803E4B48;
    ((Dim2IceFloeState*)sub)->unkA8 = (f32)(s32)
    randomGetRange(-0x1e, 0x1e);
    *(int*)(p + 0x14) = -1;
    objAnim->bankIndex = (s8)randomGetRange(0, objAnim->modelInstance->modelCount - 1);
    ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)(p + 0x18) << 8);
    ((GameObject*)obj)->anim.rotX = (s16)randomGetRange(0, 0xffff);
    ((GameObject*)obj)->anim.alpha = 0;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x109:
        ((Dim2IceFloeState*)sub)->unkAC = lbl_803E4B4C + (f32)(s32)
        randomGetRange(0, 0x28);
        ((Dim2IceFloeState*)sub)->unkB0 = lbl_803E4B50;
        break;
    case 0x10d:
        ((Dim2IceFloeState*)sub)->unkAC = lbl_803E4B54 + (f32)(s32)
        randomGetRange(0, 0x32);
        ((Dim2IceFloeState*)sub)->unkB0 = lbl_803E4B50;
        break;
    case 0x111:
    default:
        ((Dim2IceFloeState*)sub)->unkAC = lbl_803E4B58 + (f32)(s32)
        randomGetRange(0, 0x28);
        ((Dim2IceFloeState*)sub)->unkB0 = lbl_803E4B50;
        break;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */
extern WaterfxInterface** gWaterfxInterface;

void dim2icicle_update(int obj);

/* dll_1DB_update: geyser state machine driven by player standing on it. */


/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */


/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */


/* 8b "li r3, N; blr" returners. */
int dim2icefloe_getExtraSize(void) { return 0xbc; }
int dim2icefloe_getObjectTypeId(void) { return 0x0; }
int dim2icicle_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4B30;


void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B30);
}

void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


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

