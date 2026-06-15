/* DLL 0x1DC - DIM2IceFloe [801B8798-801B8860) */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();

extern f32 timeDelta;

extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);
extern int ObjList_FindObjectById(int id);
extern u8 framesThisStep;

#include "main/game_object.h"
#include "main/dll/DIM/DIM2projrock.h"

#pragma scheduling on
#pragma peephole on
extern void fn_80296D20(void* player, int obj);
extern f32 lbl_803E4B34;
extern f32 lbl_803E4B38;
extern f32 lbl_803E4B3C;
extern f32 lbl_803E4B48;
extern f32 lbl_803E4B4C;
extern f32 lbl_803E4B50;
extern f32 lbl_803E4B54;
extern f32 lbl_803E4B58;
extern f32 lbl_803E4B30;

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


/* dim2icefloe: per-frame curve-follow update + path-param init. */
typedef struct
{
    u8 finished : 1;
    u8 rest : 7;
} IceFloeFlags;

void dim2icefloe_update(int obj)
{
    extern int Obj_FreeObject(int obj);
    int sub = *(int*)&((GameObject*)obj)->extra;
    if (*(void**)&((Dim2IceFloeState*)sub)->followedObj != NULL &&
        (((GameObject*)((Dim2IceFloeState*)sub)->followedObj)->objectFlags & 0x40) != 0)
    {
        ((Dim2IceFloeState*)sub)->flags &= ~1;
        ((Dim2IceFloeState*)sub)->followedObj = 0;
    }
    else
    {
        int v;
        int reached;
        switch ((int)((Dim2IceFloeState*)sub)->paused)
        {
        case 0:
        v = ((GameObject*)obj)->anim.alpha + framesThisStep * 4;
        if (v > 0xff)
        {
            v = 0xff;
        }
        ((GameObject*)obj)->anim.alpha = v;
        if ((((Dim2IceFloeState*)sub)->flags & 1) == 0)
        {
            ((Dim2IceFloeState*)sub)->followedObj = ObjList_FindObjectById(((Dim2IceFloeState*)sub)->targetId);
            ((Dim2IceFloeState*)sub)->curve.count = (*(code*)(**(int**)(((Dim2IceFloeState*)sub)->followedObj + 0x68) + 0x20))(
                ((Dim2IceFloeState*)sub)->followedObj, sub + 0x84, sub + 0x88, sub + 0x8c, 0);
            ((Dim2IceFloeState*)sub)->curve.dir = 0;
            ((Dim2IceFloeState*)sub)->curve.eval = Curve_EvalHermite;
            ((Dim2IceFloeState*)sub)->curve.coeffFn = Curve_BuildHermiteCoeffs;
            curvesMove(&((Dim2IceFloeState*)sub)->curve);
            ((Dim2IceFloeState*)sub)->flags |= 1;
        }
        Curve_AdvanceAlongPath(&((Dim2IceFloeState*)sub)->curve, ((Dim2IceFloeState*)sub)->curveStep);
        reached = ((Dim2IceFloeState*)sub)->curve.idx >= ((Dim2IceFloeState*)sub)->curve.count - 4;
        ((GameObject*)obj)->anim.localPosX = ((Dim2IceFloeState*)sub)->curve.sample[0];
        if (!((IceFloeFlags*)(sub + 0xb9))->finished)
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E4B34 + ((Dim2IceFloeState*)sub)->curve.sample[1];
        }
        ((GameObject*)obj)->anim.localPosZ = ((Dim2IceFloeState*)sub)->curve.sample[2];
        if (reached)
        {
            ((IceFloeFlags*)(sub + 0xb9))->finished = 1;
        }
        ((Dim2IceFloeState*)sub)->bobPhase = timeDelta * ((Dim2IceFloeState*)sub)->bobRate + (f32) * (u16*)&((
            Dim2IceFloeState*)sub)->bobPhase;
        if (((IceFloeFlags*)(sub + 0xb9))->finished)
        {
            ((GameObject*)obj)->anim.localPosY = -(lbl_803E4B38 * timeDelta - ((GameObject*)obj)->anim.localPosY);
            if (((GameObject*)obj)->anim.localPosY < ((Dim2IceFloeState*)sub)->curve.sample[1])
            {
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->objectFlags |= 0x100;
                fn_80296D20(Obj_GetPlayerObject(), obj);
            }
            if (((GameObject*)obj)->anim.localPosY < ((Dim2IceFloeState*)sub)->curve.sample[1] - lbl_803E4B3C)
            {
                Obj_FreeObject(obj);
            }
        }
        break;
        default:
            break;
        }
    }
}

void dim2icefloe_init(int obj, int p)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int sub = *(int*)&((GameObject*)obj)->extra;
    ((Dim2IceFloeState*)sub)->targetId = *(int*)(p + 0x14);
    ((Dim2IceFloeState*)sub)->curveStep = (f32) * (s16*)(p + 0x1c) / lbl_803E4B48;
    ((Dim2IceFloeState*)sub)->yawJitter = (f32)(s32)
    randomGetRange(-0x1e, 0x1e);
    *(int*)(p + 0x14) = -1;
    objAnim->bankIndex = (s8)randomGetRange(0, objAnim->modelInstance->modelCount - 1);
    ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)(p + 0x18) << 8);
    ((GameObject*)obj)->anim.rotX = (s16)randomGetRange(0, 0xffff);
    ((GameObject*)obj)->anim.alpha = 0;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x109:
        ((Dim2IceFloeState*)sub)->bobRate = lbl_803E4B4C + (f32)(s32)
        randomGetRange(0, 0x28);
        ((Dim2IceFloeState*)sub)->bobBase = lbl_803E4B50;
        break;
    case 0x10d:
        ((Dim2IceFloeState*)sub)->bobRate = lbl_803E4B54 + (f32)(s32)
        randomGetRange(0, 0x32);
        ((Dim2IceFloeState*)sub)->bobBase = lbl_803E4B50;
        break;
    case 0x111:
    default:
        ((Dim2IceFloeState*)sub)->bobRate = lbl_803E4B58 + (f32)(s32)
        randomGetRange(0, 0x28);
        ((Dim2IceFloeState*)sub)->bobBase = lbl_803E4B50;
        break;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}


/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */

int dim2icefloe_getExtraSize(void) { return 0xbc; }
int dim2icefloe_getObjectTypeId(void) { return 0x0; }

void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B30);
}


/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */

/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */
