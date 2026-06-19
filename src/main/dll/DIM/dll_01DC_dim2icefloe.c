/* DLL 0x1DC — DIM2 Ice Floe: floating ice platform that follows a hermite
 * curve path toward a target object, bobs, then sinks on arrival. */
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

extern u32 randomGetRange(int min, int max);
extern u32 ObjHits_DisableObject();

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
            ((Dim2IceFloeState*)sub)->curve.count = (*(VtableFn*)(**(int**)(((Dim2IceFloeState*)sub)->followedObj + 0x68) + 0x20))(
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


int dim2icefloe_getExtraSize(void) { return 0xbc; }
int dim2icefloe_getObjectTypeId(void) { return 0x0; }

void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B30);
}
