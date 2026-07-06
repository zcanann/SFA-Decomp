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



extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern int ObjList_FindObjectById(int id);
#include "main/dll/DIM/DIM2projrock.h"
#include "main/objhits.h"
#include "main/engine_shared.h"
#include "main/obj_placement.h"

#define DIM2ICEFLOE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIM2ICEFLOE_OBJFLAG_FREED 0x40

/* dim2icefloe romlist placement: ObjPlacement head (mapId@0x14 repurposed as
   the target-object id consumed at init), then class-specific bytes. */
typedef struct Dim2IceFloePlacement
{
    ObjPlacement base;
    s8 yawByte;     /* 0x18 */
    u8 pad19[3];
    s16 curveStep;  /* 0x1c */
} Dim2IceFloePlacement;

STATIC_ASSERT(offsetof(Dim2IceFloePlacement, yawByte) == 0x18);
STATIC_ASSERT(offsetof(Dim2IceFloePlacement, curveStep) == 0x1c);

extern void fn_80296D20(void* player, int obj);
extern f32 lbl_803E4B34;
extern f32 gDim2IceFloeSinkSpeed;
extern f32 gDim2IceFloeSinkFreeThreshold;
extern f32 lbl_803E4B48;
extern f32 lbl_803E4B4C;
extern f32 lbl_803E4B50;
extern f32 lbl_803E4B54;
extern f32 lbl_803E4B58;
extern f32 lbl_803E4B30;

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
        (((GameObject*)((Dim2IceFloeState*)sub)->followedObj)->objectFlags & DIM2ICEFLOE_OBJFLAG_FREED) != 0)
    {
        ((Dim2IceFloeState*)sub)->flags &= ~1;
        ((Dim2IceFloeState*)sub)->followedObj = 0;
    }
    else
    {
        int alpha;
        int reached;
        switch ((int)((Dim2IceFloeState*)sub)->paused)
        {
        case 0:
        alpha = ((GameObject*)obj)->anim.alpha + framesThisStep * 4;
        if (alpha > 0xff)
        {
            alpha = 0xff;
        }
        ((GameObject*)obj)->anim.alpha = alpha;
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
            ((GameObject*)obj)->anim.localPosY = -(gDim2IceFloeSinkSpeed * timeDelta - ((GameObject*)obj)->anim.localPosY);
            if (((GameObject*)obj)->anim.localPosY < ((Dim2IceFloeState*)sub)->curve.sample[1])
            {
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->objectFlags |= 0x100;
                fn_80296D20(Obj_GetPlayerObject(), obj);
            }
            if (((GameObject*)obj)->anim.localPosY < ((Dim2IceFloeState*)sub)->curve.sample[1] - gDim2IceFloeSinkFreeThreshold)
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
    Dim2IceFloePlacement* placement = (Dim2IceFloePlacement*)p;
    int sub = *(int*)&((GameObject*)obj)->extra;
    ((Dim2IceFloeState*)sub)->targetId = placement->base.mapId;
    ((Dim2IceFloeState*)sub)->curveStep = (f32)placement->curveStep / lbl_803E4B48;
    ((Dim2IceFloeState*)sub)->yawJitter = (f32)(s32)
    randomGetRange(-0x1e, 0x1e);
    placement->base.mapId = -1;
    objAnim->bankIndex = randomGetRange(0, objAnim->modelInstance->modelCount - 1);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)placement->yawByte << 8);
    ((GameObject*)obj)->anim.rotX = randomGetRange(0, 0xffff);
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
    ((GameObject*)obj)->objectFlags |= DIM2ICEFLOE_OBJFLAG_HITDETECT_DISABLED;
}

int dim2icefloe_getExtraSize(void) { return 0xbc; }
int dim2icefloe_getObjectTypeId(void) { return 0x0; }

void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4B30);
}
