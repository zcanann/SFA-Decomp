/* DLL 0x1DC - DIM2 Ice Floe: floating ice platform that follows a hermite
 * curve path toward a target object, bobs, then sinks on arrival. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* DIM2PathGenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);




#include "main/dll/DIM/dll_01DC_dim2icefloe.h"
#include "main/curve.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/dll/player_api.h"

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


int dim2icefloe_getExtraSize(void) { return 0xbc; }
int dim2icefloe_getObjectTypeId(void) { return 0x0; }

void dim2icefloe_free(void)
{
}

void dim2icefloe_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dim2icefloe_hitDetect(void)
{
}

typedef struct
{
    u8 finished : 1;
    u8 rest : 7;
} IceFloeFlags;

void dim2icefloe_update(GameObject *obj)
{
    Dim2IceFloeState* sub = (Dim2IceFloeState*)(obj)->extra;
    if (*(void**)&sub->followedObj != NULL &&
        (((GameObject*)sub->followedObj)->objectFlags & DIM2ICEFLOE_OBJFLAG_FREED) != 0)
    {
        sub->flags &= ~1;
        sub->followedObj = 0;
    }
    else
    {
        int alpha;
        int reached;
        switch ((int)sub->paused)
        {
        case 0:
        alpha = (obj)->anim.alpha + framesThisStep * 4;
        if (alpha > 0xff)
        {
            alpha = 0xff;
        }
        (obj)->anim.alpha = alpha;
        if ((sub->flags & 1) == 0)
        {
            sub->followedObj =
                (int)ObjList_FindObjectById(sub->targetId);
            sub->curve.count = (*(VtableFn*)(**(int**)(sub->followedObj + 0x68) + 0x20))(
                sub->followedObj, (int)sub + 0x84, (int)sub + 0x88, (int)sub + 0x8c, 0);
            sub->curve.dir = 0;
            sub->curve.eval = Curve_EvalHermite;
            sub->curve.coeffFn = Curve_BuildHermiteCoeffs;
            curvesMove(&sub->curve);
            sub->flags |= 1;
        }
        Curve_AdvanceAlongPath(&sub->curve, sub->curveStep);
        reached = sub->curve.idx >= sub->curve.count - 4;
        (obj)->anim.localPosX = sub->curve.sample[0];
        if (!((IceFloeFlags*)((char*)sub + 0xb9))->finished)
        {
            (obj)->anim.localPosY = 5.0f + sub->curve.sample[1];
        }
        (obj)->anim.localPosZ = sub->curve.sample[2];
        if (reached)
        {
            ((IceFloeFlags*)((char*)sub + 0xb9))->finished = 1;
        }
        sub->bobPhase = timeDelta * sub->bobRate + (f32) * (u16*)&((
            Dim2IceFloeState*)sub)->bobPhase;
        if (((IceFloeFlags*)((char*)sub + 0xb9))->finished)
        {
            (obj)->anim.localPosY = -(0.3f * timeDelta - (obj)->anim.localPosY);
            if ((obj)->anim.localPosY < sub->curve.sample[1])
            {
                ObjHits_DisableObject(obj);
                (obj)->objectFlags |= 0x100;
                fn_80296D20(Obj_GetPlayerObject(), obj);
            }
            if ((obj)->anim.localPosY < sub->curve.sample[1] - 50.0f)
            {
                Obj_FreeObject((GameObject*)obj);
            }
        }
        break;
        default:
            break;
        }
    }
}

void dim2icefloe_init(GameObject *obj, int p)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    Dim2IceFloePlacement* placement = (Dim2IceFloePlacement*)p;
    Dim2IceFloeState* sub = (Dim2IceFloeState*)(obj)->extra;
    sub->targetId = placement->base.mapId;
    sub->curveStep = (f32)placement->curveStep / 100.0f;
    sub->yawJitter = (f32)(s32)
    randomGetRange(-0x1e, 0x1e);
    placement->base.mapId = -1;
    objAnim->bankIndex = randomGetRange(0, objAnim->modelInstance->modelCount - 1);
    (obj)->anim.rotX = (s16)((s32)placement->yawByte << 8);
    (obj)->anim.rotX = randomGetRange(0, 0xffff);
    (obj)->anim.alpha = 0;
    switch ((obj)->anim.seqId)
    {
    case 0x109:
        sub->bobRate = 180.0f + (f32)(s32)
        randomGetRange(0, 0x28);
        sub->bobBase = 2.0f;
        break;
    case 0x10d:
        sub->bobRate = 200.0f + (f32)(s32)
        randomGetRange(0, 0x32);
        sub->bobBase = 2.0f;
        break;
    case 0x111:
    default:
        sub->bobRate = 196.0f + (f32)(s32)
        randomGetRange(0, 0x28);
        sub->bobBase = 2.0f;
        break;
    }
    (obj)->objectFlags |= DIM2ICEFLOE_OBJFLAG_HITDETECT_DISABLED;
}

void dim2icefloe_release(void)
{
}

void dim2icefloe_initialise(void)
{
}

ObjectDescriptor gDIM2IceFloeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dim2icefloe_initialise,
    (ObjectDescriptorCallback)dim2icefloe_release,
    0,
    (ObjectDescriptorCallback)dim2icefloe_init,
    (ObjectDescriptorCallback)dim2icefloe_update,
    (ObjectDescriptorCallback)dim2icefloe_hitDetect,
    (ObjectDescriptorCallback)dim2icefloe_render,
    (ObjectDescriptorCallback)dim2icefloe_free,
    (ObjectDescriptorCallback)dim2icefloe_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dim2icefloe_getExtraSize,
};
