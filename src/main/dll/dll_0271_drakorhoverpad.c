/*
 * drakorhoverpad (DLL 0x271) - a rideable hover-pad object in the
 * Drakor (DR) levels that follows a ROM spline/curve network.
 *
 * initMain seeds the pad onto its curve and selects a behaviour mode
 * from its placement subtype; updateMain advances the pad along the
 * active curve each step, applying a sinusoidal vertical bob, banking
 * the model toward its travel direction, and steering the object
 * toward the curve sample point. update() picks the next path point in
 * the network (masked vs unmasked branch) and recomputes the per-node
 * velocity/tangent data. handlePathPointEvent dispatches the per-node
 * event ids: speed flips, state changes, camera shake / view offset
 * while the player is riding, and the game bits that gate the ride.
 * render emits the trailing particle spray on a frame cadence.
 *
 * Curve/velocity state lives in the object's extra block
 * (DrakorHoverpadState, 0x17c bytes); the two flag bytes at 0x178/0x179
 * are DrakorHoverpadFlags / DrakorHoverpadPathFlags.
 */
#include "main/dll/dll_0271_drakorhoverpad.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "string.h"
#include "main/curve.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/objhits.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/objprint_api.h"
#include "main/vecmath.h"
#include "main/audio/sfx_play_int_u16_legacy_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"

f32 lbl_803DC2F8 = 5.0f;
s16 lbl_803DC2FC = 3;
f32 lbl_803DC300 = 5.0f;
f32 lbl_803DC304 = -40.0f;

/*
 * A ROM curve network node (the record returned by gRomCurveInterface->getById
 * and walked through anim.currentMove / anim.activeMoveProgress / anim.targetObj
 * in drakorhoverpad_update). The leading layout matches ObjfsaRomCurveDef
 * (pos at 0x8/0xc/0x10, blockedLinkMask at 0x1b, linkIds[4] at 0x1c); this view
 * extends it with the per-node tangent record at 0x2c-0x2e that the hover-pad
 * uses to derive its bob / banking velocity.
 */
typedef struct DrakorCurveNode
{
    u8 pad0[0x8 - 0x0];
    f32 x; /* 0x08 */
    f32 y; /* 0x0c */
    f32 z; /* 0x10 */
    u8 pad14[0x2C - 0x14];
    s8 tangentYaw;   /* 0x2c << 8 -> yaw angle */
    s8 tangentPitch; /* 0x2d << 8 -> pitch angle */
    u8 tangentMag;   /* 0x2e magnitude scalar */
} DrakorCurveNode;

typedef struct DrakorHoverpadUpdateMainPlacement
{
    s16 subtype;
    u8 pad02[0x18 - 0x02];
    s8 rotXByte;
    u8 pad19[0x1a - 0x19];
    s16 unk1a;
    u8 pad1c[0x20 - 0x1c];
    s16 activateGameBit;
    u8 pad22[0x28 - 0x22];
} DrakorHoverpadUpdateMainPlacement;

typedef struct DrakorHoverpadUpdateMainState
{
    u8 pad0[0xD8 - 0x0];
    f32 unkD8;
    u8 padDC[0xE0 - 0xDC];
    f32 unkE0;
    f32 unkE4;
    u8 padE8[0x110 - 0xE8];
    f32 verticalVel;
    f32 targetSpeed;
    u8 pad118[0x174 - 0x118];
    s16 anglePhase;
    u8 pad176[0x178 - 0x176];
} DrakorHoverpadUpdateMainState;

typedef struct DrakorHoverpadRenderState
{
    u8 pad0[0xD8 - 0x0];
    f32 unkD8;
    u8 padDC[0xE0 - 0xDC];
    f32 unkE0;
    f32 unkE4;
    u8 padE8[0x110 - 0xE8];
    f32 verticalVel;
    f32 targetSpeed;
    u8 pad118[0x154 - 0x118];
    f32 particleEmitAX; /* 0x154: emit point A, X (jittered) */
    f32 particleEmitAY; /* 0x158 */
    f32 particleEmitAZ; /* 0x15c: emit point A, Z (jittered) */
    f32 particleEmitBX; /* 0x160: emit point B, X (jittered) */
    f32 particleEmitBY; /* 0x164 */
    f32 particleEmitBZ; /* 0x168: emit point B, Z (jittered) */
    u8 pad16C[0x174 - 0x16C];
    s16 anglePhase;
    s16 frameCounter;
    u8 pad178[0x17C - 0x178];
} DrakorHoverpadRenderState;

typedef struct DrakorHoverpadHandlePathPointEventState
{
    u8 pad0[0xD8 - 0x0];
    f32 unkD8;
    u8 padDC[0xE0 - 0xDC];
    f32 unkE0;
    f32 unkE4;
    u8 padE8[0x110 - 0xE8];
    f32 verticalVel;
    f32 targetSpeed;
    u8 pad118[0x154 - 0x118];
    f32 particleEmitAX; /* 0x154 */
    f32 particleEmitAY; /* 0x158 */
    f32 particleEmitAZ; /* 0x15c */
    f32 particleEmitBX; /* 0x160 */
    f32 particleEmitBY; /* 0x164 */
    f32 particleEmitBZ; /* 0x168 */
    u8 pad16C[0x174 - 0x16C];
    s16 anglePhase;   /* 0x174 */
    s16 frameCounter; /* 0x176 */
} DrakorHoverpadHandlePathPointEventState;

typedef struct DrakorHoverpadState
{
    f32 unk00;
    RomCurveWalker curve; /* 0x004 */
    u8 pad10C[4];
    f32 speed;       /* 0x110 */
    f32 targetSpeed; /* 0x114 */
    f32 unk118;
    f32 unk11C;
    f32 unk120;
    u8 pad124[0x30];
    f32 particleEmitAX; /* 0x154 */
    f32 particleEmitAY; /* 0x158 */
    f32 particleEmitAZ; /* 0x15c */
    f32 particleEmitBX; /* 0x160 */
    f32 particleEmitBY; /* 0x164 */
    f32 particleEmitBZ; /* 0x168 */
    u8 pad16C[4];
    int unk170;
    s16 anglePhase;
    s16 frameCounter;
    u8 pad178[4];
} DrakorHoverpadState;

STATIC_ASSERT(sizeof(DrakorHoverpadState) == 0x17c);

/* placement subtype id (desc[0]) selecting the pad behaviour mode */
#define DRAKORHOVERPAD_SUBTYPE_TRACKING   1812 /* tracks/yaws toward a nearby object */
#define DRAKORHOVERPAD_SUBTYPE_FREE       1048 /* free curve-follow, no tracking */
#define DRAKORHOVERPAD_OBJGROUP           0x46
#define DRAKORHOVERPAD_OBJGROUP_SECONDARY 0xa
#define DRAKORHOVERPAD_HIT_VOLUME_SLOT    8
/* group owned by another DLL, queried here */
#define BOSSDRAKOR_OBJGROUP 0x45 /* DLL 0x24D bossdrakor */

int drakorhoverpad_func0B(void)
{
    return 0x1;
}

int drakorhoverpad_func0E(void)
{
    return 0x1;
}

int drakorhoverpad_func10(void)
{
    return 0x0;
}

void drakorhoverpad_func11(void)
{
}

int drakorhoverpad_func14(void)
{
    return 0x0;
}

void drakorhoverpad_func15(void)
{
}

int drakorhoverpad_getExtraSize(void)
{
    return 0x17c;
}

int drakorhoverpad_getObjectTypeId(void)
{
    return 0x0;
}

void drakorhoverpad_hitDetect(void)
{
}

void drakorhoverpad_initialise(void)
{
}

void drakorhoverpad_release(void)
{
}

void drakorhoverpad_initMain(GameObject* obj, void* desc)
{
    u8* p = (obj)->extra;
    DrakorHoverpadFlags* f = (DrakorHoverpadFlags*)(p + 0x178);
    DrakorHoverpadPathFlags* g = (DrakorHoverpadPathFlags*)(p + 0x179);
    DrakorHoverpadUpdateMainPlacement* d = (DrakorHoverpadUpdateMainPlacement*)desc;
    f32 initialSpeed;

    (obj)->anim.rotX = (s16)(d->rotXByte << 8);
    ((DrakorHoverpadState*)p)->unk118 = (f32)d->unk1a;
    initialSpeed = lbl_803E6A3C;
    ((DrakorHoverpadState*)p)->speed = initialSpeed;
    f->bit20 = 0;
    f->b40 = 1;
    ((DrakorHoverpadState*)p)->unk170 = 0;
    ((DrakorHoverpadState*)p)->unk11C = initialSpeed;
    ((DrakorHoverpadState*)p)->unk120 = initialSpeed;
    ((DrakorHoverpadState*)p)->frameCounter = 0;
    switch (d->subtype)
    {
    case DRAKORHOVERPAD_SUBTYPE_TRACKING:
        g->f10 = 1;
        g->f04 = 1;
        g->f08 = 0;
        break;
    case DRAKORHOVERPAD_SUBTYPE_FREE:
        g->f10 = 0;
        g->f04 = 0;
        g->f08 = 1;
        break;
    }
    ObjGroup_AddObject((int)obj, DRAKORHOVERPAD_OBJGROUP);
    ObjGroup_AddObject((int)obj, DRAKORHOVERPAD_OBJGROUP_SECONDARY);
}

#pragma dont_inline on
int drakorhoverpad_init(GameObject* obj)
{
    u8* p = (obj)->extra;
    DrakorHoverpadFlags* f = (DrakorHoverpadFlags*)(p + 0x178);

    if (f->b40 == 0)
    {
        if (f->state > 3)
        {
            if (lbl_803E6A3C == ((DrakorHoverpadState*)p)->speed)
            {
                f->state = 0;
            }
        }
    }
    if (f->b01 != mainGetBit(1654))
    {
        f->b01 ^= 1;
        *(f32*)p = -*(f32*)p;
        if (f->state == 3)
        {
            f->state = 0;
            *(f32*)p = lbl_803E6A38;
        }
        if (f->state == 4)
        {
            f->state = 0;
            *(f32*)p = lbl_803E6A74;
        }
        if (f->b40 != 0)
        {
            if (lbl_803E6A3C == *(f32*)p)
            {
                *(f32*)p = (f->b01 != 0) ? lbl_803E6A74 : lbl_803E6A38;
            }
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_id_309);
    }
    return 0;
}
#pragma dont_inline reset

void drakorhoverpad_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible)
{
    u8* p = (obj)->extra;
    if (visible)
    {
        objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E6A48);
        ((DrakorHoverpadRenderState*)p)->frameCounter += framesThisStep;
        if (((DrakorHoverpadRenderState*)p)->frameCounter == 0 || ((DrakorHoverpadRenderState*)p)->frameCounter > 10)
        {
            ((DrakorHoverpadRenderState*)p)->frameCounter = 0;
            ((DrakorHoverpadRenderState*)p)->particleEmitAX = (obj)->anim.localPosX + (f32)(int)randomGetRange(-30, 30);
            ((DrakorHoverpadRenderState*)p)->particleEmitAY = (obj)->anim.localPosY;
            ((DrakorHoverpadRenderState*)p)->particleEmitAZ = (obj)->anim.localPosZ + (f32)(int)randomGetRange(-30, 30);
            ((DrakorHoverpadRenderState*)p)->particleEmitBX =
                (obj)->anim.localPosX + (f32)(int)randomGetRange(-120, 120);
            ((DrakorHoverpadRenderState*)p)->particleEmitBY = (obj)->anim.localPosY - lbl_803E6A88;
            ((DrakorHoverpadRenderState*)p)->particleEmitBZ =
                (obj)->anim.localPosZ + (f32)(int)randomGetRange(-120, 120);
        }
    }
}

#pragma dont_inline on
int drakorhoverpad_pickUnmaskedNextPoint(int* pad, int exclude, int maxIndex)
{
    int collected[4];
    int pt;
    int count;
    u32 bit;
    int i;

    count = 0;
    bit = 1;
    for (i = 0; i < 4; i++)
    {
        pt = pad[7 + i];
        if (pt > -1 && (*(s8*)((char*)pad + 0x1b) & bit) == 0 && pt != exclude)
        {
            collected[count++] = pt;
        }
        bit <<= 1;
    }
    if (count != 0)
    {
        if (maxIndex != -1 && maxIndex > count - 1)
        {
            maxIndex = count - 1;
        }
        if (maxIndex == -1)
        {
            maxIndex = randomGetRange(0, count - 1);
        }
        return collected[maxIndex];
    }
    return -1;
}
#pragma dont_inline reset

#pragma dont_inline on
int drakorhoverpad_pickMaskedNextPoint(int* pad, int exclude, int maxIndex)
{
    int collected[4];
    int pt;
    int count;
    u32 bit;
    int i;

    count = 0;
    bit = 1;
    for (i = 0; i < 4; i++)
    {
        pt = pad[7 + i];
        if (pt > -1 && (*(s8*)((char*)pad + 0x1b) & bit) != 0 && pt != exclude)
        {
            collected[count++] = pt;
        }
        bit <<= 1;
    }
    if (count != 0)
    {
        if (maxIndex != -1 && maxIndex > count - 1)
        {
            maxIndex = count - 1;
        }
        if (maxIndex == -1)
        {
            maxIndex = randomGetRange(0, count - 1);
        }
        return collected[maxIndex];
    }
    return -1;
}
#pragma dont_inline reset

int drakorhoverpad_update(RomCurveWalker* curve, int maxIndex)
{
    u8* p = (u8*)curve;
    u8* cur;
    int result;

    if (curve == NULL)
    {
        return 1;
    }
    cur = *(u8**)&((GameObject*)p)->anim.currentMove;
    if (cur == NULL || ((GameObject*)p)->anim.targetObj == NULL)
    {
        return 1;
    }
    *(u8**)&((GameObject*)p)->anim.activeMoveProgress = cur;
    *(u8**)&((GameObject*)p)->anim.currentMove = *(u8**)&((GameObject*)p)->anim.targetObj;
    memcpy(p + 0xa8, p + 0xb8, 16);
    memcpy(p + 0xc8, p + 0xd8, 16);
    memcpy(p + 0xe8, p + 0xf8, 16);
    if (*(int*)&((GameObject*)p)->anim.previousLocalPosX != 0)
    {
        result = drakorhoverpad_pickMaskedNextPoint(*(int**)&((GameObject*)p)->anim.currentMove, -1, maxIndex);
    }
    else
    {
        result = drakorhoverpad_pickUnmaskedNextPoint(*(int**)&((GameObject*)p)->anim.currentMove, -1, maxIndex);
    }
    if (result == -1)
    {
        goto set_null;
    }
    ((GameObject*)p)->anim.targetObj = (*gRomCurveInterface)->getById(result);
    if (((GameObject*)p)->anim.targetObj == NULL)
    {
        goto ret1;
    }
/* Each field access re-reads the node pointer out of the anim slot (the
 * original never cached it in a local); these macros keep that reload. */
#define CM_NODE  (*(DrakorCurveNode**)&((GameObject*)p)->anim.currentMove)
#define AMP_NODE (*(DrakorCurveNode**)&((GameObject*)p)->anim.activeMoveProgress)
#define TGT_NODE (*(DrakorCurveNode**)&((GameObject*)p)->anim.targetObj)
    if (*(int*)&((GameObject*)p)->anim.previousLocalPosX != 0)
    {
        *(f32*)&((GameObject*)p)->extra = CM_NODE->x;
        *(f32*)&((GameObject*)p)->animEventCallback = AMP_NODE->x;
        *(f32*)&((GameObject*)p)->pendingParentObj =
            lbl_803E6A38 *
            ((f32)(u32)CM_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(CM_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->ownerObj =
            lbl_803E6A38 *
            ((f32)(u32)AMP_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(AMP_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xd8) = CM_NODE->y;
        *(f32*)&((GameObject*)p)->unkDC = AMP_NODE->y;
        *(f32*)(p + 0xe0) =
            lbl_803E6A38 *
            ((f32)(u32)CM_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(CM_NODE->tangentPitch << 8) / gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xe4) =
            lbl_803E6A38 *
            ((f32)(u32)AMP_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(AMP_NODE->tangentPitch << 8) / gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->unkF8 = CM_NODE->z;
        ((GameObject*)p)->externalVelX = AMP_NODE->z;
        ((GameObject*)p)->externalVelY =
            lbl_803E6A38 *
            ((f32)(u32)CM_NODE->tangentMag *
             mathCosf(gDrakorHoverpadPi * (f32)(int)(CM_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
        ((GameObject*)p)->externalVelZ =
            lbl_803E6A38 *
            ((f32)(u32)AMP_NODE->tangentMag *
             mathCosf(gDrakorHoverpadPi * (f32)(int)(AMP_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
    }
    else
    {
        *(f32*)&((GameObject*)p)->extra = CM_NODE->x;
        *(f32*)&((GameObject*)p)->animEventCallback = TGT_NODE->x;
        *(f32*)&((GameObject*)p)->pendingParentObj =
            lbl_803E6A38 *
            ((f32)(u32)CM_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(CM_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->ownerObj =
            lbl_803E6A38 *
            ((f32)(u32)TGT_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(TGT_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xd8) = CM_NODE->y;
        *(f32*)&((GameObject*)p)->unkDC = TGT_NODE->y;
        *(f32*)(p + 0xe0) =
            lbl_803E6A38 *
            ((f32)(u32)CM_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(CM_NODE->tangentPitch << 8) / gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xe4) =
            lbl_803E6A38 *
            ((f32)(u32)TGT_NODE->tangentMag *
             mathSinf(gDrakorHoverpadPi * (f32)(int)(TGT_NODE->tangentPitch << 8) / gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->unkF8 = CM_NODE->z;
        ((GameObject*)p)->externalVelX = TGT_NODE->z;
        ((GameObject*)p)->externalVelY =
            lbl_803E6A38 *
            ((f32)(u32)CM_NODE->tangentMag *
             mathCosf(gDrakorHoverpadPi * (f32)(int)(CM_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
        ((GameObject*)p)->externalVelZ =
            lbl_803E6A38 *
            ((f32)(u32)TGT_NODE->tangentMag *
             mathCosf(gDrakorHoverpadPi * (f32)(int)(TGT_NODE->tangentYaw << 8) / gDrakorHoverpadAngleScale));
    }
#undef CM_NODE
#undef AMP_NODE
#undef TGT_NODE
    if (*(int*)&((GameObject*)p)->anim.previousWorldPosY != 0)
    {
        curvesSetupMoveNetworkCurve(&curve->curve);
    }
    if (*(int*)&((GameObject*)p)->anim.previousLocalPosX != 0)
    {
        Curve_AdvanceAlongPath(&curve->curve, lbl_803E6A70);
    }
    else
    {
        Curve_AdvanceAlongPath(&curve->curve, lbl_803E6A48);
    }
    return 0;
set_null:
    ((GameObject*)p)->anim.targetObj = NULL;
ret1:
    return 1;
}

#pragma opt_dead_assignments off
#pragma opt_common_subs off
#pragma fp_contract off
void drakorhoverpad_updateMain(GameObject* obj)
{
    u8* p = (obj)->extra;
    RomCurveWalker* curve;
    DrakorHoverpadUpdateMainPlacement* q = (DrakorHoverpadUpdateMainPlacement*)(obj)->anim.placementData;
    DrakorHoverpadFlags* f = (DrakorHoverpadFlags*)(p + 0x178);
    DrakorHoverpadPathFlags* g = (DrakorHoverpadPathFlags*)(p + 0x179);
    int evOut;
    f32 diff[3];
    f32 curvePos[3];
    int curveArg;
    f32 phase;
    f32 wobbleY;
    f32 limit;
    f32 absH;
    f32 absV;
    GameObject* nearest;
    s16 yawDelta;
    int c;
    int angle;
    int clamped;
    f32 spd;

    Obj_GetPlayerObject();
    if (drakorhoverpad_init(obj) != 0)
    {
        return;
    }
    if (f->bit20 == 0)
    {
        f->bit20 = mainGetBit(q->activateGameBit);
        ((DrakorHoverpadUpdateMainState*)p)->targetSpeed = lbl_803E6A3C;
        if (f->bit20 != 0)
        {
            curveArg = 0x2a;
            (*gRomCurveInterface)
                ->initCurve(&((DrakorHoverpadState*)p)->curve, (void*)obj, lbl_803E6A4C, &curveArg, -1);
            Curve_AdvanceAlongPath(&((DrakorHoverpadState*)p)->curve.curve, lbl_803E6A50);
            (obj)->anim.localPosX = ((DrakorHoverpadState*)p)->curve.posX;
            (obj)->anim.localPosY = ((DrakorHoverpadState*)p)->curve.posY;
            (obj)->anim.localPosZ = ((DrakorHoverpadState*)p)->curve.posZ;
            *(f32*)p = lbl_803E6A38;
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_308);
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_30a);
        }
        return;
    }
    curve = &((DrakorHoverpadState*)p)->curve;
    if (g->f08 != 0)
    {
        angle = (s16)getAngle(sqrtf(curve->tangentX * curve->tangentX + curve->tangentZ * curve->tangentZ),
                              curve->tangentY);
        phase = gDrakorHoverpadPi * (f32)angle / gDrakorHoverpadAngleScale;
        wobbleY = lbl_803E6A8C * mathCosf(phase);
        limit = lbl_803E6A90 * (lbl_803E6A94 * mathSinf(phase));
        if (f->b40 != 0)
        {
            absH = (*(f32*)p >= lbl_803E6A3C) ? *(f32*)p : -*(f32*)p;
            absV = (((DrakorHoverpadUpdateMainState*)p)->verticalVel >= lbl_803E6A3C)
                       ? ((DrakorHoverpadUpdateMainState*)p)->verticalVel
                       : -((DrakorHoverpadUpdateMainState*)p)->verticalVel;
            if (absV > lbl_803E6A38 + absH)
            {
                limit = limit + lbl_803E6A38;
            }
        }
        if (f->state != 0)
        {
            limit = limit + lbl_803E6A38;
        }
        ((DrakorHoverpadUpdateMainState*)p)->verticalVel = ((DrakorHoverpadUpdateMainState*)p)->targetSpeed +
                                                           (((DrakorHoverpadUpdateMainState*)p)->verticalVel + wobbleY);
        absV = ((DrakorHoverpadUpdateMainState*)p)->verticalVel;
        absH = (absV >= lbl_803E6A3C) ? absV : -absV;
        if (absH < limit)
        {
            ((DrakorHoverpadUpdateMainState*)p)->verticalVel = *(f32*)p;
        }
        else
        {
            ((DrakorHoverpadUpdateMainState*)p)->verticalVel += (absV > *(f32*)p) ? -limit : limit;
        }
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DRAKORHOVERPAD_HIT_VOLUME_SLOT, 1, 0);
    }
    else
    {
        ObjHits_DisableObject((int)obj);
        ((DrakorHoverpadUpdateMainState*)p)->verticalVel = *(f32*)p;
        lbl_803DC2F8 = lbl_803E6A38 * *(f32*)p;
    }
    if (((DrakorHoverpadUpdateMainState*)p)->verticalVel < lbl_803E6A3C)
    {
        (*gRomCurveInterface)->setClosed(&((DrakorHoverpadState*)p)->curve, 1);
    }
    else
    {
        (*gRomCurveInterface)->setClosed(&((DrakorHoverpadState*)p)->curve, 0);
    }
    ((DrakorHoverpadUpdateMainState*)p)->targetSpeed = lbl_803E6A3C;
    if (lbl_803E6A3C != ((DrakorHoverpadUpdateMainState*)p)->verticalVel)
    {
        Curve_AdvanceAlongPath(&curve->curve, ((DrakorHoverpadUpdateMainState*)p)->verticalVel);
        c = curve->reverse;
        if ((c == 0 && curve->atSegmentEnd != 0) || (c != 0 && curve->atSegmentEnd == 0))
        {
            if (drakorhoverpad_handlePathPointEvent(obj, *(u8*)((u8*)curve->nodeA0 + 0x18),
                                                    *(u8*)((u8*)curve->nodeA4 + 0x18), &evOut) != 0)
            {
                drakorhoverpad_update(curve, evOut);
            }
        }
    }
    curvePos[0] = curve->posX;
    curvePos[1] = curve->posY;
    curvePos[2] = curve->posZ;
    curvePos[1] = curvePos[1] + (lbl_803E6A48 + mathSinf(gDrakorHoverpadPi *
                                                         (f32)(int)((DrakorHoverpadUpdateMainState*)p)->anglePhase /
                                                         gDrakorHoverpadAngleScale));
    ((DrakorHoverpadUpdateMainState*)p)->anglePhase =
        (s16)(((DrakorHoverpadUpdateMainState*)p)->anglePhase + framesThisStep * 0x320);
    if (g->f10 != 0)
    {
        nearest = (GameObject*)ObjGroup_FindNearestObject(BOSSDRAKOR_OBJGROUP, (int)obj, 0);
        if (nearest != NULL)
        {
            yawDelta = Obj_GetYawDeltaToObject(obj, nearest, 0);
            if (yawDelta < -0x200)
            {
                yawDelta = -0x200;
            }
            else if (yawDelta > 0x200)
            {
                yawDelta = 0x200;
            }
            c = (s16)yawDelta;
            (obj)->anim.rotX += (s16)c;
            if ((obj)->anim.rotY != 0)
            {
                yawDelta = (obj)->anim.rotY;
                if (yawDelta < -0x100)
                {
                    yawDelta = -0x100;
                }
                else if (yawDelta > 0x100)
                {
                    yawDelta = 0x100;
                }
                (obj)->anim.rotY -= (s16)yawDelta;
            }
            (obj)->anim.rotZ = (s16)(c * lbl_803DC2FC);
        }
    }
    else
    {
        s16 yawDelta;
        phase = sqrtf(curve->tangentX * curve->tangentX + curve->tangentZ * curve->tangentZ);
        yawDelta = (s16)(getAngle(curve->tangentX, curve->tangentZ) + 0x8000) - (obj)->anim.rotX;
        (obj)->anim.rotY = (s16)getAngle(curve->tangentY, phase);
        if (yawDelta < -0x800)
        {
            clamped = -0x800;
        }
        else if (yawDelta > 0x800)
        {
            clamped = 0x800;
        }
        else
        {
            clamped = yawDelta;
        }
        c = (s16)clamped;
        (obj)->anim.rotZ = (s16)((((DrakorHoverpadUpdateMainState*)p)->verticalVel < lbl_803E6A3C) ? c : -c);
        (obj)->anim.rotX += (s16)((c < -0x100) ? -0x100 : (c > 0x100) ? 0x100 : c);
        c = (obj)->anim.rotY;
        if (c < -0x64)
        {
            c = -0x64;
        }
        else if (c > 0x64)
        {
            c = 0x64;
        }
        (obj)->anim.rotY = c;
    }
    PSVECSubtract(curvePos, &(obj)->anim.localPosX, diff);
    /* snapshot the shared steer speed before building the call args (the
     * through-pointer read keeps the load at this statement) */
    spd = *(f32*)&lbl_803DC2F8;
    Obj_SteerVelocityTowardVector(obj, (Vec3f*)&obj->anim.velocityX, (Vec3f*)diff, spd, spd / lbl_803E6A98,
                                  lbl_803E6A9C);
    PSVECAdd(&(obj)->anim.localPosX, &(obj)->anim.velocityX, &(obj)->anim.localPosX);
}
#pragma fp_contract reset
#pragma opt_common_subs reset
#pragma opt_dead_assignments reset

int drakorhoverpad_setScale(GameObject* obj);
int drakorhoverpad_render2(GameObject* obj);
void drakorhoverpad_func12(int obj, f32* outFloat, int* outFlag);
void drakorhoverpad_modelMtxFn(GameObject* obj, f32* ox, f32* oy, f32* oz);
f32 drakorhoverpad_func13(int obj, f32* out);
void drakorhoverpad_free(int obj);
void drakorhoverpad_func17(GameObject* obj, int sel, int* out);
void drakorhoverpad_func0F(int obj, f32* ox, f32* oy, f32* oz);
void drakorhoverpad_renderGroundMarker(GameObject* obj, f32 scale);

ObjectDescriptor24 gDrakorHoverPadObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)drakorhoverpad_initialise,
    (ObjectDescriptorCallback)drakorhoverpad_release,
    0,
    (ObjectDescriptorCallback)drakorhoverpad_initMain,
    (ObjectDescriptorCallback)drakorhoverpad_updateMain,
    (ObjectDescriptorCallback)drakorhoverpad_hitDetect,
    (ObjectDescriptorCallback)drakorhoverpad_render,
    (ObjectDescriptorCallback)drakorhoverpad_free,
    (ObjectDescriptorCallback)drakorhoverpad_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)drakorhoverpad_getExtraSize,
    (ObjectDescriptorCallback)drakorhoverpad_setScale,
    (ObjectDescriptorCallback)drakorhoverpad_func0B,
    (ObjectDescriptorCallback)drakorhoverpad_modelMtxFn,
    (ObjectDescriptorCallback)drakorhoverpad_render2,
    (ObjectDescriptorCallback)drakorhoverpad_func0E,
    (ObjectDescriptorCallback)drakorhoverpad_func0F,
    (ObjectDescriptorCallback)drakorhoverpad_func10,
    (ObjectDescriptorCallback)drakorhoverpad_func11,
    (ObjectDescriptorCallback)drakorhoverpad_func12,
    (ObjectDescriptorCallback)drakorhoverpad_func13,
    (ObjectDescriptorCallback)drakorhoverpad_func14,
    (ObjectDescriptorCallback)drakorhoverpad_func15,
    (ObjectDescriptorCallback)drakorhoverpad_renderGroundMarker,
    (ObjectDescriptorCallback)drakorhoverpad_func17,
};

int drakorhoverpad_handlePathPointEvent(GameObject* obj, u8 eventCode, u8 subCode, void* out)
{
    u8* p = (obj)->extra;
    DrakorHoverpadFlags* f = (DrakorHoverpadFlags*)(p + 0x178);
    DrakorHoverpadPathFlags* g = (DrakorHoverpadPathFlags*)(p + 0x179);
    int player;
    f32 shakeMag;
    f32 absP;
    f32 cur;

    player = (int)Obj_GetPlayerObject();
    *(int*)out = -1;
    switch (eventCode)
    {
    case 1:
        player = (int)Obj_GetPlayerObject();
        ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel =
            lbl_803E6A78 * -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
        *(f32*)p = lbl_803E6A3C;
        if (((GameObject*)player)->anim.parent == (void*)obj)
        {
            Camera_EnableViewYOffset();
            if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
            {
                shakeMag = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            else
            {
                shakeMag = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            CameraShake_SetAllMagnitudes(shakeMag);
        }
        break;
    case 3:
        if (f->b40 != 0)
        {
            break;
        }
        if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel <= lbl_803E6A3C)
        {
            break;
        }
        if (f->bit80 != 0)
        {
            break;
        }
        player = (int)Obj_GetPlayerObject();
        ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel =
            lbl_803E6A78 * -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
        *(f32*)p = lbl_803E6A3C;
        if (((GameObject*)player)->anim.parent == (void*)obj)
        {
            Camera_EnableViewYOffset();
            if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
            {
                shakeMag = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            else
            {
                shakeMag = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            CameraShake_SetAllMagnitudes(shakeMag);
        }
        return 1;
    case 4:
        if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel <= lbl_803E6A3C)
        {
            break;
        }
        if (f->b40 != 0)
        {
            mainSetBits(0x660, 1);
        }
        else if (mainGetBit(0x661) == 0)
        {
            mainSetBits(0x788, 1);
            f->state = 1;
            *(f32*)p = lbl_803E6A3C;
        }
        else
        {
            ((DrakorHoverpadHandlePathPointEventState*)p)->targetSpeed +=
                (*(f32*)p < lbl_803E6A3C) ? lbl_803E6A74 : lbl_803E6A38;
        }
        break;
    case 9:
        if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
        {
            break;
        }
        if (mainGetBit(0x661) == 0)
        {
            f->state = 1;
            *(f32*)p = lbl_803E6A3C;
        }
        else
        {
            ((DrakorHoverpadHandlePathPointEventState*)p)->targetSpeed +=
                (*(f32*)p < lbl_803E6A3C) ? lbl_803E6A74 : lbl_803E6A38;
        }
        break;
    case 5:
        if (f->b40 != 0)
        {
            break;
        }
        f->state = 2;
        break;
    case 6:
        if (f->b40 != 0)
        {
            break;
        }
        ((DrakorHoverpadHandlePathPointEventState*)p)->targetSpeed +=
            (*(f32*)p < lbl_803E6A3C) ? lbl_803E6A7C : lbl_803E6A80;
        break;
    case 7:
        if (*(f32*)p <= lbl_803E6A3C)
        {
            f->state = 3;
            *(f32*)p = lbl_803E6A3C;
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_30b);
        }
        break;
    case 17:
        if (*(f32*)p >= lbl_803E6A3C)
        {
            f->state = 4;
            *(f32*)p = lbl_803E6A3C;
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_30b);
        }
        break;
    case 10:
        if (g->p1 == 0)
        {
            break;
        }
        if (mainGetBit(0x689) != 0)
        {
            break;
        }
        mainSetBits(0x689, 1);
        break;
    case 11:
        if (g->p1 == 0)
        {
            break;
        }
        if (((GameObject*)player)->anim.parent != (void*)obj)
        {
            break;
        }
        mainSetBits(0x68a, 1);
        break;
    case 12:
        if (g->p1 == 0)
        {
            break;
        }
        if (((GameObject*)player)->anim.parent != (void*)obj)
        {
            break;
        }
        mainSetBits(0x68b, 1);
        break;
    case 13:
        if (mainGetBit(0x68a) == 0)
        {
            break;
        }
        if (*(f32*)p >= lbl_803E6A3C)
        {
            player = (int)Obj_GetPlayerObject();
            ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel =
                lbl_803E6A78 * -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            *(f32*)p = lbl_803E6A3C;
            if (((GameObject*)player)->anim.parent == (void*)obj)
            {
                Camera_EnableViewYOffset();
                if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
                {
                    shakeMag = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                else
                {
                    shakeMag = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                CameraShake_SetAllMagnitudes(shakeMag);
            }
        }
        break;
    case 14:
        if (g->p1 == 0)
        {
            break;
        }
        if (*(f32*)p <= lbl_803E6A3C)
        {
            player = (int)Obj_GetPlayerObject();
            ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel =
                lbl_803E6A78 * -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            *(f32*)p = lbl_803E6A3C;
            if (((GameObject*)player)->anim.parent == (void*)obj)
            {
                Camera_EnableViewYOffset();
                if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
                {
                    shakeMag = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                else
                {
                    shakeMag = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                CameraShake_SetAllMagnitudes(shakeMag);
            }
        }
        break;
    case 15:
        if (f->b40 != 0)
        {
            break;
        }
        mainSetBits(0x788, 1);
        break;
    case 16:
        cur = *(f32*)p;
        if (cur >= lbl_803E6A3C)
        {
            absP = cur;
        }
        else
        {
            absP = -cur;
        }
        if (lbl_803E6A38 == absP)
        {
            *(f32*)p = cur * lbl_803E6A84;
        }
        else
        {
            *(f32*)p = lbl_803E6A38 * cur;
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_id_309);
        break;
    case 20:
        g->f10 = !g->f10;
        break;
    case 21:
        g->p6 = 1;
        *(f32*)p = lbl_803E6A3C;
        break;
    }
    switch (subCode)
    {
    case 8:
        if (mainGetBit(0x67f) != 0)
        {
            *(int*)out = 1;
        }
        else
        {
            *(int*)out = 0;
        }
        break;
    case 2:
        mainSetBits(0x7ba, 1);
        break;
    case 18:
        *(int*)out = 0;
        break;
    case 19:
        *(int*)out = 1;
        break;
    }
    return 1;
}

int drakorhoverpad_setScale(GameObject* obj)
{
    u8* p = obj->extra;
    return (p[0x179] >> 2) & 1;
}

int drakorhoverpad_render2(GameObject* obj)
{
    u8* p = obj->extra;
    return ((p[0x179] >> 2) & 1) == 0;
}

void drakorhoverpad_func12(int obj, f32* outFloat, int* outFlag)
{
    *outFloat = lbl_803E6A3C;
    *outFlag = 0;
}

void drakorhoverpad_modelMtxFn(GameObject* obj, f32* ox, f32* oy, f32* oz)
{
    *ox = obj->anim.localPosX;
    *oy = lbl_803E6A40 + obj->anim.localPosY;
    *oz = obj->anim.localPosZ;
}

f32 drakorhoverpad_func13(int obj, f32* out)
{
    *out = lbl_803E6A44;
    return lbl_803E6A3C;
}

void drakorhoverpad_free(int obj)
{
    ObjGroup_RemoveObject(obj, DRAKORHOVERPAD_OBJGROUP);
    ObjGroup_RemoveObject(obj, DRAKORHOVERPAD_OBJGROUP_SECONDARY);
}

void drakorhoverpad_func17(GameObject* obj, int sel, int* out)
{
    switch (sel)
    {
    case 2:
        *out = obj->anim.rotX;
        break;
    case 3:
        *out = 0x1000;
        break;
    case 4:
        *out = 1;
        break;
    }
}

void drakorhoverpad_func0F(int obj, f32* ox, f32* oy, f32* oz)
{
    MatrixTransform pos;
    f32 mtx[16];
    GameObject* src = Obj_GetPlayerObject();
    if (src == NULL)
    {
        src = (GameObject*)obj;
    }
    pos.x = src->anim.localPosX;
    pos.y = src->anim.localPosY;
    pos.z = src->anim.localPosZ;
    pos.rotX = src->anim.rotX;
    pos.rotY = src->anim.rotY;
    pos.rotZ = src->anim.rotZ;
    pos.scale = lbl_803E6A48;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6A3C, lbl_803DC300, lbl_803DC304, ox, oy, oz);
}

void drakorhoverpad_resetPendingMotion(GameObject* obj)
{
    u8* p = obj->extra;
    DrakorHoverpadPathFlags* g = (DrakorHoverpadPathFlags*)(p + 0x179);
    if (g->p6 != 0)
    {
        g->p6 = 0;
        *(f32*)p = lbl_803E6A38;
    }
}

void drakorhoverpad_renderGroundMarker(GameObject* obj, f32 scale)
{
    f32* mtx;
    MatrixTransform pos;
    mtx = (f32*)ObjPath_GetPointModelMtx(obj, 0);
    pos.x = lbl_803E6A3C;
    pos.y = lbl_803E6A40;
    pos.z = lbl_803E6A3C;
    pos.rotX = 0;
    pos.rotY = 0;
    pos.rotZ = 0;
    pos.scale = scale / (obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(gDrakorHoverpadMtx, &pos);
    mtx44_mult(gDrakorHoverpadMtx, mtx, gDrakorHoverpadMtx);
    fn_8003B950(gDrakorHoverpadMtx);
}

u8 lbl_8032AAB0[0x80] = {
    0x04, 0x30, 0x0B, 0x00, 0x03, 0x00, 0x04, 0x31, 0x05, 0x00, 0x02, 0x00, 0x04, 0x32, 0x0B, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05,
};
