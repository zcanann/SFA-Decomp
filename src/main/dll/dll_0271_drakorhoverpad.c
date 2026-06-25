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
 * are HoverpadFlags / Flags377.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

/* placement subtype id (desc[0]) selecting the pad behaviour mode */
#define DRAKORHOVERPAD_SUBTYPE_TRACKING 1812 /* tracks/yaws toward a nearby object */
#define DRAKORHOVERPAD_SUBTYPE_FREE 1048     /* free curve-follow, no tracking */

int drakorhoverpad_func0B(void) { return 0x1; }

int drakorhoverpad_func0E(void) { return 0x1; }

int drakorhoverpad_func10(void) { return 0x0; }

void drakorhoverpad_func11(void)
{
}

int drakorhoverpad_func14(void) { return 0x0; }

void drakorhoverpad_func15(void)
{
}

typedef struct DrakorHoverpadUpdateMainPlacement
{
    u8 pad0[0x20 - 0x0];
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
    f32 unk114;
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
    f32 unk114;
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
    f32 unk114;
    u8 pad118[0x154 - 0x118];
    f32 particleEmitAX; /* 0x154 */
    f32 particleEmitAY; /* 0x158 */
    f32 particleEmitAZ; /* 0x15c */
    f32 particleEmitBX; /* 0x160 */
    f32 particleEmitBY; /* 0x164 */
    f32 particleEmitBZ; /* 0x168 */
    u8 pad16C[0x174 - 0x16C];
    s16 anglePhase;  /* 0x174 */
    s16 frameCounter; /* 0x176 */
} DrakorHoverpadHandlePathPointEventState;

typedef struct DrakorHoverpadState
{
    f32 unk00;
    RomCurveWalker curve; /* 0x004 */
    u8 pad10C[4];
    f32 speed; /* 0x110 */
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

int drakorhoverpad_getExtraSize(void) { return 0x17c; }

int drakorhoverpad_getObjectTypeId(void) { return 0x0; }

void drakorhoverpad_hitDetect(void)
{
}

void drakorhoverpad_initialise(void)
{
}

void drakorhoverpad_release(void)
{
}

void drakorhoverpad_initMain(int obj, void* desc)
{
    u8* p = ((GameObject*)obj)->extra;
    HoverpadFlags* f = (HoverpadFlags*)(p + 0x178);
    Flags377* g = (Flags377*)(p + 0x179);
    f32 v;

    ((GameObject*)obj)->anim.rotX = (s16)(*(s8*)((char*)desc + 0x18) << 8);
    ((DrakorHoverpadState*)p)->unk118 = (f32) * (s16*)((char*)desc + 0x1a);
    v = lbl_803E6A3C;
    ((DrakorHoverpadState*)p)->speed = v;
    f->bit20 = 0;
    f->b40 = 1;
    ((DrakorHoverpadState*)p)->unk170 = 0;
    ((DrakorHoverpadState*)p)->unk11C = v;
    ((DrakorHoverpadState*)p)->unk120 = v;
    ((DrakorHoverpadState*)p)->frameCounter = 0;
    switch (*(s16*)desc)
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
    ObjGroup_AddObject(obj, 70);
    ObjGroup_AddObject(obj, 10);
}

#pragma dont_inline on
int drakorhoverpad_init(int obj)
{
    u8* p = ((GameObject*)obj)->extra;
    HoverpadFlags* f = (HoverpadFlags*)(p + 0x178);

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
    if (f->b01 != GameBit_Get(1654))
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
        Sfx_PlayFromObject(obj, SFXfend_fox_keytap3);
    }
    return 0;
}
#pragma dont_inline reset

void drakorhoverpad_render(void* obj, int p2, int p3, int p4, int p5, char visible)
{
    u8* p = ((GameObject*)obj)->extra;
    if (visible)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6A48);
        ((DrakorHoverpadRenderState*)p)->frameCounter += framesThisStep;
        if (((DrakorHoverpadRenderState*)p)->frameCounter == 0 || ((DrakorHoverpadRenderState*)p)->frameCounter > 10)
        {
            ((DrakorHoverpadRenderState*)p)->frameCounter = 0;
            ((DrakorHoverpadRenderState*)p)->particleEmitAX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
            randomGetRange(-30, 30);
            ((DrakorHoverpadRenderState*)p)->particleEmitAY = ((GameObject*)obj)->anim.localPosY;
            ((DrakorHoverpadRenderState*)p)->particleEmitAZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
            randomGetRange(-30, 30);
            ((DrakorHoverpadRenderState*)p)->particleEmitBX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
            randomGetRange(-120, 120);
            ((DrakorHoverpadRenderState*)p)->particleEmitBY = ((GameObject*)obj)->anim.localPosY - lbl_803E6A88;
            ((DrakorHoverpadRenderState*)p)->particleEmitBZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
            randomGetRange(-120, 120);
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

#pragma peephole off
int drakorhoverpad_update(RomCurveWalker* curve, int arg)
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
        result = drakorhoverpad_pickMaskedNextPoint(*(int**)&((GameObject*)p)->anim.currentMove, -1, arg);
    }
    else
    {
        result = drakorhoverpad_pickUnmaskedNextPoint(*(int**)&((GameObject*)p)->anim.currentMove, -1, arg);
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
    if (*(int*)&((GameObject*)p)->anim.previousLocalPosX != 0)
    {
        *(f32*)&((GameObject*)p)->extra = *(f32*)(*(u8**)&((GameObject*)p)->anim.currentMove + 8);
        *(f32*)&((GameObject*)p)->animEventCallback = *(f32*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 8);
        *(f32*)&((GameObject*)p)->pendingParentObj = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.
            currentMove + 0x2e) * mathSinf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2c) << 8) / gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->ownerObj = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.
            activeMoveProgress + 0x2e) * mathSinf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 0x2c) << 8) /
            gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xd8) = *(f32*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0xc);
        *(f32*)&((GameObject*)p)->unkDC = *(f32*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 0xc);
        *(f32*)(p + 0xe0) = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2e) *
            mathSinf(
                gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2d) << 8) /
                gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xe4) = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 0x2e)
            * mathSinf(
                gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 0x2d) << 8) /
                gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->unkF8 = *(f32*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x10);
        ((GameObject*)p)->externalVelX = *(f32*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 0x10);
        ((GameObject*)p)->externalVelY = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.currentMove +
            0x2e) * mathCosf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2c) << 8) / gDrakorHoverpadAngleScale));
        ((GameObject*)p)->externalVelZ = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.
            activeMoveProgress + 0x2e) * mathCosf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.activeMoveProgress + 0x2c) << 8) /
            gDrakorHoverpadAngleScale));
    }
    else
    {
        *(f32*)&((GameObject*)p)->extra = *(f32*)(*(u8**)&((GameObject*)p)->anim.currentMove + 8);
        *(f32*)&((GameObject*)p)->animEventCallback = *(f32*)(*(u8**)&((GameObject*)p)->anim.targetObj + 8);
        *(f32*)&((GameObject*)p)->pendingParentObj = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.
            currentMove + 0x2e) * mathSinf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2c) << 8) / gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->ownerObj = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.
            targetObj + 0x2e) * mathSinf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.targetObj + 0x2c) << 8) / gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xd8) = *(f32*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0xc);
        *(f32*)&((GameObject*)p)->unkDC = *(f32*)(*(u8**)&((GameObject*)p)->anim.targetObj + 0xc);
        *(f32*)(p + 0xe0) = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2e) *
            mathSinf(
                gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2d) << 8) /
                gDrakorHoverpadAngleScale));
        *(f32*)(p + 0xe4) = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.targetObj + 0x2e) *
            mathSinf(
                gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.targetObj + 0x2d) << 8) /
                gDrakorHoverpadAngleScale));
        *(f32*)&((GameObject*)p)->unkF8 = *(f32*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x10);
        ((GameObject*)p)->externalVelX = *(f32*)(*(u8**)&((GameObject*)p)->anim.targetObj + 0x10);
        ((GameObject*)p)->externalVelY = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.currentMove +
            0x2e) * mathCosf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.currentMove + 0x2c) << 8) / gDrakorHoverpadAngleScale));
        ((GameObject*)p)->externalVelZ = lbl_803E6A38 * ((f32)(u32) * (u8*)(*(u8**)&((GameObject*)p)->anim.targetObj +
            0x2e) * mathCosf(
            gDrakorHoverpadPi * (f32)(int)(*(s8*)(*(u8**)&((GameObject*)p)->anim.targetObj + 0x2c) << 8) / gDrakorHoverpadAngleScale));
    }
    if (*(int*)&((GameObject*)p)->anim.previousWorldPosY != 0)
    {
        curvesSetupMoveNetworkCurve(curve);
    }
    if (*(int*)&((GameObject*)p)->anim.previousLocalPosX != 0)
    {
        Curve_AdvanceAlongPath(curve, lbl_803E6A70);
    }
    else
    {
        Curve_AdvanceAlongPath(curve, lbl_803E6A48);
    }
    return 0;
set_null:
    ((GameObject*)p)->anim.targetObj = NULL;
ret1:
    return 1;
}

#pragma opt_common_subs off
#pragma fp_contract off
void drakorhoverpad_updateMain(int obj)
{
    u8* p = ((GameObject*)obj)->extra;
    RomCurveWalker* curve;
    int q = *(int*)&((GameObject*)obj)->anim.placementData;
    HoverpadFlags* f = (HoverpadFlags*)(p + 0x178);
    Flags377* g = (Flags377*)(p + 0x179);
    int evOut;
    f32 diff[3];
    f32 curvePos[3];
    int curveArg;
    f32 phase;
    f32 wobbleY;
    f32 limit;
    f32 absH;
    f32 absV;
    int nearest;
    int yawDelta;
    int c;
    int angle;

    Obj_GetPlayerObject();
    if (drakorhoverpad_init(obj) != 0)
    {
        return;
    }
    if (f->bit20 == 0)
    {
        f->bit20 = GameBit_Get(((DrakorHoverpadUpdateMainPlacement*)q)->activateGameBit);
        ((DrakorHoverpadUpdateMainState*)p)->unk114 = lbl_803E6A3C;
        if (f->bit20 != 0)
        {
            curveArg = 0x2a;
            (*gRomCurveInterface)->initCurve(&((DrakorHoverpadState*)p)->curve, (void*)obj, lbl_803E6A4C, &curveArg, -1);
            Curve_AdvanceAlongPath(&((DrakorHoverpadState*)p)->curve, lbl_803E6A50);
            ((GameObject*)obj)->anim.localPosX = ((DrakorHoverpadState*)p)->curve.posX;
            ((GameObject*)obj)->anim.localPosY = ((DrakorHoverpadState*)p)->curve.posY;
            ((GameObject*)obj)->anim.localPosZ = ((DrakorHoverpadState*)p)->curve.posZ;
            *(f32*)p = lbl_803E6A38;
            Sfx_PlayFromObject(obj, SFXfend_fox_keytap2);
            Sfx_PlayFromObject(obj, SFXfend_pep_wakeup);
        }
        return;
    }
    curve = &((DrakorHoverpadState*)p)->curve;
    if (g->f08 != 0)
    {
        angle = getAngle(sqrtf(curve->tangentX * curve->tangentX +
                               curve->tangentZ * curve->tangentZ),
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
        ((DrakorHoverpadUpdateMainState*)p)->verticalVel = ((DrakorHoverpadUpdateMainState*)p)->unk114 + (((
            DrakorHoverpadUpdateMainState*)p)->verticalVel + wobbleY);
        absV = ((DrakorHoverpadUpdateMainState*)p)->verticalVel;
        absV = (absV >= lbl_803E6A3C) ? absV : -absV;
        if (absV < limit)
        {
            ((DrakorHoverpadUpdateMainState*)p)->verticalVel = *(f32*)p;
        }
        else
        {
            ((DrakorHoverpadUpdateMainState*)p)->verticalVel = ((DrakorHoverpadUpdateMainState*)p)->verticalVel +
                ((((DrakorHoverpadUpdateMainState*)p)->verticalVel > *(f32*)p) ? -limit : limit);
        }
        ObjHits_SetHitVolumeSlot(obj, 8, 1, 0);
    }
    else
    {
        ObjHits_DisableObject(obj);
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
    ((DrakorHoverpadUpdateMainState*)p)->unk114 = lbl_803E6A3C;
    if (lbl_803E6A3C != ((DrakorHoverpadUpdateMainState*)p)->verticalVel)
    {
        Curve_AdvanceAlongPath(curve, ((DrakorHoverpadUpdateMainState*)p)->verticalVel);
        c = curve->reverse;
        if ((c == 0 && curve->atSegmentEnd != 0) ||
            (c != 0 && curve->atSegmentEnd == 0))
        {
            if (drakorhoverpad_handlePathPointEvent(obj, *(u8*)((u8*)curve->nodeA0 + 0x18),
                                                    *(u8*)((u8*)curve->nodeA4 + 0x18),
                                                    &evOut) != 0)
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
    ((DrakorHoverpadUpdateMainState*)p)->anglePhase = (s16)(
        ((DrakorHoverpadUpdateMainState*)p)->anglePhase + framesThisStep * 0x320);
    if (g->f10 != 0)
    {
        nearest = ObjGroup_FindNearestObject(0x45, obj, 0);
        if ((u32)nearest != 0)
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
            ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + c);
            if (((GameObject*)obj)->anim.rotY != 0)
            {
                yawDelta = ((GameObject*)obj)->anim.rotY;
                if (yawDelta < -0x100)
                {
                    yawDelta = -0x100;
                }
                else if (yawDelta > 0x100)
                {
                    yawDelta = 0x100;
                }
                ((GameObject*)obj)->anim.rotY = (s16)(((GameObject*)obj)->anim.rotY - yawDelta);
            }
            ((GameObject*)obj)->anim.rotZ = (s16)(c * lbl_803DC2FC);
        }
    }
    else
    {
        phase = sqrtf(curve->tangentX * curve->tangentX +
            curve->tangentZ * curve->tangentZ);
        yawDelta = (s16)((s16)(getAngle(curve->tangentX, curve->tangentZ) + 0x8000) -
            ((GameObject*)obj)->anim.rotX);
        ((GameObject*)obj)->anim.rotY = getAngle(curve->tangentY, phase);
        if (yawDelta < -0x800)
        {
            yawDelta = -0x800;
        }
        else if (yawDelta > 0x800)
        {
            yawDelta = 0x800;
        }
        c = (s16)yawDelta;
        ((GameObject*)obj)->anim.rotZ = (s16)((((DrakorHoverpadUpdateMainState*)p)->verticalVel <
            lbl_803E6A3C) ? c : -c);
        if (c < -0x100)
        {
            c = -0x100;
        }
        else if (c > 0x100)
        {
            c = 0x100;
        }
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + c);
        c = ((GameObject*)obj)->anim.rotY;
        if (c < -0x64)
        {
            c = -0x64;
        }
        else if (c > 0x64)
        {
            c = 0x64;
        }
        ((GameObject*)obj)->anim.rotY = c;
    }
    PSVECSubtract(curvePos, &((GameObject*)obj)->anim.localPosX, diff);
    Obj_SteerVelocityTowardVector(obj, &((GameObject*)obj)->anim.velocityX, diff, lbl_803DC2F8,
                                  lbl_803DC2F8 / lbl_803E6A98, lbl_803E6A9C);
    PSVECAdd(&((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.velocityX,
             &((GameObject*)obj)->anim.localPosX);
}
#pragma fp_contract reset
#pragma opt_common_subs reset

int drakorhoverpad_handlePathPointEvent(int obj, u8 a, u8 b, void* out)
{
    u8* p = ((GameObject*)obj)->extra;
    HoverpadFlags* f = (HoverpadFlags*)(p + 0x178);
    Flags377* g = (Flags377*)(p + 0x179);
    int player;
    f32 m;
    f32 absP;
    f32 cur;

    player = (int)Obj_GetPlayerObject();
    *(int*)out = -1;
    switch (a)
    {
    case 1:
        player = (int)Obj_GetPlayerObject();
        ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel = lbl_803E6A78 * -((
            DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
        *(f32*)p = lbl_803E6A3C;
        if (((GameObject*)player)->anim.parent == (void*)obj)
        {
            Camera_EnableViewYOffset();
            if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
            {
                m = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            else
            {
                m = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            CameraShake_SetAllMagnitudes(m);
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
        ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel = lbl_803E6A78 * -((
            DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
        *(f32*)p = lbl_803E6A3C;
        if (((GameObject*)player)->anim.parent == (void*)obj)
        {
            Camera_EnableViewYOffset();
            if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
            {
                m = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            else
            {
                m = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            }
            CameraShake_SetAllMagnitudes(m);
        }
        return 1;
    case 4:
        if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel <= lbl_803E6A3C)
        {
            break;
        }
        if (f->b40 != 0)
        {
            GameBit_Set(0x660, 1);
        }
        else if (GameBit_Get(0x661) == 0)
        {
            GameBit_Set(0x788, 1);
            f->state = 1;
            *(f32*)p = lbl_803E6A3C;
        }
        else
        {
            ((DrakorHoverpadHandlePathPointEventState*)p)->unk114 +=
                (*(f32*)p < lbl_803E6A3C) ? lbl_803E6A74 : lbl_803E6A38;
        }
        break;
    case 9:
        if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
        {
            break;
        }
        if (GameBit_Get(0x661) == 0)
        {
            f->state = 1;
            *(f32*)p = lbl_803E6A3C;
        }
        else
        {
            ((DrakorHoverpadHandlePathPointEventState*)p)->unk114 +=
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
        ((DrakorHoverpadHandlePathPointEventState*)p)->unk114 +=
            (*(f32*)p < lbl_803E6A3C) ? lbl_803E6A7C : lbl_803E6A80;
        break;
    case 7:
        if (*(f32*)p <= lbl_803E6A3C)
        {
            f->state = 3;
            *(f32*)p = lbl_803E6A3C;
            Sfx_PlayFromObject(obj, SFXfend_rob_servo1);
        }
        break;
    case 17:
        if (*(f32*)p >= lbl_803E6A3C)
        {
            f->state = 4;
            *(f32*)p = lbl_803E6A3C;
            Sfx_PlayFromObject(obj, SFXfend_rob_servo1);
        }
        break;
    case 10:
        if (g->p1 == 0)
        {
            break;
        }
        if (GameBit_Get(0x689) != 0)
        {
            break;
        }
        GameBit_Set(0x689, 1);
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
        GameBit_Set(0x68a, 1);
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
        GameBit_Set(0x68b, 1);
        break;
    case 13:
        if (GameBit_Get(0x68a) == 0)
        {
            break;
        }
        if (*(f32*)p >= lbl_803E6A3C)
        {
            player = (int)Obj_GetPlayerObject();
            ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel = lbl_803E6A78 * -((
                DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            *(f32*)p = lbl_803E6A3C;
            if (((GameObject*)player)->anim.parent == (void*)obj)
            {
                Camera_EnableViewYOffset();
                if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
                {
                    m = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                else
                {
                    m = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                CameraShake_SetAllMagnitudes(m);
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
            ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel = lbl_803E6A78 * -((
                DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
            *(f32*)p = lbl_803E6A3C;
            if (((GameObject*)player)->anim.parent == (void*)obj)
            {
                Camera_EnableViewYOffset();
                if (((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel >= lbl_803E6A3C)
                {
                    m = ((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                else
                {
                    m = -((DrakorHoverpadHandlePathPointEventState*)p)->verticalVel;
                }
                CameraShake_SetAllMagnitudes(m);
            }
        }
        break;
    case 15:
        if (f->b40 != 0)
        {
            break;
        }
        GameBit_Set(0x788, 1);
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
        Sfx_PlayFromObject(obj, SFXfend_fox_keytap3);
        break;
    case 20:
        g->f10 = !g->f10;
        break;
    case 21:
        g->p6 = 1;
        *(f32*)p = lbl_803E6A3C;
        break;
    }
    switch (b)
    {
    case 8:
        if (GameBit_Get(0x67f) != 0)
        {
            *(int*)out = 1;
        }
        else
        {
            *(int*)out = 0;
        }
        break;
    case 2:
        GameBit_Set(0x7ba, 1);
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

int drakorhoverpad_setScale(int obj)
{
    u8* p = ((GameObject*)obj)->extra;
    return (p[0x179] >> 2) & 1;
}

int drakorhoverpad_render2(int obj)
{
    u8* p = ((GameObject*)obj)->extra;
    return ((p[0x179] >> 2) & 1) == 0;
}

void drakorhoverpad_func12(int obj, f32* a, int* b)
{
    *a = lbl_803E6A3C;
    *b = 0;
}

void drakorhoverpad_modelMtxFn(int obj, f32* a, f32* b, f32* c)
{
    *a = ((GameObject*)obj)->anim.localPosX;
    *b = lbl_803E6A40 + ((GameObject*)obj)->anim.localPosY;
    *c = ((GameObject*)obj)->anim.localPosZ;
}

f32 drakorhoverpad_func13(int obj, f32* out)
{
    *out = lbl_803E6A44;
    return lbl_803E6A3C;
}

void drakorhoverpad_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x46);
    ObjGroup_RemoveObject(obj, 0xa);
}

void drakorhoverpad_func17(int obj, int sel, int* out)
{
    switch (sel)
    {
    case 2:
        *out = ((GameObject*)obj)->anim.rotX;
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
    ObjPosParams pos;
    f32 mtx[16];
    int* src = Obj_GetPlayerObject();
    if (src == NULL)
    {
        src = (int*)obj;
    }
    pos.x = ((GameObject*)src)->anim.localPosX;
    pos.y = ((GameObject*)src)->anim.localPosY;
    pos.z = ((GameObject*)src)->anim.localPosZ;
    pos.rx = *(s16*)src;
    pos.ry = ((GameObject*)src)->anim.rotY;
    pos.rz = ((GameObject*)src)->anim.rotZ;
    pos.scale = lbl_803E6A48;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6A3C, lbl_803DC300, lbl_803DC304, ox, oy, oz);
}

void drakorhoverpad_resetPendingMotion(int obj)
{
    u8* p = ((GameObject*)obj)->extra;
    Flags377* g = (Flags377*)(p + 0x179);
    if (g->p6 != 0)
    {
        g->p6 = 0;
        *(f32*)p = lbl_803E6A38;
    }
}

void drakorhoverpad_func16(int obj, f32 scale)
{
    f32* mtx;
    ObjPosParams pos;
    mtx = ObjPath_GetPointModelMtx(obj, 0);
    pos.x = lbl_803E6A3C;
    pos.y = lbl_803E6A40;
    pos.z = lbl_803E6A3C;
    pos.rx = 0;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = scale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(gDrakorHoverpadMtx, &pos);
    mtx44_mult(gDrakorHoverpadMtx, mtx, gDrakorHoverpadMtx);
    fn_8003B950(gDrakorHoverpadMtx);
}
