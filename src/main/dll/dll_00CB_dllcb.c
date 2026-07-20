/*
 * DLL 0x00CB - a ground-baddie object (object type id 0x14b, extra size
 * 0x410). Its AI runs through gBaddieControlInterface and gPlayerInterface:
 * dll_CB_init sets up the control state and registers dll_CB_seqFn as the
 * anim-event callback; dll_CB_update advances movement and, while the
 * sub-state's flags400 bit 8 is set, walks a ROM curve path
 * (gRomCurveInterface / Curve_AdvanceAlongPath) copying the curve's
 * position/orientation onto the object. dll_CB_seqFn drives an objseq
 * sub-state machine (subMode 0/1/2) handling player tracking, route paths
 * (routeNav/routeState) and game-bit gating (gameBitC / DllCBPlacement.gameBitId yield).
 * dll_CB_initialise installs the two callback tables gDllCBMoveHandlers /
 * gDllCBStateHandlers used by the player-interface update.
 *
 * This TU also defines the co-located ChukChuk (gChukChukObjDescriptor) and
 * IceBall (gIceBallObjDescriptor) object descriptors, whose bodies live in
 * their own DLL TUs.
 */
#include "main/dll/chukchukstate_struct.h"
#include "main/dll/baddie_control_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/objprint_character_api.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/curve_walker.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00CB_dllcb.h"
#include "main/dll/dll_00CD_iceball.h"
#include "main/voxmaps.h"
#include "main/curve.h"
#include "string.h"

typedef struct DllCBPlacement
{
    u8 pad0[0x4 - 0x0];
    s8 unk4;
    s8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x24 - 0x14];
    s16 trackYieldId;
    u8 pad26[0x2C - 0x26];
    s16 gameBitId;
    s8 trackYieldEnable;
    u8 pad2F[0x30 - 0x2F];
} DllCBPlacement;

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (ChukChuk_getExtraSize == 0x18).
 */

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

/* object group this object belongs to */
#define DLLCB_OBJGROUP 3

extern void* gDllCBMoveHandlers[];
void* gDllCBStateHandlers[6];
int dll_CB_stateHandler5(GameObject* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub;
    RouteNav* routePath;
    f32 zero;

    sub = obj->extra;
    if (*(void**)&state->baddie.targetObj != NULL)
    {
        (*gPlayerInterface)->setState((void*)obj, state, 1);
        routePath = &sub->routeNav;
        zero = 0.0f;
        state->baddie.moveInputX = zero;
        state->baddie.moveInputZ = zero;
        memcpy(routePath, &obj->anim.localPosX, 12);
        memcpy((void*)sub->routeNav.curPos, (void*)&((GameObject*)state->baddie.targetObj)->anim.localPosX, 12);
        voxmaps_updateRoutePath(&sub->routeNav, &sub->routeState);
        if (state->baddie.targetDistance < 5e+01f && sub->subMode == 2)
        {
            return 5;
        }
        if (routePath->flag25 == 0)
        {
            (*gPlayerInterface)
                ->moveTowardPoint((void*)obj, state, routePath->tgtPos[0], routePath->tgtPos[2], 0.0f,
                                  0.0f, 6e+01f);
        }
        else
        {
            (*gPlayerInterface)
                ->moveTowardPoint((void*)obj, state, routePath->tgtPos[0], routePath->tgtPos[2], 15.0f,
                                  3e+01f, 6e+01f);
        }
    }
    else
    {
        (*gPlayerInterface)->setState((void*)obj, state, 0);
        state->baddie.moveDone = 0;
    }
    return 0;
}

int dll_CB_stateHandler4(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        (*gPlayerInterface)->setState(obj, state, 0);
        fz = 5.0f;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
    }
    if (((GameObject*)obj)->anim.velocityY < 0.25)
    {
        f32 fz = 0.0f;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
        return 6;
    }
    {
        f32 d = 1.1f;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY / d;
        state->baddie.animSpeedA = state->baddie.animSpeedA / d;
        state->baddie.animSpeedC = state->baddie.animSpeedC / d;
    }
    return 0;
}

int dll_CB_stateHandler3(int* obj, u8* obj2)
{
    GroundBaddieState* x = ((GameObject*)obj)->extra;
    if ((s8)obj2[0x27b] != 0)
    {
        (*gBaddieControlInterface)->spawnChild((GameObject*)obj, x->triggerId, -1, 0);
    }
    return 0;
}

int dll_CB_stateHandler2(GameObject* obj, GroundBaddieState* state)
{
    ObjHitsPriorityState* hitState;

    if (*(char*)&state->baddie.moveJustStartedB != '\0')
    {
        (*gPlayerInterface)->setState((void*)obj, state, 3);
        *(int*)&state->baddie.targetObj = 0;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        hitState->flags &= ~1;
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xe0000, obj, 0);
        if ((obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int dll_CB_stateHandler1(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1)
        return 3;
    return 6;
}

int dll_CB_stateHandler0(void)
{
    return 0x6;
}

int dll_CB_moveHandler3(int* obj)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    u8 step;
    if (((GameObject*)obj)->anim.alpha >= (step = framesThisStep))
    {
        ((GameObject*)obj)->anim.alpha -= step;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        mainSetBits(sub->gameBitB, 0);
        mainSetBits(sub->gameBitA, 1);
    }
    return 0;
}

int dll_CB_moveHandler2(short* out, u8* obj)
{
    f32 f = 0.0f;
    ((BaddieState*)obj)->animSpeedA = f;
    ((BaddieState*)obj)->animSpeedB = f;
    ((BaddieState*)obj)->physicsActive = 1;
    out[2] = ((BaddieState*)obj)->spawnRotZ;
    out[1] = ((BaddieState*)obj)->spawnRotY;
    return 0;
}

int dll_CB_moveHandler1(int* obj, GroundBaddieState* def)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    if ((s8)def->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
        def->baddie.moveDone = 0;
    }
    def->baddie.physicsActive = 1;
    ((GameObject*)obj)->anim.rotZ = def->baddie.spawnRotZ;
    ((GameObject*)obj)->anim.rotY = def->baddie.spawnRotY;
    (*gBaddieControlInterface)
        ->updateMovementBlend((GameObject*)obj, def, state, 1.0f, 12.0f);
    def->baddie.moveSpeed = 0.075f * def->baddie.animSpeedA;
    return 0;
}

int dll_CB_moveHandler0(short* out, u8* obj)
{
    f32 f = 0.0f;
    ((BaddieState*)obj)->animSpeedA = f;
    ((BaddieState*)obj)->animSpeedB = f;
    ((BaddieState*)obj)->moveSpeed = f;
    ((BaddieState*)obj)->physicsActive = 1;
    out[2] = ((BaddieState*)obj)->spawnRotZ;
    out[1] = ((BaddieState*)obj)->spawnRotY;
    (*gPlayerInterface)->rotateTowardTarget(out, obj, f, 5);
    return 0;
}

void dll_CB_seekAndUpdate(int obj, void* seq, int sub, GroundBaddieState* state);

void dll_CB_advanceAI(int* obj, GroundBaddieState* sub, GroundBaddieState* state);

void dll_CB_seekAndUpdate(int obj, void* seq, int sub, GroundBaddieState* state)
{
    int setup;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    state->baddie.moveDone = 1;
    if ((*gBaddieControlInterface)
            ->shouldDropTarget((GameObject*)obj, state, (f32)(u32)((GroundBaddieState*)sub)->aggroRange, 1) != 0)
    {
        *(int*)&state->baddie.targetObj = ((GroundBaddieState*)sub)->savedObjC0;
        state->baddie.hasTarget = 0;
        if (((DllCBPlacement*)setup)->trackYieldEnable != -1)
        {
            if (seq != NULL)
            {
                (*gObjectTriggerInterface)->yield((ObjSeqState*)seq, ((DllCBPlacement*)setup)->trackYieldId);
            }
            ((GroundBaddieState*)sub)->subMode = 1;
        }
        else
        {
            *(int*)&state->baddie.targetObj = 0;
        }
    }
    (*gBaddieControlInterface)->updateGravity((GameObject*)obj, state, 0.17f, 1);
    ((GroundBaddieState*)sub)->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;
    (*gPlayerInterface)->update((void*)obj, state, timeDelta, timeDelta, gDllCBMoveHandlers, gDllCBStateHandlers);
    *(int*)&((GameObject*)obj)->pendingParentObj = ((GroundBaddieState*)sub)->savedObjC0;
}

void dll_CB_advanceAI(int* obj, GroundBaddieState* sub, GroundBaddieState* state)
{
    char* targetObj;
    int stateResult;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        ((GameObject*)((GameObject*)obj)->childObjs[0])->anim.parent = ((GameObject*)obj)->anim.parent;
    }
    targetObj = *(char**)&state->baddie.targetObj;
    if (targetObj != NULL)
    {
        d.x = ((GameObject*)targetObj)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = ((GameObject*)targetObj)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = ((GameObject*)targetObj)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        state->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    characterDoEyeAnims((GameObject*)obj, sub->eyeAnimState);
    if ((sub->configFlags & 1) == 0)
    {
        (*gBaddieControlInterface)
            ->pollCameraTarget((GameObject*)obj, state, &sub->flags400, 2, 3, sub->soundIdB, sub->soundIdA);
    }
    (*gBaddieControlInterface)
        ->processMessages((GameObject*)obj, state, &sub->routeNav, sub->gameBitB, &sub->subMode, 0, 0, 0);
    stateResult = (*gBaddieControlInterface)
                      ->updateHitReaction((GameObject*)obj, state, &sub->routeNav, sub->gameBitB,
                                          lbl_80320008, lbl_80320080, 1, NULL);
    if (stateResult >= 4)
    {
        sub->subMode = 2;
        *(int*)&state->baddie.targetObj = (int)Obj_GetPlayerObject();
    }
}

int dll_CB_seqFn(short* obj, int p2, u8* e)
{
    int setup;
    RomCurveWalker* path;
    int sub;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->userData1 != 0)
    {
        return 0;
    }
    if (((GameObject*)obj)->seqIndex != -1)
    {
        if ((*gBaddieControlInterface)
                ->isObjectValid((GameObject*)obj, (void*)sub, 1) == 0)
        {
            return 1;
        }
        dll_CB_advanceAI((int*)obj, (GroundBaddieState*)sub, (GroundBaddieState*)sub);
        if (((GroundBaddieState*)sub)->gameBitC != -1 && mainGetBit(((GroundBaddieState*)sub)->gameBitC) != 0)
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)e, ((DllCBPlacement*)setup)->gameBitId);
            ((GroundBaddieState*)sub)->gameBitC = -1;
        }
        switch (((GroundBaddieState*)sub)->subMode)
        {
        case 2:
            ((ObjSeqState*)e)->flags = 0;
            dll_CB_seekAndUpdate((int)obj, e, sub, (GroundBaddieState*)sub);
            if (((GroundBaddieState*)sub)->subMode == 1)
            {
                ((GroundBaddieState*)sub)->baddie.substate = 5;
                (*gPlayerInterface)
                    ->update(obj, (void*)sub, 1.0f, 1.0f, gDllCBMoveHandlers,
                             gDllCBStateHandlers);
                ((ObjSeqState*)e)->movementState = 0;
            }
            break;
        case 1:
            if ((*gBaddieControlInterface)
                    ->updateSequenceMovement((GameObject*)obj, (ObjSeqState*)e, (char*)sub, gDllCBMoveHandlers,
                                             gDllCBStateHandlers, 0) != 0)
            {
                (*gBaddieControlInterface)
                    ->updateGravity((GameObject*)obj, (void*)sub, 0.17f, 1);
            }
            break;
        case 0:
        default:
            ((ObjSeqState*)e)->flags = -1;
            ((ObjSeqState*)e)->flags &= ~0x40;
            path = (RomCurveWalker*)((GroundBaddieState*)sub)->path;
            if ((((GroundBaddieState*)sub)->flags400 & BADDIE_FLAG400_PATH_ACTIVE) != 0)
            {
                if ((Curve_AdvanceAlongPath((Curve*)path, ((GroundBaddieState*)sub)->baddie.animSpeedA) != 0 ||
                     path->atSegmentEnd != 0) &&
                    (*gRomCurveInterface)->goNextPoint(path) != 0)
                {
                    ((GroundBaddieState*)sub)->flags400 &= ~BADDIE_FLAG400_PATH_ACTIVE;
                }
                ((GroundBaddieState*)sub)->baddie.animSpeedA = 0.1f;
                ((GameObject*)obj)->anim.rotX = getAngle(path->tangentX, path->tangentZ) + 0x8000;
                ((GameObject*)obj)->anim.rotY = getAngle(path->tangentZ, path->tangentY) + 0x4000;
                ((GameObject*)obj)->anim.rotZ = getAngle(path->tangentY, path->tangentX) + 0x4000;
                ((GameObject*)obj)->anim.localPosX = path->posX;
                ((GameObject*)obj)->anim.localPosY = path->posY;
                ((GameObject*)obj)->anim.localPosZ = path->posZ;
            }
            break;
        }
    }
    if (((GameObject*)obj)->seqIndex == -1)
    {
        ((GroundBaddieState*)sub)->flags400 |= 2;
        return 0;
    }
    return ((GroundBaddieState*)sub)->subMode != 0;
}

void dll_CB_func0B_nop(void)
{
}

s16 dll_CB_setScale(int* obj)
{
    return ((BaddieState*)((GameObject*)obj)->extra)->controlMode;
}

int dll_CB_getExtraSize_ret_1040(void)
{
    return 0x410;
}

int dll_CB_getObjectTypeId(void)
{
    return 0x14b;
}

void dll_CB_free(int* obj)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject((int)obj, DLLCB_OBJGROUP);
    {
        int* sub = ((GameObject*)obj)->childObjs[0];
        if (sub != NULL)
        {
            Obj_FreeObject((GameObject*)sub);
            ((GameObject*)obj)->childObjs[0] = NULL;
        }
    }
    (*gBaddieControlInterface)->releaseState((GameObject*)obj, state, 1);
}

void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->userData1)
        {
        case 0:
            objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
            break;
        }
    }
}

void dll_CB_hitDetect(int* obj)
{
    void* a = ((GameObject*)obj)->extra;
    (*gPlayerInterface)->updateVelocityState(obj, a, gDllCBMoveHandlers);
}

void dll_CB_update(int* obj)
{
    RomCurveWalker* path;
    GroundBaddieState* sub;
    u8* def;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->userData1 != 0)
        return;
    if (((GameObject*)obj)->userData2 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((DllCBPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((DllCBPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((DllCBPlacement*)def)->posZ;
        ((GameObject*)obj)->userData2 = 1;
        return;
    }
    if ((sub->flags400 & 2) != 0)
    {
        (*gBaddieControlInterface)
            ->startHitReaction((GameObject*)obj, sub, &sub->routeNav, sub->gameBitB, &sub->subMode, 0, 0, 0, 1);
        sub->flags400 = (u16)(sub->flags400 & ~2);
    }
    if ((*gBaddieControlInterface)->isObjectValid((GameObject*)obj, sub, 1) == 0)
        return;
    dll_CB_advanceAI(obj, sub, sub);
    path = (RomCurveWalker*)sub->path;
    if ((sub->flags400 & BADDIE_FLAG400_PATH_ACTIVE) == 0)
        return;
    if (Curve_AdvanceAlongPath((Curve*)path, sub->baddie.animSpeedA) != 0 || path->atSegmentEnd != 0)
    {
        if ((*gRomCurveInterface)->goNextPoint(path) != 0)
        {
            sub->flags400 = (u16)(sub->flags400 & ~BADDIE_FLAG400_PATH_ACTIVE);
        }
    }
    sub->baddie.animSpeedA = 0.1f;
    ((GameObject*)obj)->anim.rotX = (s16)(getAngle(path->tangentX, path->tangentZ) + 0x8000);
    ((GameObject*)obj)->anim.rotY = (s16)(getAngle(path->tangentZ, path->tangentY) + 0x4000);
    ((GameObject*)obj)->anim.rotZ = (s16)(getAngle(path->tangentY, path->tangentX) + 0x4000);
    ((GameObject*)obj)->anim.localPosX = path->posX;
    ((GameObject*)obj)->anim.localPosY = path->posY;
    ((GameObject*)obj)->anim.localPosZ = path->posZ;
}

void dll_CB_init(int* obj, u8* params, int extra)
{
    GroundBaddieState* sub;
    u8 flags;

    sub = ((GameObject*)obj)->extra;
    flags = 0x16;
    if (extra != 0)
        flags |= 1;
    if ((params[0x2b] & 1) == 0)
        flags |= 8;
    ((GameObject*)obj)->anim.rotY = (s16)((s8)params[0x28] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s8)params[0x27] << 8);
    (*gBaddieControlInterface)
        ->initGroundBaddie((GameObject*)obj, params, (u8*)sub, 4, 6, 0x82, flags, 2e+01f);
    ((GameObject*)obj)->animEventCallback = dll_CB_seqFn;
    (*gPlayerInterface)->setState(obj, sub, 0);
    sub->baddie.substate = 0;
    if (sub->aggroRange < 0x32)
    {
        sub->aggroRange = 0x32;
    }
}

void dll_CB_release_nop(void)
{
}

void dll_CB_initialise(void)
{
    ((void**)gDllCBMoveHandlers)[0] = dll_CB_moveHandler0;
    ((void**)gDllCBMoveHandlers)[1] = dll_CB_moveHandler1;
    ((void**)gDllCBMoveHandlers)[2] = dll_CB_moveHandler2;
    ((void**)gDllCBMoveHandlers)[3] = dll_CB_moveHandler3;
    gDllCBStateHandlers[0] = dll_CB_stateHandler0;
    gDllCBStateHandlers[1] = dll_CB_stateHandler1;
    gDllCBStateHandlers[2] = dll_CB_stateHandler2;
    gDllCBStateHandlers[3] = dll_CB_stateHandler3;
    gDllCBStateHandlers[4] = dll_CB_stateHandler4;
    gDllCBStateHandlers[5] = dll_CB_stateHandler5;
}
