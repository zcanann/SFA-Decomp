#include "main/camera_interface.h"
#include "string.h"
#include "sys/objects.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/objprint_api.h"
#include "dlls/object_descriptor.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/FRONT/POST.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_list.h"
#include "main/objtype.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "track/intersect_api.h"
#include "main/curve.h"
#include "main/objlib_api.h"
#include "main/objseq.h"
#include "main/track_dolphin_api.h"
#define MOVELIB_TARGET_OBJGROUP 8

#define MOVELIB_CURVE_WALK_DONE 0x10

extern u8 gMoveLibDefaultMoveData[];

typedef struct ProjNearSearch
{
    f32 range;
    f32 dx;
    f32 dy;
    f32 dz;
} ProjNearSearch;

int dll_2E_func0F_ret_0(void)
{
    return 0x0;
}

void dll_2E_setLookAtMaxDistance(MoveLibState* state, f32 value)
{
    state->lookAtMaxDistance = value;
}

void dll_2E_setMoveTables(MoveLibState* s, const void* src1, const void* src2, int count)
{
    (void)count;
    if (src1 == NULL)
        src1 = gMoveLibDefaultMoveData;
    if (src2 == NULL)
        src2 = gMoveLibDefaultMoveData;
    memcpy(s->turnTable, src1, (u32)s->pointCount * 2);
    memcpy(s->eventTable, src2, (u32)s->pointCount * 2);
}

f32 dll_2E_getDistanceToCurveAction(GameObject* obj, int arg)
{
    int r = (*gRomCurveInterface)->findByAction(arg);
    if (r > -1)
    {
        return (*gRomCurveInterface)->distanceToObject(obj, r);
    }
    return -1.0f;
}

int dll_2E_getCurveActionTargetAimed(int idx, MoveLibTarget* out)
{
    f32 range;
    int curveId;

    range = 1000.0f;
    curveId = (*gRomCurveInterface)->findByAction(idx);
    if (curveId > -1)
    {
        RomCurveDef* p = (RomCurveDef*)(*gRomCurveInterface)->getById(curveId);
        GameObject* q;
        out->x = p->x;
        out->y = p->y;
        out->z = p->z;
        q = (GameObject*)objGetNearestType(MOVELIB_TARGET_OBJGROUP, &out->x, &range);
        if (q != NULL)
        {
            out->angle = (s16)atan2i((int)(q->anim.localPosX - out->x), (int)(q->anim.localPosZ - out->z));
        }
        else
        {
            out->angle = (s16)(p->yaw << 8);
        }
        return 1;
    }
    return 0;
}

int dll_2E_getCurveActionTarget(int idx, MoveLibTarget* out)
{
    int curveId;

    if (idx >= 0x1c)
    {
        return 0;
    }
    curveId = (*gRomCurveInterface)->findByAction(idx);
    if (curveId > -1)
    {
        RomCurveDef* p = (RomCurveDef*)(*gRomCurveInterface)->getById(curveId);
        out->x = p->x;
        out->y = p->y;
        out->z = p->z;
        out->angle = (s16)(p->yaw << 8);
        return 1;
    }
    return 0;
}

f32 moveLibHermiteArcLength(const Vec* start, const Vec* end, const Vec* startTangent, const Vec* endTangent, int steps)
{
    f32 prev_x, prev_y, prev_z;
    f32 total;
    f32 t;
    f32 cur_x, cur_y, cur_z;
    f32 dx, dy, dz;
    f32 buf[4];
    int i;

    prev_x = start->x;
    prev_y = start->y;
    prev_z = start->z;
    total = 0.0f;

    for (i = 1; i < steps + 1; i++)
    {
        t = (f32)i / steps;

        buf[0] = start->x;
        buf[1] = startTangent->x;
        buf[2] = end->x;
        buf[3] = endTangent->x;
        cur_x = Curve_EvalHermite(buf, t, 0);
        dx = cur_x - prev_x;

        buf[0] = start->y;
        buf[1] = startTangent->y;
        buf[2] = end->y;
        buf[3] = endTangent->y;
        cur_y = Curve_EvalHermite(buf, t, 0);
        dy = cur_y - prev_y;

        buf[0] = start->z;
        buf[1] = startTangent->z;
        buf[2] = end->z;
        buf[3] = endTangent->z;
        cur_z = Curve_EvalHermite(buf, t, 0);
        dz = cur_z - prev_z;

        total += sqrtf(dx * dx + dy * dy + dz * dz);
        prev_x = cur_x;
        prev_y = cur_y;
        prev_z = cur_z;
    }

    return total;
}

int moveLibAdvanceHermite(GameObject* obj, const MoveLibWaypointDef* def, MoveLibHermiteState* state, f32* phaseOut, f32 speed)
{
    int ret = 0;

    if (def != NULL)
    {
        s16 angles[3];
        f32 va;
        f32 vb;
        va = -150.0f;
        state->end.x = va;
        vb = 0.0f;
        state->end.y = vb;
        state->end.z = vb;
        state->endTangent.x = va;
        state->endTangent.y = vb;
        state->endTangent.z = vb;
        vecRotateYXZ((s16*)obj, &state->end.x);
        angles[2] = 0;
        angles[1] = (s16)def->angleY;
        angles[0] = (s16)def->angleX;
        vecRotateYXZ(angles, &state->endTangent.x);
        *phaseOut = 0.0f;
        state->length = moveLibHermiteArcLength(&state->start, &state->end, &state->startTangent, &state->endTangent, 10);
    }
    else
    {
        *phaseOut = *phaseOut + speed * (f32)(u32)framesThisStep / state->length;
        if (*phaseOut >= 1.0f)
        {
            ret = 1;
            *phaseOut = 1.0f;
        }
    }

    {
        f32 buf[4];
        buf[0] = state->start.x;
        buf[1] = state->startTangent.x;
        buf[2] = state->end.x;
        buf[3] = state->endTangent.x;
        (obj)->anim.localPosX = Curve_EvalHermite(buf, *phaseOut, 0);
        buf[0] = state->start.y;
        buf[1] = state->startTangent.y;
        buf[2] = state->end.y;
        buf[3] = state->endTangent.y;
        (obj)->anim.localPosY = Curve_EvalHermite(buf, *phaseOut, 0);
        buf[0] = state->start.z;
        buf[1] = state->startTangent.z;
        buf[2] = state->end.z;
        buf[3] = state->endTangent.z;
        (obj)->anim.localPosZ = Curve_EvalHermite(buf, *phaseOut, 0);
    }
    return ret;
}

int dll_2E_advanceAlongRoute(GameObject* obj, RomCurveWalker* route, f32 phase, MoveLibHermiteState* state, int curveVariant,
                  f32* rootOut, int* flags)
{
    int moved;
    int hit;
    f32 ground;
    int fl;
    int args[2];

    moved = 1;
    hit = 0;
    ground = 0.0f;
    fl = *flags;
    if (fl & MOVELIB_CURVE_WALK_DONE)
    {
        return 1;
    }
    if (fl & 0x4)
    {
        if (moveLibAdvanceHermite(obj, NULL, state, &state->phase, phase) != 0)
        {
            args[0] = 0x19;
            args[1] = 0x15;
            (*gRomCurveInterface)->initCurve(route, (void*)obj, 200.0f, args, (u8)curveVariant);
            *flags |= 8;
            moved = 1;
        }
    }
    else
    {
        hit = 0;
        if (Curve_AdvanceAlongPath(&route->curve, phase) != 0 || route->atSegmentEnd != 0)
        {
            hit = (*gRomCurveInterface)->goNextPoint(route);
        }
        (obj)->anim.localPosX = route->posX;
        (obj)->anim.localPosY = route->posY;
        (obj)->anim.localPosZ = route->posZ;
        if (hit != 0)
        {
            *flags |= MOVELIB_CURVE_WALK_DONE;
        }
    }
    ObjAnim_SampleRootCurvePhase(&obj->anim, phase, rootOut);
    if (*flags & 1)
    {
        if (trackGetNearestGroundOffset(obj, (obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, &ground,
                                 0) == 0)
        {
            (obj)->anim.localPosY -= ground;
        }
    }
    if (moved != 0 && (*flags & 0x2) != 0)
    {
        int targetAngle = (s16)(getAngle((obj)->anim.localPosX - (obj)->anim.previousLocalPosX,
                                         (obj)->anim.localPosZ - (obj)->anim.previousLocalPosZ) +
                                0x8000);
        (obj)->anim.rotX = (s16)((obj)->anim.rotX + ((targetAngle - (obj)->anim.rotX) >> 3));
    }
    return hit;
}

int dll_2E_moveToTarget(GameObject* obj, const MoveLibTarget* target, f32 speed, int move, f32* out, u8* flags)
{
    f32 dz;
    f32 dy;
    f32 dx;
    f32 ground;
    f32 dist;
    s16 delta;

    if (target == NULL)
    {
        return 0;
    }
    dx = target->x - obj->anim.localPosX;
    dy = target->y - obj->anim.localPosY;
    dz = target->z - obj->anim.localPosZ;
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < 5.0f * speed)
    {
        obj->anim.localPosX = target->x;
        obj->anim.localPosY = target->y;
        obj->anim.localPosZ = target->z;
        if (*flags & 1)
        {
            if (trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &ground, 0) ==
                0)
            {
                obj->anim.localPosY -= ground;
            }
        }
        return 1;
    }
    normalize(&dx, &dy, &dz);
    obj->anim.velocityX = dx * (speed * timeDelta);
    obj->anim.velocityY = dy * (speed * timeDelta);
    obj->anim.velocityZ = dz * (speed * timeDelta);
    if (*flags & 1)
    {
        if (trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &ground, 0) == 0)
        {
            obj->anim.localPosY -= ground;
        }
    }
    if (*flags & 2)
    {
        delta = target->angle - (u16)obj->anim.rotX;
        if (delta > 0x8000)
        {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xffff;
        }
        obj->anim.rotX = (f32) * (s16*)obj + (0.5f + delta) * (speed * timeDelta) / dist;
    }
    objMove(obj, obj->anim.velocityX, obj->anim.velocityY, obj->anim.velocityZ);
    if (move != -1)
    {
        if (obj->anim.currentMove != move)
        {
            ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
        }
        delta = obj->anim.rotX - (u16)(s16)getAngle(dx, dz);
        if (delta > 0x8000)
        {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xffff;
        }
        speed = speed * -mathCosf(3.1415927f * delta / 32768.0f);
        ObjAnim_SampleRootCurvePhase(&obj->anim, speed, out);
    }
    return 0;
}

void moveLibSeqFreeCallback(GameObject* obj)
{
    MoveLibState* state;
    int* types;

    types = objGetLookAtJointKeys();
    state = obj->extra;

    (*gCameraInterface)->setTarget(0);

    state->phase = MOVELIB_PHASE_IDLE;
    objJointTracksCaptureCurrentAngles(obj, types, state->pointCount, state->animChannels);
    state->setupFlag = 0x50;
    objJointTracksSetAngles(state->animChannels, state->pointCount, 0, 0);
}

int dll_2E_updateSequenceTurn(GameObject* obj, ObjSeqState* seq, MoveLibState* s, s16 a, s16 b)
{
    s16 pair[2];
    int mode;
    GameObject* player;

    player = Obj_GetPlayerObject();
    pair[0] = a;
    pair[1] = b;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
    mode = (s8)seq->movementState;
    if (mode == 4)
    {
        s->setupFlag = 0x50;
        seq->flags = seq->flags & ~8;
        seq->flags = seq->flags & ~2;
        s->phase = MOVELIB_PHASE_SETUP;
        seq->movementState = 5;
        if ((s->modeBits & 2) == 0)
        {
            seq->flags = seq->flags & ~4;
        }
        seq->freeCallback = (ObjAnimSequenceFreeCallback)moveLibSeqFreeCallback;
        return 0;
    }
    else if (mode == 5)
    {
        if (s->phase >= MOVELIB_PHASE_RUN && s->phase <= MOVELIB_PHASE_FINISH)
        {
            void* types = objGetLookAtJointKeys();
            switch (s->phase)
            {
            case MOVELIB_PHASE_SETUP:
                objJointTracksCaptureCurrentAngles(obj, types, s->pointCount, s->animChannels);
                s->setupFlag = 0;
                s->phase = MOVELIB_PHASE_RUN;
            case MOVELIB_PHASE_RUN:
                if (moveLibTurnToFaceTarget(obj, player, &s->turnState, (PostControl*)s,
                                       (float*)s, pair, &s->targetX) == 0)
                {
                    s->phase = MOVELIB_PHASE_DONE;
                }
                break;
            case MOVELIB_PHASE_DONE:
                s->phase = MOVELIB_PHASE_FINISH;
            case MOVELIB_PHASE_FINISH:
                s->animPhase = 0.005f;
                break;
            }
            s->lastTarget = player;
            ObjAnim_AdvanceCurrentMove(obj, s->animPhase, framesThisStep, NULL);
            if (s->phase == MOVELIB_PHASE_FINISH)
            {
                s16* v;
                seq->flags = seq->flags | 8;
                v = objFindJointPoseVector(obj, 0);
                if (v != NULL)
                {
                    seq->baseRotY = v[1];
                    seq->baseRotX = v[0];
                }
                s->phase = MOVELIB_PHASE_IDLE;
                seq->movementState = 0;
                seq->flags = seq->flags | 4;
                return 0;
            }
            return 0;
        }
    }
    return 0;
}

void dll_2E_setTargetFromPathPoint(GameObject* obj, MoveLibState* s, int point)
{
    struct
    {
        s16 ang[3];
        f32 x0, y0, z0, x1, y1, z1;
    } v;

    if (s->needsReinit != 0)
    {
        f32 cA;
        f32 cB;
        f32 cC;
        characterDecayJointVecs(obj, objGetLookAtJointKeys(), s->pointCount);
        ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
        ObjPath_GetPointWorldPosition(obj, point + 1, &v.x1, &v.y1, &v.z1, 0);
        cA = 3.0f;
        cB = cA * v.x0 + v.x1;
        cC = 0.25f;
        s->startOffsetX = cB * cC;
        s->startOffsetY = v.y0;
        cB = cA * v.z0 + v.z1;
        s->startOffsetZ = cB * cC;
        s->startOffsetX -= (obj)->anim.localPosX;
        s->startOffsetY -= (obj)->anim.localPosY;
        s->startOffsetZ -= (obj)->anim.localPosZ;
        v.ang[0] = (s16) - (obj)->anim.rotZ;
        v.ang[1] = (s16) - (obj)->anim.rotY;
        v.ang[2] = (s16) - (obj)->anim.rotX;
        vecRotateZXY(v.ang, &s->startOffsetX);
        s->needsReinit = 0;
    }
    ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
    s->targetX = v.x0;
    s->targetY = v.y0;
    s->targetZ = v.z0;
}

void dll_2E_initState(GameObject* obj, MoveLibState* s, s16 a, s16 b, int count)
{
    f32 zero;

    s->yawLimitA = a;
    s->yawLimitB = b;
    s->pointCount = count;
    s->turnState = 0;
    zero = 0.0f;
    s->animPhase = zero;
    s->setupFlag = 0;
    s->lastTarget = NULL;
    s->lockTarget = NULL;
    s->lookAtMaxDistance = 1000.0f;
    s->phase = MOVELIB_PHASE_IDLE;
    s->needsReinit = 1;
    s->startOffsetX = zero;
    s->startOffsetY = zero;
    s->startOffsetZ = zero;
    s->reattackDelayBase = -1;
    characterDecayJointVecs(obj, objGetLookAtJointKeys(), count);
    objJointTracksCaptureCurrentAngles(obj, objGetLookAtJointKeys(), count, s->animChannels);
    objJointTracksSetAngles(s->animChannels, s->pointCount, 0, 0);
    dll_2E_setMoveTables(s, gMoveLibDefaultMoveData, gMoveLibDefaultMoveData, s->pointCount);
}

void dll_2E_setReattackDelay(MoveLibState* state, int reattackDelayBase, int reattackDelayMin)
{
    state->reattackDelayBase = reattackDelayBase;
    state->reattackDelayMin = reattackDelayMin;
    state->reattackTimer = reattackDelayBase;
}

void dll_2E_setLockTarget(MoveLibState* state, GameObject* target)
{
    state->lockTarget = target;
}

void dll_2E_updateLookAt(GameObject* obj, MoveLibState* s)
{
    register int yawDelta;
    register int seqHandle;
    register u32 target;
    GameObject* targetObj;
    int bit1;
    int ival;
    float dist;
    float blendA;
    float blendB;
    float targetYaw;
    ProjNearSearch sv;

    sv.range = 1000.0f;
    targetYaw = 30.0f;
    yawDelta = 0;
    seqHandle = (int)objGetLookAtJointKeys();
    (void)Obj_GetPlayerObject();
    if (s->needsReinit == 0)
    {
        bit1 = s->modeBits & 1;
        if (bit1 != 0 && s->phase != MOVELIB_PHASE_HELD)
        {
            s->phase = MOVELIB_PHASE_HELD;
            if ((s->modeBits & 8) == 0)
            {
                objJointTracksCaptureCurrentAngles(obj, (int*)seqHandle, (u32)s->pointCount, s->animChannels);
                s->setupFlag = 0x50;
                objJointTracksSetAngles(s->animChannels, (u32)s->pointCount, 0, 0);
            }
            else
            {
                characterDecayJointVecs(obj, objGetLookAtJointKeys(), (u32)s->pointCount);
            }
        }
        else if (bit1 == 0 && s->phase == MOVELIB_PHASE_HELD)
        {
            s->phase = MOVELIB_PHASE_IDLE;
            if ((s->modeBits & 8) == 0)
            {
                objJointTracksCaptureCurrentAngles(obj, (int*)seqHandle, (u32)s->pointCount, s->animChannels);
                s->setupFlag = 0x50;
            }
        }
        if (s->phase > MOVELIB_PHASE_TURN)
        {
            if (s->setupFlag != 0 && (s->modeBits & 8) == 0)
            {
                s->setupFlag = !characterTrackJointList(obj, (int*)seqHandle, s->pointCount, s->animChannels);
            }
            else
            {
                characterDecayJointVecs(obj, objGetLookAtJointKeys(), (u32)s->pointCount);
            }
        }
        else
        {
            targetObj = s->lockTarget;
            target = (u32)(targetObj != NULL ? targetObj
                                             : (targetObj = objGetNearestTypeTo(MOVELIB_TARGET_OBJGROUP,
                                                                                              obj, (f32*)&sv)));
            if (targetObj != NULL)
            {
                if ((s->modeBits & 0x20) != 0)
                {
                    sv.dx = s->targetX - targetObj->anim.localPosX;
                    sv.dy = s->targetY - targetObj->anim.localPosY;
                    sv.dz = s->targetZ - targetObj->anim.localPosZ;
                    blendA = sv.dx * sv.dx;
                    blendB = sv.dz * sv.dz;
                    dist = sqrtf(blendA + blendB);
                    if (dist <= 40.0f)
                    {
                        blendA = (dist - 10.0f) / 30.0f;
                        blendB = (blendA < 0.0f) ? 0.0f : ((blendA > 1.0f) ? 1.0f : blendA);
                        blendB = 1.0f - blendB;
                        s->targetX = s->targetX * (blendA = 1.0f - blendB) +
                                     obj->anim.localPosX * blendB;
                        s->targetZ = s->targetZ * blendA + obj->anim.localPosZ * blendB;
                    }
                }
                if ((s->reattackDelayBase != -1) && (target == (u32)s->lastTarget))
                {
                    ival = -framesThisStep + s->reattackTimer;
                    s->reattackTimer = ival;
                    if ((ival <= 0) && ((int)(s->reattackTimer + framesThisStep) > 0))
                    {
                        objJointTracksCaptureCurrentAngles(obj, (int*)seqHandle, (u32)s->pointCount, s->animChannels);
                        s->setupFlag = 0x50;
                        objJointTracksSetAngles(s->animChannels, (u32)s->pointCount, 0, 0);
                        s->phase = MOVELIB_PHASE_IDLE;
                        return;
                    }
                    if (s->setupFlag != 0)
                    {
                        s->setupFlag = !characterTrackJointList(obj, (int*)seqHandle, s->pointCount, s->animChannels);
                    }
                    if (s->reattackTimer < -s->reattackDelayMin)
                    {
                        s->reattackTimer = randomGetRange(s->reattackDelayMin, s->reattackDelayBase);
                    }
                    if (s->reattackTimer < 0)
                        return;
                }
                else
                {
                    s->reattackTimer = s->reattackDelayBase;
                }
                if ((target != (u32)s->lastTarget) && (target != 0))
                {
                    if (((GameObject*)target)->anim.hitReactState != NULL)
                    {
                        ObjHitsPriorityState* hitShape =
                            (ObjHitsPriorityState*)((GameObject*)target)->anim.hitReactState;
                        if ((hitShape->shapeFlags & 2) != 0)
                        {
                            targetYaw = 4.0f * (float)(int)hitShape->primaryCapsuleOffsetB;
                        }
                        else if ((hitShape->shapeFlags & 1) != 0)
                        {
                            targetYaw = (float)(int)hitShape->primaryRadius;
                        }
                        else
                        {
                            targetYaw = 30.0f;
                        }
                    }
                    else
                    {
                        targetYaw = 30.0f;
                    }
                }
                if (target != 0)
                {
                    yawDelta = Obj_GetYawDeltaToObject(obj, (GameObject*)target, NULL);
                }
                if ((s->modeBits & 0x10) != 0)
                {
                    objSetLookAtFlip(0, 1);
                    yawDelta = yawDelta + -0x8000;
                }
                ival = (short)yawDelta;
                ival = (ival >= 0) ? ival : -ival;
                if (((ival > 0x5555) || (target == 0)) ||
                    (Vec_distance(&obj->anim.worldPosX, &((GameObject*)target)->anim.worldPosX) > s->lookAtMaxDistance))
                {
                    if ((s->phase != MOVELIB_PHASE_IDLE) || ((target == 0 && ((u32)s->lastTarget != 0))))
                    {
                        objJointTracksCaptureCurrentAngles(obj, (int*)seqHandle, (u32)s->pointCount, s->animChannels);
                        s->setupFlag = 10;
                        objJointTracksSetAngles(s->animChannels, (u32)s->pointCount, 0, 0);
                        s->phase = MOVELIB_PHASE_IDLE;
                    }
                }
                else
                {
                    if ((target != (u32)s->lastTarget) || (s->phase == MOVELIB_PHASE_IDLE))
                    {
                        objJointTracksCaptureCurrentAngles(obj, (int*)seqHandle, (u32)s->pointCount, s->animChannels);
                        s->setupFlag = 1;
                    }
                    if ((s->modeBits & 8) != 0)
                    {
                        s->setupFlag = 0;
                    }
                    objJointTracksAimAtTarget(obj, (GameObject*)target, &s->targetX,
                                              (s->setupFlag != 0) ? s->animChannels : NULL, s->turnTable, targetYaw, 8,
                                              s->yawLimitA);
                    s->phase = MOVELIB_PHASE_TURN;
                }
                *(u32*)&s->lastTarget = target;
                if (s->setupFlag == 0)
                {
                    s->lockTarget = NULL;
                }
                if (((s->modeBits & 8) == 0) && (s->setupFlag != 0))
                {
                    s->setupFlag = !characterTrackJointList(obj, (int*)seqHandle, s->pointCount, s->animChannels);
                }
            }
        }
    }
}

int moveLibTurnToFaceTarget(GameObject* obj, GameObject* targetObj, int* turning, PostControl* control, float* turnSpeed,
                       s16* moves, f32* targetPos)
{
    int yawDelta;
    int* jointKeys;
    s16 hitResult;
    int turnAmount;
    u32 ret;
    f32 distance;
    s16 turnDelta;

    jointKeys = objGetLookAtJointKeys();
    if (targetObj->anim.hitReactState != 0)
    {
        ObjHitsPriorityState* hitShape = (ObjHitsPriorityState*)targetObj->anim.hitReactState;
        if ((hitShape->shapeFlags & 2) != 0)
        {
            distance = 4.0f * (f32)(s32)hitShape->primaryCapsuleOffsetB;
        }
        else if ((hitShape->shapeFlags & 1) != 0)
        {
            distance = (f32)(s32)hitShape->primaryRadius;
        }
        else
        {
            distance = 30.0f;
        }
    }
    else
    {
        distance = 30.0f;
    }

    yawDelta = Obj_GetYawDeltaToObject(obj, targetObj, NULL);
    if ((control->flags & 0x10) != 0)
    {
        objSetLookAtFlip(0, 1);
        yawDelta += -0x8000;
    }

    hitResult = objJointTracksAimAtTarget(obj, targetObj, control->primary,
                                          ((control->flags & 8) != 0) ? NULL : control->secondary, control->events,
                                          distance, 8, control->eventState);
    if ((control->flags & 8) == 0)
    {
        control->blocked =
            (u32)__cntlzw(characterTrackJointList(obj, jointKeys, control->contactAnim, control->secondary)) >> 5;
    }
    control->blocked = 0;

    if (((control->flags & 2) != 0) && (hitResult != 0))
    {
        *turning = 0;
        return 0;
    }

    if (control->blocked == 0)
    {
        if (((s16)yawDelta > -control->yawLimit) && ((s16)yawDelta < control->yawLimit))
        {
            *turnSpeed = 0.005f;
            *turning = 0;
            return (u32)__cntlzw((int)hitResult) >> 5;
        }
    }

    if ((*turning == 0) && (hitResult != 0))
    {
        *turning = 1;
        *turnSpeed = 0.005f;
    }
    else if (*turning != 0)
    {
        if (((s16)yawDelta > 0) && (obj->anim.currentMove != moves[1]))
        {
            ObjAnim_SetCurrentMove(obj, moves[1], 0.0f, 0);
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x1e);
        }
        if (((s16)yawDelta < 0) && (obj->anim.currentMove != moves[0]))
        {
            ObjAnim_SetCurrentMove(obj, moves[0], 0.0f, 0);
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x1e);
        }

        if (hitResult == 0)
        {
            turnAmount = (s16)yawDelta;
            if (turnAmount > 0)
            {
                turnAmount = turnAmount / 0x14;
            }
            else
            {
                turnAmount = turnAmount / 0x14;
            }
            turnDelta = turnAmount;
        }
        else
        {
            turnAmount = (s16)yawDelta;
            if (turnAmount > 0)
            {
                turnAmount = (turnAmount - 0x500) / 0x14;
            }
            else
            {
                turnAmount = (turnAmount + 0x500) / 0x14;
            }
            turnDelta = turnAmount;
        }

        obj->anim.rotX += turnDelta;
        ret = (u32)turnDelta;
        ret = ((int)ret >= 0) ? ret : -ret;
        *turnSpeed = (float)(s32)ret / 20922.25f;
    }
    return 1;
}

void dll_2E_release_nop(void)
{
}

void dll_2E_initialise_nop(void)
{
}

u8 gMoveLibDefaultMoveData[20] = {0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23,
                                  0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23};

typedef struct Dll2EDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback updateLookAt;
    ObjectDescriptorCallback setLockTarget;
    ObjectDescriptorCallback initState;
    ObjectDescriptorCallback setTargetFromPathPoint;
    ObjectDescriptorCallback updateSequenceTurn;
    ObjectDescriptorCallback setReattackDelay;
    ObjectDescriptorCallback setMoveTables;
    ObjectDescriptorCallback getCurveActionTarget;
    ObjectDescriptorCallback getDistanceToCurveAction;
    ObjectDescriptorCallback getCurveActionTargetAimed;
    ObjectDescriptorCallback moveToTarget;
    ObjectDescriptorCallback advanceAlongRoute;
    ObjectDescriptorCallback slot0F;
    u32 padding;
} Dll2EDllInterface;

Dll2EDllInterface dll_2E = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_16_SLOTS,
    (ObjectDescriptorCallback)dll_2E_initialise_nop,
    (ObjectDescriptorCallback)dll_2E_release_nop,
    0,
    (ObjectDescriptorCallback)dll_2E_updateLookAt,
    (ObjectDescriptorCallback)dll_2E_setLockTarget,
    (ObjectDescriptorCallback)dll_2E_initState,
    (ObjectDescriptorCallback)dll_2E_setTargetFromPathPoint,
    (ObjectDescriptorCallback)dll_2E_updateSequenceTurn,
    (ObjectDescriptorCallback)dll_2E_setReattackDelay,
    (ObjectDescriptorCallback)dll_2E_setMoveTables,
    (ObjectDescriptorCallback)dll_2E_getCurveActionTarget,
    (ObjectDescriptorCallback)dll_2E_getDistanceToCurveAction,
    (ObjectDescriptorCallback)dll_2E_getCurveActionTargetAimed,
    (ObjectDescriptorCallback)dll_2E_moveToTarget,
    (ObjectDescriptorCallback)dll_2E_advanceAlongRoute,
    (ObjectDescriptorCallback)dll_2E_func0F_ret_0,
    0,
};
