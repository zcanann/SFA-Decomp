/*
 * moveLib (DLL 0x2E) - shared movement helpers for baddie/object DLLs.
 * Exports (dll_2E_func*) drive scripted curve traversal and homing:
 *   - func05/06/09 prime and refresh a movement-state block laid out at
 *     state+0x1c.. (path-relative start offset, blend factors, anim
 *     channel tables) keyed off the per-object curve point;
 *   - func0A/0B/0C resolve a ROM curve point into a position + packed
 *     facing angle, optionally aiming at the nearest group-8 object;
 *   - func0D homes an object toward a target at a given speed, snapping
 *     when close and easing the yaw, pacing a walk move;
 *   - func0E advances the object along its movement curve, snapping to
 *     ground and easing yaw toward the path direction;
 *   - func03/07 + objAnimFn_80115650 run the object-sequence scripted
 *     move steps (movementState 4 arms, 5 walks the sub-phases at
 *     state+0x600) and the turn/lead-anim arbitration.
 * func0F_ret_0/release_nop/initialise_nop are object-descriptor stubs.
 * The persistent movement-state byte fields live at state+0x600 (phase),
 * +0x601 (needs-reinit), +0x610 (point count), +0x611 (mode bits).
 */
#include "main/camera_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/objprint.h"
#include "main/curve_eval.h"
#include "main/object_descriptor.h"
#include "main/dll/baddie_state.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/FRONT/POST.h"
#include "string.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/frame_timing.h"

/* Persistent movement-state block that sits at the start of the per-object
 * extra for the baddie/object DLLs that use moveLib. The anim-channel table
 * region (0x1c..0x5bb) and the two packed turn/event tables (0x5bc/0x5da) are
 * handed to the seq helpers (objFn_8003acfc / fn_8003A9C0 / objMathFn_8003a380)
 * as raw blocks, so they stay byte arrays here. */

/* MoveLibState.phase (state+0x600): shared scripted-move / turn-arbitration
 * step. func03 (turn/lead-anim) walks 0/1/8; func07 (scripted move) walks the
 * 2/3/6/7 sub-phase chain. */
/* object group queried to find this object's target */
#define MOVELIB_TARGET_OBJGROUP 8

/* dll_2E_func0E route flags: curve walk reached its final point (done-guard) */
#define MOVELIB_CURVE_WALK_DONE 0x10

extern u8 gMoveLibDefaultMoveData[];
extern f32 lbl_803E1C88;
extern f32 lbl_803E1C8C;
extern f32 lbl_803E1C90;
extern f32 lbl_803E1CC8;
extern const f32 lbl_803E1CCC;
extern f32 lbl_803E1CB0;
extern f32 lbl_803E1CC4;
extern f32 lbl_803E1CB4;
extern f32 lbl_803E1CB8;
extern f32 gMoveLibPi;
extern f32 gMoveLibAngleHalfScale;
extern f32 lbl_803E1CA4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CD4;
extern f32 lbl_803E1CD8;
extern f32 lbl_803E1CDC;
extern f32 lbl_803E1CE0;

extern void TitleScreenInit_render(void);
extern void n_rareware_render(void);

extern void TitleScreenInit_frameEnd(void);
extern void n_rareware_frameEnd(void);

extern void TitleScreenInit_frameStart(void);
extern void n_rareware_frameStart(void);

extern void TitleScreenInit_release(void);
extern void n_rareware_release(void);

extern void TitleScreenInit_initialise(void);
extern void n_rareware_initialise(void);

extern int ObjGroup_FindNearestObjectToPoint();
extern int objAnimFn_80115650();
extern void vecRotateZXY(s16* angles, f32* vec);
extern int getAngle(float y, float x);
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve);
extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern s16* objModelGetVecFn_800395d8(GameObject* obj, int idx);
extern void normalize(f32* x, f32* y, f32* z);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();

f32 fn_80114224(int startPos, int endPos, int startTangent, int endTangent, int steps)
{
    f32 prev_x, prev_y, prev_z;
    f32 total;
    f32 t;
    f32 cur_x, cur_y, cur_z;
    f32 dx, dy, dz;
    f32 buf[4];
    int i;

    prev_x = *(f32*)(startPos + 0);
    prev_y = *(f32*)(startPos + 4);
    prev_z = *(f32*)(startPos + 8);
    total = lbl_803E1C90;

    for (i = 1; i < steps + 1; i++)
    {
        t = (f32)i / steps;

        buf[0] = *(f32*)(startPos + 0);
        buf[1] = *(f32*)(startTangent + 0);
        buf[2] = *(f32*)(endPos + 0);
        buf[3] = *(f32*)(endTangent + 0);
        cur_x = Curve_EvalHermiteValuesFirst(buf, t, 0);
        dx = cur_x - prev_x;

        buf[0] = *(f32*)(startPos + 4);
        buf[1] = *(f32*)(startTangent + 4);
        buf[2] = *(f32*)(endPos + 4);
        buf[3] = *(f32*)(endTangent + 4);
        cur_y = Curve_EvalHermiteValuesFirst(buf, t, 0);
        dy = cur_y - prev_y;

        buf[0] = *(f32*)(startPos + 8);
        buf[1] = *(f32*)(startTangent + 8);
        buf[2] = *(f32*)(endPos + 8);
        buf[3] = *(f32*)(endTangent + 8);
        cur_z = Curve_EvalHermiteValuesFirst(buf, t, 0);
        dz = cur_z - prev_z;

        total += sqrtf(dx * dx + dy * dy + dz * dz);
        prev_x = cur_x;
        prev_y = cur_y;
        prev_z = cur_z;
    }

    return total;
}

int fn_80114408(GameObject* obj, int def, int state, int phaseOut, f32 speed)
{
    extern f32 fn_80114224(int, int, int, int, int);
    extern f32 lbl_803E1CA0;
    int ret = 0;

    if ((void*)def != NULL)
    {
        s16 angles[3];
        f32 va;
        f32 vb;
        va = *(f32*)&lbl_803E1CA0;
        ((BaddieState*)state)->posY = va;
        vb = lbl_803E1C90;
        ((BaddieState*)state)->posZ = vb;
        *(f32*)(state + 0x20) = vb;
        *(f32*)(state + 0x24) = va;
        *(f32*)(state + 0x28) = vb;
        *(f32*)(state + 0x2c) = vb;
        vecRotateYXZ((s16*)obj, (f32*)(state + 0x18));
        angles[2] = 0;
        angles[1] = (s16)(s8) * (u8*)(def + 0x2d);
        angles[0] = (s16)(s8) * (u8*)(def + 0x2c);
        vecRotateYXZ(angles, (f32*)(state + 0x24));
        *(f32*)phaseOut = lbl_803E1C90;
        *(f32*)(state + 0x34) = fn_80114224(state, state + 0x18, state + 0xc, state + 0x24, 10);
    }
    else
    {
        *(f32*)phaseOut = *(f32*)phaseOut + speed * (f32)(u32)framesThisStep / *(f32*)(state + 0x34);
        if (*(f32*)phaseOut >= *(f32*)&lbl_803E1CA4)
        {
            ret = 1;
            *(f32*)phaseOut = lbl_803E1CA4;
        }
    }

    {
        f32 buf[4];
        buf[0] = *(f32*)(state + 0x00);
        buf[1] = *(f32*)(state + 0x0c);
        buf[2] = ((BaddieState*)state)->posY;
        buf[3] = *(f32*)(state + 0x24);
        (obj)->anim.localPosX = Curve_EvalHermiteValuesFirst(buf, *(f32*)phaseOut, 0);
        buf[0] = *(f32*)(state + 0x04);
        buf[1] = *(f32*)(state + 0x10);
        buf[2] = ((BaddieState*)state)->posZ;
        buf[3] = *(f32*)(state + 0x28);
        (obj)->anim.localPosY = Curve_EvalHermiteValuesFirst(buf, *(f32*)phaseOut, 0);
        buf[0] = *(f32*)(state + 0x08);
        buf[1] = ((BaddieState*)state)->posX;
        buf[2] = *(f32*)(state + 0x20);
        buf[3] = *(f32*)(state + 0x2c);
        (obj)->anim.localPosZ = Curve_EvalHermiteValuesFirst(buf, *(f32*)phaseOut, 0);
    }
    return ret;
}

int dll_2E_func0F_ret_0(void)
{
    return 0x0;
}

void dll_2E_setLookAtMaxDistance(int* state, f32 value)
{
    ((MoveLibState*)state)->lookAtMaxDistance = value;
}
void dll_2E_func04(int* state, int target)
{
    *(int*)&((MoveLibState*)state)->lockTarget = target;
}

void dll_2E_func08(int obj, int v1, int v2)
{
    MoveLibState* s = (MoveLibState*)obj;
    s->reattackDelayBase = v1;
    s->reattackDelayMin = v2;
    s->reattackTimer = v1;
}

void dll_2E_func09(int obj, void* src1, void* src2)
{
    MoveLibState* s = (MoveLibState*)obj;
    if (src1 == NULL)
        src1 = gMoveLibDefaultMoveData;
    if (src2 == NULL)
        src2 = gMoveLibDefaultMoveData;
    memcpy(s->turnTable, src1, (u32)s->pointCount * 2);
    memcpy(s->eventTable, src2, (u32)s->pointCount * 2);
}

f32 dll_2E_func0B(int obj, int arg)
{
    int r = ((int (*)(int))(*gRomCurveInterface)->slot40)(arg);
    if (r > -1)
    {
        return ((f32 (*)(int, int))(*gRomCurveInterface)->slot24)(obj, r);
    }
    return lbl_803E1C88;
}

void fn_80114B1C(int* obj)
{
    extern void objFn_8003acfc(GameObject * obj, int* types, int count, char* out);
    extern void fn_8003A9C0(char* p, int count, s16 a, s16 b);
    MoveLibState* state;
    int* types;

    types = seqFn_800394a0();
    state = ((GameObject*)obj)->extra;

    (*gCameraInterface)->setTarget(0);

    state->phase = MOVELIB_PHASE_IDLE;
    objFn_8003acfc((GameObject*)(obj), types, state->pointCount, (char*)state->animChannels);
    state->setupFlag = 0x50;
    fn_8003A9C0((char*)state->animChannels, state->pointCount, 0, 0);
}

/* Caller record filled by func0A/func0C: a packed facing angle plus the
 * resolved curve-point world position. */
typedef struct CurvePointResult
{
    s16 angle; /* 0x00 */
    u8 pad02[0xa];
    f32 x; /* 0x0c */
    f32 y; /* 0x10 */
    f32 z; /* 0x14 */
} CurvePointResult;

/* Copies a curve point's position and packed angle into the caller's
 * record. */
int dll_2E_func0A(int idx, char* outArg)
{
    CurvePointResult* out = (CurvePointResult*)outArg;
    int curveId;

    if (idx >= 0x1c)
    {
        return 0;
    }
    curveId = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (curveId > -1)
    {
        RomCurvePlacementDef* p = (RomCurvePlacementDef*)(*gRomCurveInterface)->getById(curveId);
        out->x = p->base.x;
        out->y = p->base.y;
        out->z = p->base.z;
        out->angle = (s16)(p->rotZ << 8);
        return 1;
    }
    return 0;
}

/* Copies a curve point's position into the caller's record and aims its
 * angle at the nearest group-8 object (falling back to the point's packed
 * angle). */
int dll_2E_func0C(int idx, char* outArg)
{
    CurvePointResult* out = (CurvePointResult*)outArg;
    f32 range;
    int curveId;

    range = lbl_803E1C8C;
    curveId = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (curveId > -1)
    {
        RomCurvePlacementDef* p = (RomCurvePlacementDef*)(*gRomCurveInterface)->getById(curveId);
        char* q;
        out->x = p->base.x;
        out->y = p->base.y;
        out->z = p->base.z;
        q = (char*)ObjGroup_FindNearestObjectToPoint(MOVELIB_TARGET_OBJGROUP, &out->x, &range);
        if (q != NULL)
        {
            out->angle = (s16)atan2i((int)(((GameObject*)q)->anim.localPosX - out->x),
                                     (int)(((GameObject*)q)->anim.localPosZ - out->z));
        }
        else
        {
            out->angle = (s16)(p->rotZ << 8);
        }
        return 1;
    }
    return 0;
}

/* Initializes the movement-state block and primes the animation channel
 * tables. */
void dll_2E_func05(GameObject* obj, MoveLibState* s, s16 a, s16 b, int count)
{
    extern void objFn_8003acfc(GameObject * obj, int* types, int count, char* out);
    extern void fn_8003AC14(GameObject * obj, void* types, int count);
    extern void fn_8003A9C0(char* p, int count, s16 a, s16 b);
    f32 z;

    s->yawLimitA = a;
    s->yawLimitB = b;
    s->pointCount = count;
    s->turnState = 0;
    z = lbl_803E1C90;
    s->animPhase = z;
    s->setupFlag = 0;
    *(int*)&s->lastTarget = 0;
    *(int*)&s->lockTarget = 0;
    s->lookAtMaxDistance = lbl_803E1C8C;
    s->phase = MOVELIB_PHASE_IDLE;
    s->needsReinit = 1;
    s->startOffsetX = z;
    s->startOffsetY = z;
    s->startOffsetZ = z;
    s->reattackDelayBase = -1;
    fn_8003AC14(obj, seqFn_800394a0(), count);
    objFn_8003acfc(obj, seqFn_800394a0(), count, (char*)s->animChannels);
    fn_8003A9C0((char*)s->animChannels, s->pointCount, 0, 0);
    dll_2E_func09((int)s, gMoveLibDefaultMoveData, gMoveLibDefaultMoveData);
}

/* Latches the path-relative start offset on first use and refreshes the
 * current path point position. */
void dll_2E_func06(GameObject* obj, MoveLibState* s, int point)
{
    extern void fn_8003AC14(GameObject * obj, void* types, int count);
    struct
    {
        s16 ang[3];
        f32 x0, y0, z0, x1, y1, z1;
    } v;

    if (s->needsReinit != 0)
    {
        f32 cA;
        f32 cB;
        fn_8003AC14(obj, seqFn_800394a0(), s->pointCount);
        ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
        ObjPath_GetPointWorldPosition(obj, point + 1, &v.x1, &v.y1, &v.z1, 0);
        cA = lbl_803E1CC8;
        cB = cA * v.x0 + v.x1;
        s->startOffsetX = cB * lbl_803E1CCC;
        s->startOffsetY = v.y0;
        cB = cA * v.z0 + v.z1;
        s->startOffsetZ = cB * lbl_803E1CCC;
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

/* Advances the object along its movement curve, snapping to ground and
 * easing the yaw toward the path direction. */
int dll_2E_func0E(GameObject* obj, RomCurveWalker* route, f32 phase, int state, int curveVariant, f32* rootOut,
                  int* flags)
{
    int moved;
    int hit;
    f32 ground;
    int fl;
    int args[2];

    moved = 1;
    hit = 0;
    ground = lbl_803E1C90;
    fl = *flags;
    if (fl & MOVELIB_CURVE_WALK_DONE)
    {
        return 1;
    }
    if (fl & 0x4)
    {
        if (fn_80114408(obj, 0, state, state + 0x30, phase) != 0)
        {
            args[0] = 0x19;
            args[1] = 0x15;
            (*gRomCurveInterface)->initCurve(route, (void*)obj, lbl_803E1CB0, args, (u8)curveVariant);
            *flags |= 8;
            moved = 1;
        }
    }
    else
    {
        hit = 0;
        if (Curve_AdvanceAlongPath(route) != 0 || route->atSegmentEnd != 0)
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
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, phase, rootOut);
    if (*flags & 1)
    {
        if (hitDetectFn_800658a4((int)obj, (obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, &ground,
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

/* Object-sequence scripted-move step: phase 4 arms the move, phase 5 walks
 * the setup/playback sub-phases. */
#pragma optimization_level 2
int dll_2E_func07(GameObject* obj, ObjSeqState* seq, MoveLibState* s, s16 a, s16 b)
{
    extern void objFn_8003acfc(GameObject * obj, int* types, int count, char* out);
    extern int Obj_GetPlayerObject(void);
    s16 pair[2];
    int mode;
    int player;
    u8* phasePtr;

    player = Obj_GetPlayerObject();
    pair[0] = a;
    pair[1] = b;
    {
        char* p = *(char**)&(obj)->anim.hitReactState;
        *(s16*)(p + 0x60) = *(s16*)(p + 0x60) | 1;
    }
    phasePtr = &s->phase;
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
        seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_80114B1C;
        return 0;
    }
    else if (mode == 5)
    {
        if (s->phase >= MOVELIB_PHASE_RUN && *phasePtr <= MOVELIB_PHASE_FINISH)
        {
            void* types = seqFn_800394a0();
            switch (s->phase)
            {
            case MOVELIB_PHASE_SETUP:
                objFn_8003acfc(obj, types, s->pointCount, (char*)s->animChannels);
                s->setupFlag = 0;
                s->phase = MOVELIB_PHASE_RUN;
            case MOVELIB_PHASE_RUN:
                if (objAnimFn_80115650(obj, player, &s->turnState, (char*)s, (char*)s, pair, &s->targetX) == 0)
                {
                    s->phase = MOVELIB_PHASE_DONE;
                }
                break;
            case MOVELIB_PHASE_DONE:
                s->phase = MOVELIB_PHASE_FINISH;
            case MOVELIB_PHASE_FINISH:
                s->animPhase = lbl_803E1CC4;
                break;
            }
            *(int*)&s->lastTarget = player;
            ObjAnim_AdvanceCurrentMove((int)obj, s->animPhase, framesThisStep, NULL);
            if (s->phase == MOVELIB_PHASE_FINISH)
            {
                s16* v;
                seq->flags = seq->flags | 8;
                v = objModelGetVecFn_800395d8(obj, 0);
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
#pragma optimization_level 4

/* Homes the object toward its target at the given speed, snapping when
 * close, easing yaw and pacing the walk anim. */
int dll_2E_func0D(int obj, int target, f32 speed, int move, f32* out, u8* flags)
{
    f32 dz;
    f32 dy;
    f32 dx;
    f32 ground;
    f32 dist;
    s16 delta;

    if ((void*)target == NULL)
    {
        return 0;
    }
    dx = ((GameObject*)target)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy = ((GameObject*)target)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dz = ((GameObject*)target)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < lbl_803E1CB4 * speed)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)target)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)target)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)target)->anim.localPosZ;
        if (*flags & 1)
        {
            if (hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                     ((GameObject*)obj)->anim.localPosZ, &ground, 0) == 0)
            {
                ((GameObject*)obj)->anim.localPosY -= ground;
            }
        }
        return 1;
    }
    normalize(&dx, &dy, &dz);
    ((GameObject*)obj)->anim.velocityX = dx * (speed * timeDelta);
    ((GameObject*)obj)->anim.velocityY = dy * (speed * timeDelta);
    ((GameObject*)obj)->anim.velocityZ = dz * (speed * timeDelta);
    if (*flags & 1)
    {
        if (hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &ground, 0) == 0)
        {
            ((GameObject*)obj)->anim.localPosY -= ground;
        }
    }
    if (*flags & 2)
    {
        delta = ((GameObject*)target)->anim.rotX - (u16)((GameObject*)obj)->anim.rotX;
        if (delta > 0x8000)
        {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xffff;
        }
        ((GameObject*)obj)->anim.rotX =
            (f32) * (s16*)(int)(GameObject*)obj + (lbl_803E1CB8 + delta) * (speed * timeDelta) / dist;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (move != -1)
    {
        if (((GameObject*)obj)->anim.currentMove != move)
        {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E1C90, 0);
        }
        delta = ((GameObject*)obj)->anim.rotX - (u16)(s16)getAngle(dx, dz);
        if (delta > 0x8000)
        {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xffff;
        }
        speed = speed * -mathCosf(gMoveLibPi * delta / gMoveLibAngleHalfScale);
        ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, speed, out);
    }
    return 0;
}

typedef struct ProjNearSearch
{
    f32 range;
    f32 dx;
    f32 dy;
    f32 dz;
} ProjNearSearch;

void dll_2E_func03(GameObject* obj, MoveLibState* s)
{
    extern int fn_8003A8B4();
    extern int objMathFn_8003a380(u16 * obj, u32 target, float* pos, int pathState, short* turnState, float targetYaw,
                                  int mode, short yawLimit);
    extern int fn_80038F1C(int a, int b);
    extern int objFn_8003acfc();
    extern int fn_8003AC14();
    extern int fn_8003A9C0();
    register int yawDelta;
    register int seqHandle;
    register u32 target;
    void* targetObj;
    int bit1;
    int ival;
    float dist;
    float blendA;
    float blendB;
    float blendMax;
    float targetYaw;
    ProjNearSearch sv;

    sv.range = lbl_803E1C8C;
    targetYaw = lbl_803E1CD0;
    yawDelta = 0;
    seqHandle = (int)seqFn_800394a0();
    (void)Obj_GetPlayerObject();
    if (s->needsReinit == 0)
    {
        bit1 = s->modeBits & 1;
        if (bit1 != 0 && s->phase != MOVELIB_PHASE_HELD)
        {
            s->phase = MOVELIB_PHASE_HELD;
            if ((s->modeBits & 8) == 0)
            {
                objFn_8003acfc((GameObject*)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                s->setupFlag = 0x50;
                fn_8003A9C0((char*)s->animChannels, (u32)s->pointCount, 0, 0);
            }
            else
            {
                fn_8003AC14((GameObject*)obj, seqFn_800394a0(), (u32)s->pointCount);
            }
        }
        else if (bit1 == 0 && s->phase == MOVELIB_PHASE_HELD)
        {
            s->phase = MOVELIB_PHASE_IDLE;
            if ((s->modeBits & 8) == 0)
            {
                objFn_8003acfc((GameObject*)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                s->setupFlag = 0x50;
            }
        }
        if (s->phase > MOVELIB_PHASE_TURN)
        {
            if (s->setupFlag != 0 && (s->modeBits & 8) == 0)
            {
                s->setupFlag = !fn_8003A8B4(obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
            }
            else
            {
                fn_8003AC14((GameObject*)obj, seqFn_800394a0(), (u32)s->pointCount);
            }
        }
        else
        {
            targetObj = s->lockTarget;
            target = (u32)(targetObj != NULL
                               ? targetObj
                               : (targetObj = (void*)ObjGroup_FindNearestObject(MOVELIB_TARGET_OBJGROUP, obj, &sv)));
            if (targetObj != NULL)
            {
                if ((s->modeBits & 0x20) != 0)
                {
                    sv.dx = s->targetX - ((GameObject*)targetObj)->anim.localPosX;
                    sv.dy = s->targetY - ((GameObject*)targetObj)->anim.localPosY;
                    sv.dz = s->targetZ - ((GameObject*)targetObj)->anim.localPosZ;
                    blendA = sv.dx * sv.dx;
                    blendB = sv.dz * sv.dz;
                    dist = sqrtf(blendA + blendB);
                    if (dist <= lbl_803E1CD4)
                    {
                        blendA = (dist - lbl_803E1CD8) / lbl_803E1CD0;
                        blendMax = lbl_803E1CA4;
                        blendB = lbl_803E1C90;
                        blendB = (blendA < blendB) ? blendB : ((blendA > blendMax) ? blendMax : blendA);
                        blendB = lbl_803E1CA4 - blendB;
                        s->targetX = s->targetX * (blendA = *(f32*)&lbl_803E1CA4 - blendB) +
                                     ((GameObject*)obj)->anim.localPosX * blendB;
                        s->targetZ = s->targetZ * blendA + ((GameObject*)obj)->anim.localPosZ * blendB;
                    }
                }
                if ((s->reattackDelayBase != -1) && (target == *(u32*)&s->lastTarget))
                {
                    ival = -framesThisStep + s->reattackTimer;
                    s->reattackTimer = ival;
                    if ((ival <= 0) && (0 < (int)(s->reattackTimer + framesThisStep)))
                    {
                        objFn_8003acfc((GameObject*)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                        s->setupFlag = 0x50;
                        fn_8003A9C0((char*)s->animChannels, (u32)s->pointCount, 0, 0);
                        s->phase = MOVELIB_PHASE_IDLE;
                        return;
                    }
                    if (s->setupFlag != 0)
                    {
                        s->setupFlag = !fn_8003A8B4(obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
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
                if ((target != *(u32*)&s->lastTarget) && (target != 0))
                {
                    if (((GameObject*)target)->anim.hitReactState != NULL)
                    {
                        if ((((PostMotionTarget*)((GameObject*)target)->anim.hitReactState)->flags & 2) != 0)
                        {
                            targetYaw =
                                lbl_803E1CDC *
                                (float)(int)((PostMotionTarget*)((GameObject*)target)->anim.hitReactState)->yawB;
                        }
                        else if ((((PostMotionTarget*)((GameObject*)target)->anim.hitReactState)->flags & 1) != 0)
                        {
                            targetYaw =
                                (float)(int)((PostMotionTarget*)((GameObject*)target)->anim.hitReactState)->yawA;
                        }
                        else
                        {
                            targetYaw = lbl_803E1CD0;
                        }
                    }
                    else
                    {
                        targetYaw = lbl_803E1CD0;
                    }
                }
                if (target != 0)
                {
                    yawDelta = Obj_GetYawDeltaToObject(obj, target, NULL);
                }
                if ((s->modeBits & 0x10) != 0)
                {
                    fn_80038F1C(0, 1);
                    yawDelta = yawDelta + -0x8000;
                }
                ival = (short)yawDelta;
                ival = (ival >= 0) ? ival : -ival;
                if (((0x5555 < ival) || (target == 0)) ||
                    (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)target)->anim.worldPosX) >
                     s->lookAtMaxDistance))
                {
                    if ((s->phase != MOVELIB_PHASE_IDLE) || ((target == 0 && (*(u32*)&s->lastTarget != 0))))
                    {
                        objFn_8003acfc((GameObject*)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                        s->setupFlag = 10;
                        fn_8003A9C0((char*)s->animChannels, (u32)s->pointCount, 0, 0);
                        s->phase = MOVELIB_PHASE_IDLE;
                    }
                }
                else
                {
                    if ((target != *(u32*)&s->lastTarget) || (s->phase == MOVELIB_PHASE_IDLE))
                    {
                        objFn_8003acfc((GameObject*)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                        s->setupFlag = 1;
                    }
                    if ((s->modeBits & 8) != 0)
                    {
                        s->setupFlag = 0;
                    }
                    objMathFn_8003a380((u16*)obj, target, &s->targetX, (s->setupFlag != 0) ? (int)s->animChannels : 0,
                                       s->turnTable, targetYaw, 8, s->yawLimitA);
                    s->phase = MOVELIB_PHASE_TURN;
                }
                *(u32*)&s->lastTarget = target;
                if (s->setupFlag == 0)
                {
                    *(u32*)&s->lockTarget = 0;
                }
                if (((s->modeBits & 8) == 0) && (s->setupFlag != 0))
                {
                    s->setupFlag = !fn_8003A8B4(obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                }
            }
        }
    }
}

int objAnimFn_80115650(PostObjAnimComponent* objAnim, PostObject* obj, int* turning, PostControl* control,
                       float* turnSpeed, s16* moves)
{
    extern int fn_8003A8B4(PostObjAnimComponent * objAnim, PostMotionTarget * leadAnims, u8 contactAnim,
                           void* secondary);
    extern s16 objMathFn_8003a380(PostObjAnimComponent * objAnim, PostObject * obj, void* primary, void* secondary,
                                  s16* events, double distance, int eventCount, int eventState);
    extern void fn_80038F1C(int a, int b);
    int yawDelta;
    PostMotionTarget* motion;
    s16 hitResult;
    int turnAmount;
    u32 ret;
    double distance;
    void* secondary;
    s16 turnDelta;

    motion = (PostMotionTarget*)seqFn_800394a0();
    if (obj->motion != 0)
    {
        if ((obj->motion->flags & 2) != 0)
        {
            distance = (double)(lbl_803E1CDC * (float)(s32)obj->motion->yawB);
        }
        else if ((obj->motion->flags & 1) != 0)
        {
            distance = (double)(float)(s32)obj->motion->yawA;
        }
        else
        {
            distance = (double)lbl_803E1CD0;
        }
    }
    else
    {
        distance = (double)lbl_803E1CD0;
    }

    yawDelta = Obj_GetYawDeltaToObject((u16*)objAnim, obj, NULL);
    if ((control->flags & 0x10) != 0)
    {
        fn_80038F1C(0, 1);
        yawDelta += -0x8000;
    }

    hitResult = objMathFn_8003a380(objAnim, obj, control->primary, ((control->flags & 8) != 0) ? 0 : control->secondary,
                                   control->events, distance, 8, control->eventState);
    if ((control->flags & 8) == 0)
    {
        control->blocked = (u32)__cntlzw(fn_8003A8B4(objAnim, motion, control->contactAnim, control->secondary)) >> 5;
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
            *turnSpeed = lbl_803E1CC4;
            *turning = 0;
            return (u32)__cntlzw((int)hitResult) >> 5;
        }
    }

    if ((*turning == 0) && (hitResult != 0))
    {
        *turning = 1;
        *turnSpeed = lbl_803E1CC4;
    }
    else if (*turning != 0)
    {
        if ((0 < (s16)yawDelta) && (objAnim->currentMove != moves[1]))
        {
            ObjAnim_SetCurrentMove((int)objAnim, moves[1], lbl_803E1C90, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)objAnim, 0x1e);
        }
        if (((s16)yawDelta < 0) && (objAnim->currentMove != moves[0]))
        {
            ObjAnim_SetCurrentMove((int)objAnim, moves[0], lbl_803E1C90, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)objAnim, 0x1e);
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

        objAnim->yaw += turnDelta;
        ret = (u32)(s16)turnDelta;
        ret = ((int)ret >= 0) ? ret : -ret;
        *turnSpeed = (float)(s32)ret / lbl_803E1CE0;
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

ObjectDescriptor16WithPadding dll_2E = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_16_SLOTS,
        (ObjectDescriptorCallback)dll_2E_initialise_nop,
        (ObjectDescriptorCallback)dll_2E_release_nop,
        0,
        (ObjectDescriptorCallback)dll_2E_func03,
        (ObjectDescriptorCallback)dll_2E_func04,
        (ObjectDescriptorCallback)dll_2E_func05,
        (ObjectDescriptorCallback)dll_2E_func06,
        (ObjectDescriptorCallback)dll_2E_func07,
        (ObjectDescriptorCallback)dll_2E_func08,
        (ObjectDescriptorExtraSizeCallback)dll_2E_func09,
        (ObjectDescriptorCallback)dll_2E_func0A,
        (ObjectDescriptorCallback)dll_2E_func0B,
        (ObjectDescriptorCallback)dll_2E_func0C,
        (ObjectDescriptorCallback)dll_2E_func0D,
        (ObjectDescriptorCallback)dll_2E_func0E,
        (ObjectDescriptorCallback)dll_2E_func0F_ret_0,
    },
    0,
};

/* descriptor/ptr table auto 0x8031a148-0x8031a1c8 */
u32 lbl_8031A148[12] = {0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
u32 lbl_8031A178[10] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00050000,
                        (u32)TitleScreenInit_initialise,
                        (u32)TitleScreenInit_release,
                        0x00000000,
                        (u32)TitleScreenInit_frameStart,
                        (u32)TitleScreenInit_frameEnd,
                        (u32)TitleScreenInit_render};
u32 lbl_8031A1A0[10] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00050000,
                        (u32)n_rareware_initialise,
                        (u32)n_rareware_release,
                        0x00000000,
                        (u32)n_rareware_frameStart,
                        (u32)n_rareware_frameEnd,
                        (u32)n_rareware_render};
