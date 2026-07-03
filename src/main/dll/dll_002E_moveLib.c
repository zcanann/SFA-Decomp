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
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/FRONT/POST.h"
#include "string.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
extern int ObjGroup_FindNearestObjectToPoint();
extern int objAnimFn_80115650();
extern f32 Curve_EvalHermite(f32* points, f32 t, int unused);
extern f32 sqrtf(f32 x);
extern u8 gMoveLibDefaultMoveData[];
extern f32 lbl_803E1C88;
extern f32 lbl_803E1C8C;
extern f32 timeDelta;
extern f32 lbl_803E1C90;
extern void vecRotateZXY(s16 * angles, f32 * vec);
extern f32 lbl_803E1CC8;
extern const f32 lbl_803E1CCC;
extern int getAngle(float y, float x);
extern float mathCosf(float x);
extern int Curve_AdvanceAlongPath(RomCurveWalker *curve);
extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern f32 lbl_803E1CB0;
extern s16* objModelGetVecFn_800395d8(int obj, int idx);
extern u8 framesThisStep;
extern f32 lbl_803E1CC4;
extern void normalize(f32 * x, f32 * y, f32 * z);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 lbl_803E1CB4;
extern f32 lbl_803E1CB8;
extern f32 gMoveLibPi;
extern f32 gMoveLibAngleHalfScale;
extern f32 Vec_distance(f32* a, f32* b);
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();
extern f32 lbl_803E1CA4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CD4;
extern f32 lbl_803E1CD8;
extern f32 lbl_803E1CDC;
extern f32 lbl_803E1CE0;

/* Persistent movement-state block that sits at the start of the per-object
 * extra for the baddie/object DLLs that use moveLib. The anim-channel table
 * region (0x1c..0x5bb) and the two packed turn/event tables (0x5bc/0x5da) are
 * handed to the seq helpers (objFn_8003acfc / fn_8003A9C0 / objMathFn_8003a380)
 * as raw blocks, so they stay byte arrays here. */
typedef struct MoveLibState
{
    f32 animPhase; /* 0x00: phase fed to ObjAnim_AdvanceCurrentMove */
    f32 startOffsetX; /* 0x04: path-relative start offset (blend source) */
    f32 startOffsetY; /* 0x08 */
    f32 startOffsetZ; /* 0x0c */
    f32 targetX; /* 0x10: current path / follow point (blend dest) */
    f32 targetY; /* 0x14 */
    f32 targetZ; /* 0x18 */
    u8 animChannels[0x5a0]; /* 0x1c: anim channel table block */
    s16 turnTable[15]; /* 0x5bc: turn-state table (count entries) */
    s16 eventTable[15]; /* 0x5da: secondary table */
    int setupFlag; /* 0x5f8: anim setup/active latch (0x50/10/1/0) */
    int turnState; /* 0x5fc: objAnimFn_80115650 turning state */
    u8 phase; /* 0x600: movement phase */
    u8 needsReinit; /* 0x601: latch path-relative start on next refresh */
    u8 pad602[2];
    void* lastTarget; /* 0x604: previous locked target */
    void* lockTarget; /* 0x608: forced lock target (0 = nearest group-8) */
    s16 yawLimitA; /* 0x60c: yaw-limit pair passed to objMathFn_8003a380 */
    s16 yawLimitB; /* 0x60e */
    u8 pointCount; /* 0x610: number of path/anim points */
    u8 modeBits; /* 0x611: behaviour mode bitset */
    u8 pad612[2];
    f32 lookAtMaxDistance; /* 0x614 */
    int reattackDelayBase; /* 0x618 */
    int reattackDelayMin; /* 0x61c */
    int reattackTimer; /* 0x620 */
} MoveLibState;

STATIC_ASSERT(offsetof(MoveLibState, targetX) == 0x10);
STATIC_ASSERT(offsetof(MoveLibState, turnTable) == 0x5bc);
STATIC_ASSERT(offsetof(MoveLibState, eventTable) == 0x5da);
STATIC_ASSERT(offsetof(MoveLibState, setupFlag) == 0x5f8);
STATIC_ASSERT(offsetof(MoveLibState, phase) == 0x600);
STATIC_ASSERT(offsetof(MoveLibState, pointCount) == 0x610);
STATIC_ASSERT(offsetof(MoveLibState, lookAtMaxDistance) == 0x614);
STATIC_ASSERT(offsetof(MoveLibState, reattackTimer) == 0x620);

f32 fn_80114224(int p1, int p2, int p3, int p4, int n)
{
    f32 prev_x, prev_y, prev_z;
    f32 total;
    f32 t;
    f32 cur_x, cur_y, cur_z;
    f32 dx, dy, dz;
    f32 buf[4];
    int i;

    prev_x = *(f32*)(p1 + 0);
    prev_y = *(f32*)(p1 + 4);
    prev_z = *(f32*)(p1 + 8);
    total = lbl_803E1C90;

    for (i = 1; i < n + 1; i++)
    {
        t = (f32)i / n;

        buf[0] = *(f32*)(p1 + 0);
        buf[1] = *(f32*)(p3 + 0);
        buf[2] = *(f32*)(p2 + 0);
        buf[3] = *(f32*)(p4 + 0);
        cur_x = Curve_EvalHermite(buf, t, 0);
        dx = cur_x - prev_x;

        buf[0] = *(f32*)(p1 + 4);
        buf[1] = *(f32*)(p3 + 4);
        buf[2] = *(f32*)(p2 + 4);
        buf[3] = *(f32*)(p4 + 4);
        cur_y = Curve_EvalHermite(buf, t, 0);
        dy = cur_y - prev_y;

        buf[0] = *(f32*)(p1 + 8);
        buf[1] = *(f32*)(p3 + 8);
        buf[2] = *(f32*)(p2 + 8);
        buf[3] = *(f32*)(p4 + 8);
        cur_z = Curve_EvalHermite(buf, t, 0);
        dz = cur_z - prev_z;

        total += sqrtf(dx * dx + dy * dy + dz * dz);
        prev_x = cur_x;
        prev_y = cur_y;
        prev_z = cur_z;
    }

    return total;
}

int fn_80114408(int p1, int p2, int p3, int p4, f32 p5)
{
    extern void vecRotateYXZ(int, int);
    extern f32 fn_80114224(int, int, int, int, int);
    extern f32 lbl_803E1CA0;
    int ret = 0;

    if ((void*)p2 != NULL)
    {
        s16 tmp[3];
        f32 va;
        f32 vb;
        va = *(f32*)&lbl_803E1CA0;
        ((BaddieState*)p3)->posY = va;
        vb = lbl_803E1C90;
        ((BaddieState*)p3)->posZ = vb;
        *(f32*)(p3 + 0x20) = vb;
        *(f32*)(p3 + 0x24) = va;
        *(f32*)(p3 + 0x28) = vb;
        *(f32*)(p3 + 0x2c) = vb;
        vecRotateYXZ(p1, p3 + 0x18);
        tmp[2] = 0;
        tmp[1] = (s16)(s8) * (u8*)(p2 + 0x2d);
        tmp[0] = (s16)(s8) * (u8*)(p2 + 0x2c);
        vecRotateYXZ((int)tmp, p3 + 0x24);
        *(f32*)p4 = lbl_803E1C90;
        *(f32*)(p3 + 0x34) = fn_80114224(p3, p3 + 0x18, p3 + 0xc, p3 + 0x24, 10);
    }
    else
    {
        *(f32*)p4 = *(f32*)p4 + p5 * (f32)(u32)
        framesThisStep / *(f32*)(p3 + 0x34);
        if (*(f32*)p4 >= *(f32*)&lbl_803E1CA4)
        {
            ret = 1;
            *(f32*)p4 = lbl_803E1CA4;
        }
    }

    {
        f32 buf[4];
        buf[0] = *(f32*)(p3 + 0x00);
        buf[1] = *(f32*)(p3 + 0x0c);
        buf[2] = ((BaddieState*)p3)->posY;
        buf[3] = *(f32*)(p3 + 0x24);
        ((GameObject*)p1)->anim.localPosX = Curve_EvalHermite(buf, *(f32*)p4, 0);
        buf[0] = *(f32*)(p3 + 0x04);
        buf[1] = *(f32*)(p3 + 0x10);
        buf[2] = ((BaddieState*)p3)->posZ;
        buf[3] = *(f32*)(p3 + 0x28);
        ((GameObject*)p1)->anim.localPosY = Curve_EvalHermite(buf, *(f32*)p4, 0);
        buf[0] = *(f32*)(p3 + 0x08);
        buf[1] = ((BaddieState*)p3)->posX;
        buf[2] = *(f32*)(p3 + 0x20);
        buf[3] = *(f32*)(p3 + 0x2c);
        ((GameObject*)p1)->anim.localPosZ = Curve_EvalHermite(buf, *(f32*)p4, 0);
    }
    return ret;
}

int dll_2E_func0F_ret_0(void) { return 0x0; }

void dll_2E_setLookAtMaxDistance(int* p, f32 v) { ((MoveLibState*)p)->lookAtMaxDistance = v; }
void dll_2E_func04(int* p, int v) { *(int*)&((MoveLibState*)p)->lockTarget = v; }

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
    if (src1 == NULL) src1 = gMoveLibDefaultMoveData;
    if (src2 == NULL) src2 = gMoveLibDefaultMoveData;
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
    extern void* seqFn_800394a0(void); /* #57 */
    extern void objFn_8003acfc(int* obj, int* types, int count, char* out); /* #57 */
    extern void fn_8003A9C0(char* p, int count, s16 a, s16 b); /* #57 */
    MoveLibState* state;
    int* types;

    types = seqFn_800394a0();
    state = ((GameObject*)obj)->extra;

    (*gCameraInterface)->setTarget(0);

    state->phase = 0;
    objFn_8003acfc(obj, types, state->pointCount, (char*)state->animChannels);
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

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */
int dll_2E_func0A(int idx, char* outArg)
{
    CurvePointResult* out = (CurvePointResult*)outArg;
    int r;

    if (idx >= 0x1c)
    {
        return 0;
    }
    r = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (r > -1)
    {
        RomCurvePlacementDef* p = (RomCurvePlacementDef*)(*gRomCurveInterface)->getById(r);
        out->x = p->base.x;
        out->y = p->base.y;
        out->z = p->base.z;
        out->angle = (s16)(p->rotZ << 8);
        return 1;
    }
    return 0;
}

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */
int dll_2E_func0C(int idx, char* outArg)
{
    CurvePointResult* out = (CurvePointResult*)outArg;
    f32 range;
    int r;

    range = lbl_803E1C8C;
    r = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (r > -1)
    {
        RomCurvePlacementDef* p = (RomCurvePlacementDef*)(*gRomCurveInterface)->getById(r);
        char* q;
        out->x = p->base.x;
        out->y = p->base.y;
        out->z = p->base.z;
        q = (char*)ObjGroup_FindNearestObjectToPoint(8, &out->x, &range);
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

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */
void dll_2E_func05(int obj, char* st, s16 a, s16 b, int count)
{
    extern void* seqFn_800394a0(void); /* #57 */
    extern void objFn_8003acfc(int* obj, int* types, int count, char* out); /* #57 */
    extern void fn_8003AC14(int obj, void* types, int count); /* #57 */
    extern void fn_8003A9C0(char* p, int count, s16 a, s16 b); /* #57 */
    MoveLibState* s = (MoveLibState*)st;
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
    s->phase = 0;
    s->needsReinit = 1;
    s->startOffsetX = z;
    s->startOffsetY = z;
    s->startOffsetZ = z;
    s->reattackDelayBase = -1;
    fn_8003AC14(obj, seqFn_800394a0(), count);
    objFn_8003acfc((int*)obj, seqFn_800394a0(), count, (char*)s->animChannels);
    fn_8003A9C0((char*)s->animChannels, s->pointCount, 0, 0);
    dll_2E_func09((int)st, gMoveLibDefaultMoveData, gMoveLibDefaultMoveData);
}

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */
void dll_2E_func06(int obj, char* st, int point)
{
    extern void* seqFn_800394a0(void); /* #57 */
    extern void fn_8003AC14(int obj, void* types, int count); /* #57 */
    MoveLibState* s = (MoveLibState*)st;
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
        s->startOffsetX -= ((GameObject*)obj)->anim.localPosX;
        s->startOffsetY -= ((GameObject*)obj)->anim.localPosY;
        s->startOffsetZ -= ((GameObject*)obj)->anim.localPosZ;
        v.ang[0] = (s16) - ((GameObject*)obj)->anim.rotZ;
        v.ang[1] = (s16) - ((GameObject*)obj)->anim.rotY;
        v.ang[2] = (s16) - ((GameObject*)obj)->anim.rotX;
        vecRotateZXY(v.ang, &s->startOffsetX);
        s->needsReinit = 0;
    }
    ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
    s->targetX = v.x0;
    s->targetY = v.y0;
    s->targetZ = v.z0;
}

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */
int dll_2E_func0E(int obj, RomCurveWalker* route, f32 phase, int p4, int c, f32* d, int* flags)
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
    if (fl & 0x10)
    {
        return 1;
    }
    if (fl & 0x4)
    {
        if (fn_80114408(obj, 0, p4, p4 + 0x30, phase) != 0)
        {
            args[0] = 0x19;
            args[1] = 0x15;
            (*gRomCurveInterface)->initCurve(route, (void*)obj, lbl_803E1CB0,
                                             args, (u8)c);
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
        ((GameObject*)obj)->anim.localPosX = route->posX;
        ((GameObject*)obj)->anim.localPosY = route->posY;
        ((GameObject*)obj)->anim.localPosZ = route->posZ;
        if (hit != 0)
        {
            *flags |= 0x10;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, phase, d);
    if (*flags & 1)
    {
        if (hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &ground, 0) == 0)
        {
            ((GameObject*)obj)->anim.localPosY -= ground;
        }
    }
    if (moved != 0 && (*flags & 0x2) != 0)
    {
        int t = (s16)(getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX,
                               ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) +
            0x8000);
        ((GameObject*)obj)->anim.rotX =
            (s16)(((GameObject*)obj)->anim.rotX + ((t - ((GameObject*)obj)->anim.rotX) >> 3));
    }
    return hit;
}

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */
#pragma optimization_level 2
int dll_2E_func07(int obj, ObjSeqState* seq, char* st, s16 a, s16 b)
{
    extern void* seqFn_800394a0(void); /* #57 */
    extern void objFn_8003acfc(int* obj, int* types, int count, char* out); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    MoveLibState* s = (MoveLibState*)st;
    s16 pair[2];
    int mode;
    int player;
    u8* phasePtr;

    player = Obj_GetPlayerObject();
    pair[0] = a;
    pair[1] = b;
    {
        char* p = *(char**)&((GameObject*)obj)->anim.hitReactState;
        *(s16*)(p + 0x60) = *(s16*)(p + 0x60) | 1;
    }
    phasePtr = &s->phase;
    mode = (s8)seq->movementState;
    if (mode == 4)
    {
        s->setupFlag = 0x50;
        seq->flags = seq->flags & ~8;
        seq->flags = seq->flags & ~2;
        s->phase = 3;
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
        if (s->phase >= 2 && *phasePtr <= 7)
        {
            void* types = seqFn_800394a0();
            switch (s->phase)
            {
            case 3:
                objFn_8003acfc((int*)obj, types, s->pointCount, (char*)s->animChannels);
                s->setupFlag = 0;
                s->phase = 2;
            case 2:
                if (objAnimFn_80115650(obj, player, &s->turnState, st, st, pair, &s->targetX) == 0)
                {
                    s->phase = 6;
                }
                break;
            case 6:
                s->phase = 7;
            case 7:
                s->animPhase = lbl_803E1CC4;
                break;
            }
            *(int*)&s->lastTarget = player;
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, s->animPhase, framesThisStep,
                                                                        NULL);
            if (s->phase == 7)
            {
                s16* v;
                seq->flags = seq->flags | 8;
                v = objModelGetVecFn_800395d8(obj, 0);
                if (v != NULL)
                {
                    seq->unk114 = v[1];
                    seq->unk116 = v[0];
                }
                s->phase = 0;
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

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */
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
        ((GameObject*)obj)->anim.rotX = (f32)*(s16*)(int)(GameObject*)obj +
            (lbl_803E1CB8 + delta) * (speed * timeDelta) / dist;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (move != -1)
    {
        if (((GameObject*)obj)->anim.currentMove != move)
        {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E1C90, 0);
        }
        delta = ((GameObject*)obj)->anim.rotX - (u16)(s16)
        getAngle(dx, dz);
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

static u32 projGetLockTarget(int state, u16* obj, ProjNearSearch* sv)
{
    u32 t = *(u32*)&((MoveLibState*)state)->lockTarget;
    if (t != 0) return t;
    return ObjGroup_FindNearestObject(8, obj, sv);
}

void dll_2E_func03(u16* obj, int state, int unused)
{
    extern int fn_8003A8B4(); /* #57 */
    extern int objMathFn_8003a380(u16* obj, u32 target, float* pos, int pathState, short* turnState, float targetYaw, int mode, short yawLimit); /* #57 */
    extern int fn_80038F1C(int a, int b); /* #57 */
    extern void* seqFn_800394a0(); /* #57 */
    extern int objFn_8003acfc(); /* #57 */
    extern int fn_8003AC14(); /* #57 */
    extern int fn_8003A9C0(); /* #57 */
    register u32 target;
    register int seqHandle;
    register int yawDelta;
    int bit1;
    int ival;
    u32 hitReact;
    float dist;
    float blendA;
    float blendB;
    float blendMax;
    float targetYaw;
    ProjNearSearch sv;
    MoveLibState* s = (MoveLibState*)state;

    (void)unused;
    sv.range = lbl_803E1C8C;
    targetYaw = lbl_803E1CD0;
    yawDelta = 0;
    seqHandle = (int)seqFn_800394a0();
    (void)Obj_GetPlayerObject();
    if (s->needsReinit == 0)
    {
        bit1 = s->modeBits & 1;
        if (bit1 != 0 && s->phase != 8)
        {
            s->phase = 8;
            if ((s->modeBits & 8) == 0)
            {
                objFn_8003acfc((int)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                s->setupFlag = 0x50;
                fn_8003A9C0((char*)s->animChannels, (u32)s->pointCount, 0, 0);
            }
            else
            {
                fn_8003AC14((int)obj, seqFn_800394a0(), (u32)s->pointCount);
            }
        }
        else if (bit1 == 0 && s->phase == 8)
        {
            s->phase = 0;
            if ((s->modeBits & 8) == 0)
            {
                objFn_8003acfc((int)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                s->setupFlag = 0x50;
            }
        }
        if (s->phase > 1)
        {
            if (s->setupFlag != 0 && (s->modeBits & 8) == 0)
            {
                s->setupFlag =
                    !fn_8003A8B4(obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
            }
            else
            {
                fn_8003AC14((int)obj, seqFn_800394a0(), (u32)s->pointCount);
            }
        }
        else
        {
            if ((target = projGetLockTarget(state, obj, &sv)) != 0)
            {
                if ((s->modeBits & 0x20) != 0)
                {
                    sv.dx = s->targetX - ((GameObject*)target)->anim.localPosX;
                    sv.dy = s->targetY - ((GameObject*)target)->anim.localPosY;
                    sv.dz = s->targetZ - ((GameObject*)target)->anim.localPosZ;
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
                        objFn_8003acfc((int)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                        s->setupFlag = 0x50;
                        fn_8003A9C0((char*)s->animChannels, (u32)s->pointCount, 0, 0);
                        s->phase = 0;
                        return;
                    }
                    if (s->setupFlag != 0)
                    {
                        s->setupFlag =
                            !fn_8003A8B4(obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                    }
                    if (s->reattackTimer < -s->reattackDelayMin)
                    {
                        s->reattackTimer =
                            randomGetRange(s->reattackDelayMin, s->reattackDelayBase);
                    }
                    if (s->reattackTimer < 0) return;
                }
                else
                {
                    s->reattackTimer = s->reattackDelayBase;
                }
                if ((target != *(u32*)&s->lastTarget) && (target != 0))
                {
                    hitReact = (u32)((GameObject*)target)->anim.hitReactState;
                    if (hitReact != 0)
                    {
                        PostMotionTarget* motion = (PostMotionTarget*)hitReact;
                        if ((motion->flags & 2) != 0)
                        {
                            targetYaw = lbl_803E1CDC * (float)(int)motion->yawB;
                        }
                        else if ((motion->flags & 1) != 0)
                        {
                            targetYaw = (float)(int)motion->yawA;
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
                    (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)target)->anim.worldPosX) > s->lookAtMaxDistance))
                {
                    if ((s->phase != 0) ||
                        ((target == 0 && (*(u32*)&s->lastTarget != 0))))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                        s->setupFlag = 10;
                        fn_8003A9C0((char*)s->animChannels, (u32)s->pointCount, 0, 0);
                        s->phase = 0;
                    }
                }
                else
                {
                    if ((target != *(u32*)&s->lastTarget) || (s->phase == 0))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                        s->setupFlag = 1;
                    }
                    if ((s->modeBits & 8) != 0)
                    {
                        s->setupFlag = 0;
                    }
                    objMathFn_8003a380(obj, target, &s->targetX,
                                       (s->setupFlag != 0) ? (int)s->animChannels : 0,
                                       s->turnTable, targetYaw, 8,
                                       s->yawLimitA);
                    s->phase = 1;
                }
                *(u32*)&s->lastTarget = target;
                if (s->setupFlag == 0)
                {
                    *(u32*)&s->lockTarget = 0;
                }
                if (((s->modeBits & 8) == 0) && (s->setupFlag != 0))
                {
                    s->setupFlag =
                        !fn_8003A8B4(obj, seqHandle, (u32)s->pointCount, (char*)s->animChannels);
                }
            }
        }
    }
}

int objAnimFn_80115650(PostObjAnimComponent* objAnim, PostObject* obj, int* turning,
                       PostControl* control, float* turnSpeed, s16* moves)
{
    extern int fn_8003A8B4(PostObjAnimComponent* objAnim, PostMotionTarget* leadAnims, u8 contactAnim, void* secondary); /* #57 */
    extern s16 objMathFn_8003a380(PostObjAnimComponent* objAnim, PostObject* obj, void* primary, void* secondary, s16* events, double distance, int eventCount, int eventState); /* #57 */
    extern void fn_80038F1C(int a, int b); /* #57 */
    extern PostMotionTarget* seqFn_800394a0(void); /* #57 */
    int yawDelta;
    PostMotionTarget* motion;
    s16 hitResult;
    int turnAmount;
    u32 ret;
    double distance;
    void* secondary;
    s16 turnDelta;

    motion = seqFn_800394a0();
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

    hitResult = objMathFn_8003a380(objAnim, obj, control->primary,
                                   ((control->flags & 8) != 0) ? 0 : control->secondary,
                                   control->events, distance, 8, control->eventState);
    if ((control->flags & 8) == 0)
    {
        control->blocked = (u32)__cntlzw(fn_8003A8B4(objAnim, motion, control->contactAnim,
                                                      control->secondary)) >> 5;
    }
    control->blocked = 0;

    if (((control->flags & 2) != 0) && (hitResult != 0))
    {
        *turning = 0;
        return 0;
    }

    if (control->blocked == 0)
    {
        if (((s16)yawDelta > -control->yawLimit) &&
            ((s16)yawDelta < control->yawLimit))
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

u8 gMoveLibDefaultMoveData[20] = { 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23 };
