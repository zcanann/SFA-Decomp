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
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/FRONT/POST.h"
#include "string.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
extern int ObjGroup_FindNearestObjectToPoint();
extern int objAnimFn_80115650();
extern f32 Curve_EvalHermite(f32* points, f32 t, int unused);
extern f32 sqrtf(f32 x);
extern u8 lbl_8031A0E0[];
extern f32 lbl_803E1C88;
extern f32 lbl_803E1C8C;
extern f32 timeDelta;
extern f32 lbl_803E1C90;
extern void vecRotateZXY(s16 * angles, f32 * vec);
extern f32 lbl_803E1CC8;
extern f32 lbl_803E1CCC;
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
extern f32 lbl_803E1CBC;
extern f32 lbl_803E1CC0;
extern f32 Vec_distance(f32* a, f32* b);
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();
extern f32 lbl_803E1CA4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CD4;
extern f32 lbl_803E1CD8;
extern f32 lbl_803E1CDC;
extern f32 lbl_803E1CE0;

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
        if (*(f32*)p4 >= *(f32*)&lbl_803E1CA4) /* #81 launder: flips the reload FP reg pair */
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

void FUN_801149b8(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  u32 param_9, u32 param_10, float* param_11, short param_12,
                  u16 param_13, u32 param_14, u32 param_15, u32 param_16)
{
}

int dll_2E_func0F_ret_0(void) { return 0x0; }

void fn_80113F94(int* p, f32 v) { *(f32*)((char*)p + 0x614) = v; }
void dll_2E_func04(int* p, int v) { *(int*)((char*)p + 0x608) = v; }

#pragma scheduling off
#pragma peephole off
void dll_2E_func08(int obj, int v1, int v2)
{
    *(int*)(obj + 0x618) = v1;
    *(int*)(obj + 0x61c) = v2;
    *(int*)(obj + 0x620) = v1;
}

void dll_2E_func09(int obj, void* src1, void* src2)
{
    if (src1 == NULL) src1 = lbl_8031A0E0;
    if (src2 == NULL) src2 = lbl_8031A0E0;
    memcpy((char*)obj + 0x5bc, src1, (u32) * (u8*)(obj + 0x610) * 2);
    memcpy((char*)obj + 0x5da, src2, (u32) * (u8*)(obj + 0x610) * 2);
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
    char* state;
    int* types;

    types = seqFn_800394a0();
    state = ((GameObject*)obj)->extra;

    (*gCameraInterface)->setTarget(0);

    *(u8*)(state + 0x600) = 0;
    objFn_8003acfc(obj, types, *(u8*)(state + 0x610), state + 0x1c);
    *(int*)(state + 0x5f8) = 0x50;
    fn_8003A9C0(state + 0x1c, *(u8*)(state + 0x610), 0, 0);
}

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */
int dll_2E_func0A(int idx, char* out)
{
    int r;

    if (idx >= 0x1c)
    {
        return 0;
    }
    r = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (r > -1)
    {
        char* p = (char*)(*gRomCurveInterface)->getById(r);
        *(f32*)(out + 0xc) = *(f32*)(p + 0x8);
        *(f32*)(out + 0x10) = *(f32*)(p + 0xc);
        *(f32*)(out + 0x14) = *(f32*)(p + 0x10);
        *(s16*)(out + 0x0) = (s16)(*(s8*)(p + 0x2c) << 8);
        return 1;
    }
    return 0;
}

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */
int dll_2E_func0C(int idx, char* out)
{
    f32 range;
    int r;

    range = lbl_803E1C8C;
    r = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (r > -1)
    {
        char* p = (char*)(*gRomCurveInterface)->getById(r);
        char* q;
        *(f32*)(out + 0xc) = *(f32*)(p + 0x8);
        *(f32*)(out + 0x10) = *(f32*)(p + 0xc);
        *(f32*)(out + 0x14) = *(f32*)(p + 0x10);
        q = (char*)ObjGroup_FindNearestObjectToPoint(8, out + 0xc, &range);
        if (q != NULL)
        {
            *(s16*)(out + 0x0) = (s16)atan2i((int)(((GameObject*)q)->anim.localPosX - *(f32*)(out + 0xc)),
                                             (int)(((GameObject*)q)->anim.localPosZ - *(f32*)(out + 0x14)));
        }
        else
        {
            *(s16*)(out + 0x0) = (s16)(*(s8*)(p + 0x2c) << 8);
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
    f32 z;

    *(s16*)(st + 0x60c) = a;
    *(s16*)(st + 0x60e) = b;
    *(u8*)(st + 0x610) = count;
    *(int*)(st + 0x5fc) = 0;
    z = lbl_803E1C90;
    *(f32*)(st + 0x0) = z;
    *(int*)(st + 0x5f8) = 0;
    *(int*)(st + 0x604) = 0;
    *(int*)(st + 0x608) = 0;
    *(f32*)(st + 0x614) = lbl_803E1C8C;
    *(u8*)(st + 0x600) = 0;
    *(u8*)(st + 0x601) = 1;
    *(f32*)(st + 0x4) = z;
    *(f32*)(st + 0x8) = z;
    *(f32*)(st + 0xc) = z;
    *(int*)(st + 0x618) = -1;
    fn_8003AC14(obj, seqFn_800394a0(), count);
    objFn_8003acfc((int*)obj, seqFn_800394a0(), count, st + 0x1c);
    fn_8003A9C0(st + 0x1c, *(u8*)(st + 0x610), 0, 0);
    dll_2E_func09((int)st, lbl_8031A0E0, lbl_8031A0E0);
}

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */
void dll_2E_func06(int obj, char* st, int point)
{
    extern void* seqFn_800394a0(void); /* #57 */
    extern void fn_8003AC14(int obj, void* types, int count); /* #57 */
    struct
    {
        s16 ang[3];
        f32 x0, y0, z0, x1, y1, z1;
    } v;

    if (*(u8*)(st + 0x601) != 0)
    {
        f32 cA;
        f32 cB;
        fn_8003AC14(obj, seqFn_800394a0(), *(u8*)(st + 0x610));
        ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
        ObjPath_GetPointWorldPosition(obj, point + 1, &v.x1, &v.y1, &v.z1, 0);
        cA = lbl_803E1CC8;
        *(f32*)(st + 0x4) = (cA * v.x0 + v.x1) * (cB = lbl_803E1CCC);
        *(f32*)(st + 0x8) = v.y0;
        *(f32*)(st + 0xc) = (cA * v.z0 + v.z1) * cB;
        *(f32*)(st + 0x4) -= ((GameObject*)obj)->anim.localPosX;
        *(f32*)(st + 0x8) -= ((GameObject*)obj)->anim.localPosY;
        *(f32*)(st + 0xc) -= ((GameObject*)obj)->anim.localPosZ;
        v.ang[0] = (s16) - ((GameObject*)obj)->anim.rotZ;
        v.ang[1] = (s16) - ((GameObject*)obj)->anim.rotY;
        v.ang[2] = (s16) - ((GameObject*)obj)->anim.rotX;
        vecRotateZXY(v.ang, (f32*)(st + 0x4));
        *(u8*)(st + 0x601) = 0;
    }
    ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
    *(f32*)(st + 0x10) = v.x0;
    *(f32*)(st + 0x14) = v.y0;
    *(f32*)(st + 0x18) = v.z0;
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
    s16 pair[2];
    int mode;
    int player;

    player = Obj_GetPlayerObject();
    pair[0] = a;
    pair[1] = b;
    {
        char* p = *(char**)&((GameObject*)obj)->anim.hitReactState;
        *(s16*)(p + 0x60) = *(s16*)(p + 0x60) | 1;
    }
    mode = (s8)seq->movementState;
    if (mode == 4)
    {
        *(int*)(st + 0x5f8) = 0x50;
        seq->flags = seq->flags & ~8;
        seq->flags = seq->flags & ~2;
        *(u8*)(st + 0x600) = 3;
        seq->movementState = 5;
        if ((*(u8*)(st + 0x611) & 2) == 0)
        {
            seq->flags = seq->flags & ~4;
        }
        seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_80114B1C;
        return 0;
    }
    else if (mode == 5)
    {
        if (*(u8*)(st + 0x600) >= 2 && *(u8*)(st + 0x600) <= 7)
        {
            void* types = seqFn_800394a0();
            switch (*(u8*)(st + 0x600))
            {
            case 3:
                objFn_8003acfc((int*)obj, types, *(u8*)(st + 0x610), st + 0x1c);
                *(int*)(st + 0x5f8) = 0;
                *(u8*)(st + 0x600) = 2;
            case 2:
                if (objAnimFn_80115650(obj, player, st + 0x5fc, st, st, pair, st + 0x10) == 0)
                {
                    *(u8*)(st + 0x600) = 6;
                }
                break;
            case 6:
                *(u8*)(st + 0x600) = 7;
            case 7:
                *(f32*)(st + 0x0) = lbl_803E1CC4;
                break;
            }
            *(int*)(st + 0x604) = player;
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, *(f32*)(st + 0x0), framesThisStep,
                                                                        NULL);
            if (*(u8*)(st + 0x600) == 7)
            {
                s16* v;
                seq->flags = seq->flags | 8;
                v = objModelGetVecFn_800395d8(obj, 0);
                if (v != NULL)
                {
                    seq->unk114 = v[1];
                    seq->unk116 = v[0];
                }
                *(u8*)(st + 0x600) = 0;
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
        ((GameObject*)obj)->anim.rotX = (f32)((GameObject*)obj)->anim.rotX +
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
        speed = speed * -mathCosf(lbl_803E1CBC * delta / lbl_803E1CC0);
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
    u32 t = *(u32*)(state + 0x608);
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
    extern int Obj_GetPlayerObject(void); /* #57 */
    register int yawDelta;
    register int seqHandle;
    register u32 target;
    int bit1;
    int ival;
    u32 hitReact;
    float dist;
    float blendA;
    float blendB;
    float blendMax;
    float targetYaw;
    ProjNearSearch sv;

    (void)unused;
    sv.range = lbl_803E1C8C;
    targetYaw = lbl_803E1CD0;
    yawDelta = 0;
    seqHandle = (int)seqFn_800394a0();
    (void)Obj_GetPlayerObject();
    if (*(u8*)(state + 0x601) == 0)
    {
        bit1 = *(u8*)(state + 0x611) & 1;
        if (bit1 != 0 && *(u8*)(state + 0x600) != 8)
        {
            *(u8*)(state + 0x600) = 8;
            if ((*(u8*)(state + 0x611) & 8) == 0)
            {
                objFn_8003acfc((int)obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
                *(u32*)(state + 0x5f8) = 0x50;
                fn_8003A9C0(state + 0x1c, (u32) * (u8*)(state + 0x610), 0, 0);
            }
            else
            {
                fn_8003AC14((int)obj, seqFn_800394a0(), (u32) * (u8*)(state + 0x610));
            }
        }
        else if (bit1 == 0 && *(u8*)(state + 0x600) == 8)
        {
            *(u8*)(state + 0x600) = 0;
            if ((*(u8*)(state + 0x611) & 8) == 0)
            {
                objFn_8003acfc((int)obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
                *(u32*)(state + 0x5f8) = 0x50;
            }
        }
        if (*(u8*)(state + 0x600) > 1)
        {
            if (*(int*)(state + 0x5f8) != 0 && (*(u8*)(state + 0x611) & 8) == 0)
            {
                *(u32*)(state + 0x5f8) =
                    !fn_8003A8B4(obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
            }
            else
            {
                fn_8003AC14((int)obj, seqFn_800394a0(), (u32) * (u8*)(state + 0x610));
            }
        }
        else
        {
            if ((target = projGetLockTarget(state, obj, &sv)) != 0)
            {
                if ((*(u8*)(state + 0x611) & 0x20) != 0)
                {
                    sv.dx = *(float*)(state + 0x10) - ((GameObject*)target)->anim.localPosX;
                    sv.dy = *(float*)(state + 0x14) - ((GameObject*)target)->anim.localPosY;
                    sv.dz = *(float*)(state + 0x18) - ((GameObject*)target)->anim.localPosZ;
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
                        blendA = *(f32*)&lbl_803E1CA4 - blendB;
                        *(float*)(state + 0x10) =
                            *(float*)(state + 0x10) * blendA + ((GameObject*)obj)->anim.localPosX * blendB;
                        *(float*)(state + 0x18) =
                            *(float*)(state + 0x18) * blendA + ((GameObject*)obj)->anim.localPosZ * blendB;
                    }
                }
                if ((*(int*)(state + 0x618) != -1) && (target == *(u32*)(state + 0x604)))
                {
                    ival = -framesThisStep + *(int*)(state + 0x620);
                    *(int*)(state + 0x620) = ival;
                    if ((ival <= 0) && (0 < (int)(*(int*)(state + 0x620) + framesThisStep)))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
                        *(u32*)(state + 0x5f8) = 0x50;
                        fn_8003A9C0(state + 0x1c, (u32) * (u8*)(state + 0x610), 0, 0);
                        *(u8*)(state + 0x600) = 0;
                        return;
                    }
                    if (*(int*)(state + 0x5f8) != 0)
                    {
                        *(u32*)(state + 0x5f8) =
                            !fn_8003A8B4(obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
                    }
                    if (*(int*)(state + 0x620) < -*(int*)(state + 0x61c))
                    {
                        *(u32*)(state + 0x620) =
                            randomGetRange(*(int*)(state + 0x61c), *(int*)(state + 0x618));
                    }
                    if (*(int*)(state + 0x620) < 0) return;
                }
                else
                {
                    *(int*)(state + 0x620) = *(int*)(state + 0x618);
                }
                if ((target != *(u32*)(state + 0x604)) && (target != 0))
                {
                    hitReact = (u32)((GameObject*)target)->anim.hitReactState;
                    if (hitReact != 0)
                    {
                        if ((*(u8*)(hitReact + 0x62) & 2) != 0)
                        {
                            targetYaw = lbl_803E1CDC * (float)(int)*(short*)(hitReact + 0x5e);
                        }
                        else if ((*(u8*)(hitReact + 0x62) & 1) != 0)
                        {
                            targetYaw = (float)(int)*(short*)(hitReact + 0x5a);
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
                if ((*(u8*)(state + 0x611) & 0x10) != 0)
                {
                    fn_80038F1C(0, 1);
                    yawDelta = yawDelta + -0x8000;
                }
                ival = (short)yawDelta;
                ival = (ival >= 0) ? ival : -ival;
                if (((0x5555 < ival) || (target == 0)) ||
                    (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)target)->anim.worldPosX) > *(float*)(state + 0x614)))
                {
                    if ((*(u8*)(state + 0x600) != 0) ||
                        ((target == 0 && (*(u32*)(state + 0x604) != 0))))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
                        *(u32*)(state + 0x5f8) = 10;
                        fn_8003A9C0(state + 0x1c, (u32) * (u8*)(state + 0x610), 0, 0);
                        *(u8*)(state + 0x600) = 0;
                    }
                }
                else
                {
                    if ((target != *(u32*)(state + 0x604)) || (*(u8*)(state + 0x600) == 0))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
                        *(u32*)(state + 0x5f8) = 1;
                    }
                    if ((*(u8*)(state + 0x611) & 8) != 0)
                    {
                        *(u32*)(state + 0x5f8) = 0;
                    }
                    objMathFn_8003a380(obj, target, (float*)(state + 0x10),
                                       (*(int*)(state + 0x5f8) != 0) ? state + 0x1c : 0,
                                       (short*)(state + 0x5bc), targetYaw, 8,
                                       *(short*)(state + 0x60c));
                    *(u8*)(state + 0x600) = 1;
                }
                *(u32*)(state + 0x604) = target;
                if (*(int*)(state + 0x5f8) == 0)
                {
                    *(u32*)(state + 0x608) = 0;
                }
                if (((*(u8*)(state + 0x611) & 8) == 0) && (*(int*)(state + 0x5f8) != 0))
                {
                    *(u32*)(state + 0x5f8) =
                        !fn_8003A8B4(obj, seqHandle, (u32) * (u8*)(state + 0x610), state + 0x1c);
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
        return 1;
    }

    if (*turning != 0)
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
            yawDelta = (s16)turnAmount;
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
            yawDelta = (s16)turnAmount;
        }

        objAnim->yaw += yawDelta;
        ret = (u32)(s16)yawDelta;
        if ((int)ret < 0)
        {
            ret = -ret;
        }
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
