/*
 * trickyfollow - Tricky sidekick follow/path-walk movement (Tricky DLL 0x0C4;
 * the Hagabon DLL 0xDF is unrelated). trickyFn_8013b368 is
 * the per-frame movement step that resolves the target's walk/patch group and
 * drives motion through a substate machine and RomCurveWalker route;
 * trickyUpdateApproachSpeed ramps the follow speed toward a target point. The
 * lbl_803E2xxx externs are this DLL's .sdata2 float constants.
 */
#include "main/dll/baddie/trickyfollow.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/modgfx.h"
#include "main/sfa_shared_decls.h"
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23E8;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;
extern f32 lbl_803E241C;
extern f32 lbl_803E2420;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2448;
extern f32 lbl_803E2468;
extern f32 lbl_803E246C;
extern f32 lbl_803E2484;
extern f32 lbl_803E2488;
extern f32 gTrickyFollowMaxSpeed;
extern f32 gTrickyFollowAnim17Speed;
extern f32 gTrickyFollowAnim18Speed;
extern f32 gTrickyFollowVerticalDeltaDivisorA;
extern f32 lbl_803E249C;
extern f32 gTrickyFollowVerticalDeltaDivisorB;
extern f32 lbl_803E24A4;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24AC;
extern f32 gTrickyFollowArcCoefficient;
extern f32 lbl_803E24B4;
extern f32 lbl_803E24B8;
extern f32 lbl_803E24BC;
extern f32 lbl_803E24C0;
extern char lbl_8031D2E8[];
extern f32 getXZDistance(f32* a, f32* b);
extern void vecRotateZXY(void* params, void* outVec);
extern f32 sqrtf(f32 x);

extern int isInWalkGroupOrPatch(f32 * pos);
extern void ObjHits_SyncObjectPosition(u8 * obj);
extern u32 Objfsa_GetWalkGroupIndexAtPoint(f32* pos, void* info);
extern s16 walkGroupFn_800db3e4(f32* pos, f32* target, int walkGroup);
extern u16 Objfsa_GetPatchGroupIdAtPoint(void* pos);
extern void fn_800DB240(void* pos, void* out, u32 patch);
extern int isPointWithinPatchGroup(f32* pos, int walkGroup, u32 patch);
extern int trickyMove(u8* obj, void* moveState);
extern void trickyRankLinkedRouteCandidates(u8* obj, u8* flags, int walkGroup, int* routes);
extern int trickyFindReachableRouteIndex(u8* state, int* routes, u8* flags, u16 group);
extern u8* trickySelectRouteEntry(u8* state, void* route, u8 dir);
extern void fn_800DA980(RomCurveWalker* route, void* fromNode, void* toNode);
extern void RomCurve_stepClamped(RomCurveWalker* state, f32 dt);
extern int getAngle(f32 x, f32 z);
extern void trickyAdvanceRouteTargetAhead(u8* obj, RomCurveWalker* route, f32 speed);
extern void objAnimFn_8013a3f0(u8* obj, int animId, f32 speed, int flags);
extern void curveFn_800da23c(RomCurveWalker* route);
extern void fn_800D9F38(RomCurveWalker* route);
extern void fn_800D9EE8(RomCurveWalker* route);
extern void fn_8004B31C(void* search, u32 route, void* target, int pathId, u32 dir);
extern void trickyTurnTowardYaw(u8* obj, int yaw);
extern void objHitDetectFn_80062e84(u8* obj, u8* newParent, int mode);
extern void trickyUpdateApproachSpeed(u8* obj, f32 baseRadius, u8* state, f32* targetPos, u8 flag);

#pragma opt_common_subs off
#pragma opt_loop_invariants off
int trickyFn_8013b368(u8* obj, f32 vel, u8* state)
{
    int tp;
    u8* target;
    char* strs = lbl_8031D2E8;
    u8 moved;
    int wg;
    int targetWg;
    u8 slot;
    u16 pp;
    int trickyPatch;
    u32 prod;
    int dir;
    int i;
    u8* node;
    u8* prevNode;
    int d;
    s16 link;
    u16 ulink;
    s16 yawA;
    s16 yawB;
    s16 diff;
    char type;
    u8 step;
    u8 mask;
    char found;
    f32 velBefore;
    f32 dist;
    f32 len;
    f32 v;
    f32 k;
    f32 sqx;
    f32 sqz;
    u8 pair[2];
    u8 routeFlags[8];
    struct
    {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } rot;
    f32 delta[3];
    struct
    {
        u8 pad; /* offset 0: mask is at +1, patch[] at +2 */
        u8 mask;
        u16 patch[5];
    } wgi;
    int routePtrs[9];
#define route (&((TrickyState*)state)->route)

    moved = 1;
    if ((((TrickyState*)state)->unk09 < 5) && (isInWalkGroupOrPatch((f32*)(obj + 0x18)) == 0))
    {
        (*gPathControlInterface)->attachObject(obj, &((TrickyState*)state)->pathControlFlags);
        ((GameObject*)obj)->anim.localPosX = ((TrickyState*)state)->homePosX;
        ((GameObject*)obj)->anim.localPosY = ((TrickyState*)state)->homePosY;
        ((GameObject*)obj)->anim.localPosZ = ((TrickyState*)state)->homePosZ;
        ((GameObject*)obj)->anim.worldPosX = ((TrickyState*)state)->homePosX;
        ((GameObject*)obj)->anim.worldPosY = ((TrickyState*)state)->homePosY;
        ((GameObject*)obj)->anim.worldPosZ = ((TrickyState*)state)->homePosZ;
        ObjHits_SyncObjectPosition(obj);
    }
    target = *(u8**)&((TrickyState*)state)->unk28;
    wg = Objfsa_GetWalkGroupIndexAtPoint((f32*)(obj + 0x18), 0);
    if ((wg != 0) && (((TrickyState*)state)->unkD0 != wg))
    {
        ((TrickyState*)state)->unkD0 = wg;
        *(s32*)&((TrickyState*)state)->stateFlags &= ~(u64)0x400;
        ((TrickyState*)state)->patch[0] = 0;
        ((TrickyState*)state)->patch[1] = 0;
        ((TrickyState*)state)->patch[2] = 0;
        ((TrickyState*)state)->patch[3] = 0;
    }
    targetWg = Objfsa_GetWalkGroupIndexAtPoint((f32*)target, &wgi);
    if (((wg != 0) && (targetWg == 0)) &&
        ((ulink = getPatchGroup((f32*)target, wg)) != 0))
    {
        walkPath_writeU16LE(ulink, pair);
        if (pair[0] == wg)
        {
            targetWg = pair[1];
        }
        else
        {
            targetWg = pair[0];
        }
    }
    if ((targetWg != 0) && (targetWg != ((TrickyState*)state)->unk532))
    {
        ((TrickyState*)state)->unk532 = targetWg;
    }
    ((TrickyState*)state)->unk534 = ((TrickyState*)state)->unk532;
    trickyDebugPrint(strs + 0x1e8, ((TrickyState*)state)->unkD0, wg, targetWg, ((TrickyState*)state)->unk532);
    if (((TrickyState*)state)->unkD0 == 0)
    {
        trickyReportError(strs + 0x214, ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                          ((GameObject*)obj)->anim.worldPosZ);
    }
    velBefore = ((TrickyState*)state)->speed;
    trickyUpdateApproachSpeed(obj, vel, state, (f32*)target, 0);
    trickyDebugPrint(strs + 0x268, velBefore, ((TrickyState*)state)->speed);
    if (targetWg == ((TrickyState*)state)->unkD0)
    {
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x400;
        i = 0;
        mask = 1;
        for (; i < 4; i++)
        {
            if (wgi.mask & mask)
            {
                *(s16*)(state + 0x98 + i * 2) = wgi.patch[i];
                *(f32*)(state + 0xa0 + i * 0xc) = *(f32*)target;
                *(f32*)(state + 0xa4 + i * 0xc) = *(f32*)(target + 4);
                *(f32*)(state + 0xa8 + i * 0xc) = *(f32*)(target + 8);
            }
            mask = mask << 1;
        }
    }
    if ((targetWg != 0) && (targetWg == ((TrickyState*)state)->unkD0))
    {
        *(s16*)&((TrickyState*)state)->unkD2 = 0;
    }
    else
    {
        prod = targetWg * ((TrickyState*)state)->unkD0 & 0xffff;
        if (prod != 0)
        {
            link = prod;
            for (i = 0; i < 4; i++)
            {
                if ((prod == wgi.patch[i]) && (((1 << i) & wgi.mask) != 0))
                {
                    *(s16*)&((TrickyState*)state)->unkD2 = link;
                    *(f32*)(state + 0xd4) = *(f32*)target;
                    *(f32*)(state + 0xd8) = *(f32*)(target + 4);
                    *(f32*)(state + 0xdc) = *(f32*)(target + 8);
                }
            }
        }
    }
    if (isInWalkGroupOrPatch((f32*)target) != 0)
    {
        trickyDebugPrint(strs + 0x284);
    }
    else
    {
        trickyDebugPrint(strs + 0x2b0);
    }
    link = getPatchGroup((f32*)target, ((TrickyState*)state)->unkD0);
    trickyDebugPrint(strs + 0x2e4, link);
    if ((((TrickyState*)state)->stateFlags & 0x400) != 0)
    {
        for (i = 0; i < 4; i++)
        {
            if (*(s16*)(state + 0x98 + i * 2) != 0)
            {
                trickyDebugPrint(strs + 0x308, i, *(f32*)(state + 0xa0 + i * 0xc),
                                 *(f32*)(state + 0xa4 + i * 0xc), *(f32*)(state + 0xa8 + i * 0xc));
            }
        }
    }
    if (*(s16*)&((TrickyState*)state)->unkD2 != 0)
    {
        trickyDebugPrint(strs + 0x328, *(f32*)(state + 0xd4), *(f32*)(state + 0xd8),
                         *(f32*)(state + 0xdc));
    }
    tp = getPatchGroup((f32*)target, ((TrickyState*)state)->unkD0) & 0xffff;
    trickyPatch = getPatchGroup((f32*)(obj + 0x18), ((TrickyState*)state)->unkD0) & 0xffff;
    if ((targetWg != 0) && (wg == targetWg))
    {
        ((TrickyState*)state)->unk09 = 1;
    }
    else
    {
        ulink = walkGroupFn_800db3e4((f32*)(obj + 0x18), (f32*)target, ((TrickyState*)state)->unkD0);
        if (ulink != 0)
        {
            ((TrickyState*)state)->unk09 = 1;
            if (ulink != ((TrickyState*)state)->unkD0)
            {
                *(u16*)&((TrickyState*)state)->unkD0 = ulink;
                *(s32*)&((TrickyState*)state)->stateFlags &= ~(u64)0x400;
                ((TrickyState*)state)->patch[0] = 0;
                ((TrickyState*)state)->patch[1] = 0;
                ((TrickyState*)state)->patch[2] = 0;
                ((TrickyState*)state)->patch[3] = 0;
            }
        }
        else if (((TrickyState*)state)->unk09 < 5)
        {
            if ((u32)tp != 0)
            {
                if (targetWg == 0)
                {
                    if (wg != 0)
                    {
                        for (i = 0; i < 4; i++)
                        {
                            if (*(s16*)(state + 0x98 + i * 2) == tp)
                            {
                                slot = i;
                                ((TrickyState*)state)->unk09 = 2;
                                break;
                            }
                        }
                        if (i == 4)
                        {
                            if (tp & !(0xff - ((TrickyState*)state)->unk530))
                            {
                                ((TrickyState*)state)->unk532 = (int)(tp & 0xff00) >> 8;
                            }
                            else
                            {
                                ((TrickyState*)state)->unk532 = tp & 0xff;
                            }
                            ((TrickyState*)state)->unk09 = 5;
                        }
                    }
                    else
                    {
                        if ((u32)trickyPatch != 0)
                        {
                            for (i = 0; i < 4; i++)
                            {
                                if (*(s16*)(state + 0x98 + i * 2) == trickyPatch)
                                {
                                    trickyPatch = i;
                                    ((TrickyState*)state)->unk09 = 2;
                                    break;
                                }
                            }
                            if (i == 4)
                            {
                                fn_800DB240(target, state + 0xec, trickyPatch);
                                ((TrickyState*)state)->unk09 = 4;
                            }
                        }
                        else
                        {
                            trickyReportError(strs + 0x344);
                            ((TrickyState*)state)->unk09 = 0;
                        }
                    }
                }
                else
                {
                    if (wg != 0)
                    {
                        for (i = 0; i < 4; i++)
                        {
                            if (*(s16*)(state + 0x98 + i * 2) == tp)
                            {
                                slot = i;
                                ((TrickyState*)state)->unk09 = 2;
                                break;
                            }
                        }
                        if (i == 4)
                        {
                            ((TrickyState*)state)->unk09 = 5;
                        }
                    }
                    else
                    {
                        if (wg == 0)
                        {
                            tp = getPatchGroup((f32*)(obj + 0x18), ((TrickyState*)state)->unkD0) & 0xffff;
                            if ((u32)tp != 0)
                            {
                                if (*(s16*)&((TrickyState*)state)->unkD2 == tp)
                                {
                                    ((TrickyState*)state)->unk09 = 3;
                                }
                                else
                                {
                                    fn_800DB240(target, state + 0xec, tp);
                                    ((TrickyState*)state)->unk09 = 4;
                                }
                                goto state_selected;
                            }
                        }
                        pp = tp;
                        i = isPointWithinPatchGroup((f32*)(obj + 0x18), ((TrickyState*)state)->unkD0,
                                                    pp);
                        trickyReportError(strs + 0x374, pp, targetWg, wg, ((TrickyState*)state)->unkD0,
                                          i);
                        ((TrickyState*)state)->unk09 = 0;
                    }
                }
            }
            else
            {
                if (targetWg == 0)
                {
                    if (wg != 0)
                    {
                        u16 pid = Objfsa_GetPatchGroupIdAtPoint(target);
                        if (pid == 0)
                        {
                            ((TrickyState*)state)->unk09 = 0;
                        }
                        else
                        {
                            ((TrickyState*)state)->unk532 = pid & 0xff;
                            ((TrickyState*)state)->unk09 = 5;
                        }
                    }
                    else
                    {
                        ((TrickyState*)state)->unk09 = 0;
                    }
                }
                else
                {
                    if (wg != 0)
                    {
                        targetWg = targetWg * wg & 0xffff;
                        if (isPointWithinPatchGroup((f32*)(obj + 0x18), ((TrickyState*)state)->unkD0,
                                                    targetWg) != 0)
                        {
                            if (*(s16*)&((TrickyState*)state)->unkD2 == targetWg)
                            {
                                ((TrickyState*)state)->unk09 = 3;
                            }
                            else
                            {
                                ((TrickyState*)state)->unk09 = 5;
                            }
                        }
                        else
                        {
                            for (i = 0; i < 4; i++)
                            {
                                if (*(s16*)(state + 0x98 + i * 2) == targetWg)
                                {
                                    slot = i;
                                    ((TrickyState*)state)->unk09 = 2;
                                    break;
                                }
                            }
                            if ((i == 4) || (targetWg != *(s16*)&((TrickyState*)state)->unkD2))
                            {
                                ((TrickyState*)state)->unk09 = 5;
                            }
                        }
                    }
                    else
                    {
                        u16 p = getPatchGroup((f32*)(obj + 0x18), ((TrickyState*)state)->unkD0);
                        if (p != 0)
                        {
                            if (targetWg == ((TrickyState*)state)->unkD0)
                            {
                                for (i = 0; i < 4; i++)
                                {
                                    if (*(s16*)(state + 0x98 + i * 2) == p)
                                    {
                                        slot = i;
                                        ((TrickyState*)state)->unk09 = 2;
                                        break;
                                    }
                                }
                                if (i == 4)
                                {
                                    fn_800DB240(target, state + 0xec, p);
                                    ((TrickyState*)state)->unk09 = 4;
                                }
                            }
                            else if (*(s16*)&((TrickyState*)state)->unkD2 == p)
                            {
                                ((TrickyState*)state)->unk09 = 3;
                            }
                            else
                            {
                                fn_800DB240(target, state + 0xec, p);
                                ((TrickyState*)state)->unk09 = 4;
                            }
                        }
                        else
                        {
                            trickyReportError(strs + 0x3ec);
                            ((TrickyState*)state)->unk09 = 0;
                        }
                    }
                }
            }
        }
    }
state_selected:
    if (((TrickyState*)state)->unk09 < 5)
    {
        ((TrickyState*)state)->stateFlags &= ~0x2000LL;
    }
    trickyDebugPrint(strs + 0x404, ((TrickyState*)state)->unk09);
    switch (((TrickyState*)state)->unk09)
    {
    case 0:
        trickyDebugPrint(strs + 0x41c);
        v = lbl_803E241C * timeDelta + velBefore;
        ((TrickyState*)state)->speed = (v < lbl_803E23DC) ? lbl_803E23DC : v;
        if (lbl_803E23DC == ((TrickyState*)state)->speed)
        {
            moved = 0;
        }
        else
        {
            moved = trickyMove(obj, target);
        }
        break;
    case 1:
        trickyDebugPrint(strs + 0x428);
        moved = trickyMove(obj, target);
        break;
    case 2:
        trickyDebugPrint(strs + 0x434);
        ((TrickyState*)state)->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E23DC, state, (f32*)(state + slot * 0xc + 0xa0), 1);
        moved = trickyMove(obj, state + slot * 0xc + 0xa0);
        break;
    case 4:
        trickyDebugPrint(strs + 0x448);
        ((TrickyState*)state)->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, (f32*)(state + 0xec), 1);
        moved = trickyMove(obj, state + 0xec);
        break;
    case 3:
        trickyDebugPrint(strs + 0x45c);
        ((TrickyState*)state)->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, (f32*)(state + 0xd4), 1);
        moved = trickyMove(obj, state + 0xd4);
        break;
    case 6:
        dist = getXZDistance((f32*)((u8*)((TrickyState*)state)->routeSeedNode + 8), (f32*)(obj + 0x18));
        trickyDebugPrint(strs + 0x46c, 10, dist);
        dist = getXZDistance((f32*)((u8*)((TrickyState*)state)->routeSeedNode + 8), (f32*)(obj + 0x18));
        if (lbl_803E23E0 > dist)
        {
            route->reverse = ((TrickyState*)state)->routeSeedDir;
            prevNode = (u8*)((TrickyState*)state)->routeSeedNode;
            node = trickySelectRouteEntry(state, prevNode, ((TrickyState*)state)->routeSeedDir);
            if (node == 0)
            {
                ((TrickyState*)state)->unk09 = 0;
            }
            else
            {
                if (trickySelectRouteEntry(state, node, ((TrickyState*)state)->routeSeedDir) == 0)
                {
                    ((TrickyState*)state)->unk09 = 0;
                }
                else
                {
                    fn_800DA980(route, prevNode, node);
                    RomCurve_stepClamped(route, lbl_803E2484);
                    yawA = getAngle(((TrickyState*)state)->prevLocalPosX - ((GameObject*)obj)->anim.localPosX,
                                    ((TrickyState*)state)->prevLocalPosZ - ((GameObject*)obj)->anim.localPosZ);
                    yawB = getAngle(((TrickyState*)state)->prevLocalPosX - route->posX,
                                    ((TrickyState*)state)->prevLocalPosZ - route->posZ);
                    diff = yawA - (u16)yawB;
                    if (0x8000 < diff)
                    {
                        diff = diff - 0xffff;
                    }
                    if (diff < -0x8000)
                    {
                        diff = diff + 0xffff;
                    }
                    if (diff > 0x4000)
                    {
                        diff -= 0x8000;
                    }
                    else if (diff < -0x4000)
                    {
                        diff += 0x8000;
                    }
                    d = (diff >= 0) ? diff : -diff;
                    if (0x1000 < d)
                    {
                        ((TrickyState*)state)->speed = velBefore;
                        trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &route->posX, 1);
                    }
                    trickyAdvanceRouteTargetAhead(obj, route, ((TrickyState*)state)->speed);
                    moved = trickyMove(obj, &route->posX);
                    switch (*(s8*)(prevNode + 0x1a))
                    {
                    case 1:
                        node = route->nodeA0;
                        ((TrickyState*)state)->dirX =
                            *(f32*)((u8*)node + 8) - ((GameObject*)obj)->anim.worldPosX;
                        ((TrickyState*)state)->dirZ =
                            *(f32*)((u8*)node + 0x10) - ((GameObject*)obj)->anim.worldPosZ;
                        sqx = ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX;
                        sqz = ((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (lbl_803E23DC != len)
                        {
                            ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / len;
                            ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / len;
                        }
                        ((TrickyState*)state)->speed = gTrickyFollowMaxSpeed;
                        objAnimFn_8013a3f0(obj, 0x15, lbl_803E2468, 0x4000000);
                        ((TrickyState*)state)->unk09 = 9;
                        ((TrickyState*)state)->unk7A0f = lbl_803E2440;
                        break;
                    case 5:
                        node = route->nodeA0;
                        ((TrickyState*)state)->dirX =
                            *(f32*)((u8*)node + 8) - ((GameObject*)obj)->anim.worldPosX;
                        ((TrickyState*)state)->dirZ =
                            *(f32*)((u8*)node + 0x10) - ((GameObject*)obj)->anim.worldPosZ;
                        sqx = ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX;
                        sqz = ((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (lbl_803E23DC != len)
                        {
                            ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / len;
                            ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / len;
                        }
                        if ((int)randomGetRange(0, 1) != 0)
                        {
                            objAnimFn_8013a3f0(obj, 0x17, gTrickyFollowAnim17Speed, 0x40000c0);
                        }
                        else
                        {
                            objAnimFn_8013a3f0(obj, 0x18, gTrickyFollowAnim18Speed, 0x40000c0);
                        }
                        ((TrickyState*)state)->verticalDelta =
                            (*(f32*)((u8*)route->nodeA0 + 0xc) - ((GameObject*)obj)->anim.worldPosY) /
                            gTrickyFollowVerticalDeltaDivisorA;
                        ((TrickyState*)state)->unk09 = 0xc;
                        if (route->reverse != 0)
                        {
                            while (route->atSegmentEnd != 0)
                            {
                                RomCurve_stepClamped(route, lbl_803E2448);
                            }
                        }
                        else
                        {
                            while (route->atSegmentEnd == 0)
                            {
                                RomCurve_stepClamped(route, lbl_803E23F8);
                            }
                        }
                        ((TrickyState*)state)->unk7A0f = lbl_803E2440;
                        break;
                    case 6:
                        ((TrickyState*)state)->dirX =
                            *(f32*)((u8*)route->nodeA0 + 8) - ((GameObject*)obj)->anim.worldPosX;
                        ((TrickyState*)state)->dirZ =
                            *(f32*)((u8*)route->nodeA0 + 0x10) - ((GameObject*)obj)->anim.worldPosZ;
                        sqx = ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX;
                        sqz = ((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (lbl_803E23DC != len)
                        {
                            ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / len;
                            ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / len;
                        }
                        objAnimFn_8013a3f0(obj, 0x19, lbl_803E249C, 0x40000c0);
                        ((TrickyState*)state)->verticalDelta =
                            (((GameObject*)obj)->anim.worldPosY - *(f32*)((u8*)route->nodeA0 + 0xc)) /
                            gTrickyFollowVerticalDeltaDivisorB;
                        ((TrickyState*)state)->unk09 = 0xe;
                        if (route->reverse != 0)
                        {
                            while (route->atSegmentEnd != 0)
                            {
                                RomCurve_stepClamped(route, lbl_803E2448);
                            }
                        }
                        else
                        {
                            while (route->atSegmentEnd == 0)
                            {
                                RomCurve_stepClamped(route, lbl_803E23F8);
                            }
                        }
                        ((TrickyState*)state)->unk7A0f = lbl_803E2440;
                        break;
                    case 2:
                    case 7:
                        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x2000;
                    default:
                        ((TrickyState*)state)->unk09 = 7;
                    }
                }
            }
        }
        else
        {
            node = (u8*)((TrickyState*)state)->routeSeedNode;
            if (node == 0)
            {
                node = 0;
            }
            else if (((*(s16*)(node + 0x30) != -1) &&
                    (GameBit_Get(*(s16*)(node + 0x30)) == 0)) ||
                ((*(s16*)(node + 0x32) != -1 &&
                    (GameBit_Get(*(s16*)(node + 0x32)) != 0))))
            {
                node = 0;
            }
            if ((node == 0) && (wg != 0))
            {
                ((TrickyState*)state)->unk09 = 0;
            }
            else
            {
                ((TrickyState*)state)->speed = velBefore;
                trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32*)((u8*)((TrickyState*)state)->routeSeedNode + 8), 1);
                moved = trickyMove(obj, ((u8*)((TrickyState*)state)->routeSeedNode + 8));
            }
        }
        break;
    case 5:
        trickyDebugPrint(strs + 0x480);
        trickyRankLinkedRouteCandidates(obj, routeFlags, wg, routePtrs);
        i = trickyFindReachableRouteIndex(state, routePtrs, routeFlags, ((TrickyState*)state)->unk532);
        if (i == -1)
        {
            ((TrickyState*)state)->speed = velBefore;
            return 2;
        }
        ((TrickyState*)state)->routeSeedDir = routeFlags[i];
        ((TrickyState*)state)->routeSeedNode = (void*)routePtrs[i];
        ((TrickyState*)state)->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, (f32*)((u8*)((TrickyState*)state)->routeSeedNode + 8), 1);
        moved = trickyMove(obj, ((u8*)((TrickyState*)state)->routeSeedNode + 8));
        ((TrickyState*)state)->unk09 = 6;
        break;
    case 7:
        trickyDebugPrint(strs + 0x490);
        if ((((TrickyState*)state)->unk534 != 0) && (wg == ((TrickyState*)state)->unk534))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            ((TrickyState*)state)->speed = (v < lbl_803E23DC) ? lbl_803E23DC : v;
        }
        node = route->nodeA0;
        if ((*(s8*)((u8*)route->node9C + 0x1a) != 9) && (*(s8*)(node + 0x1a) != 9))
        {
            f32* tpos = *(f32**)&((TrickyState*)state)->unk28;
            delta[0] = tpos[0] - ((GameObject*)obj)->anim.worldPosX;
            delta[1] = tpos[1] - ((GameObject*)obj)->anim.worldPosY;
            delta[2] = tpos[2] - ((GameObject*)obj)->anim.worldPosZ;
            rot.angle = -((GameObject*)obj)->anim.rotX;
            rot._pad0 = 0;
            rot._pad1 = 0;
            vecRotateZXY(&rot, delta);
            if ((delta[2] > lbl_803E23DC) && (lbl_803E23DC != ((TrickyState*)state)->speed))
            {
                for (step = 0; step < 4; step++)
                {
                    if (*(u8*)(node + step + 4) == ((TrickyState*)state)->unk532)
                    {
                        break;
                    }
                }
                if (step == 4)
                {
                    fn_8004B31C(((TrickyState*)state)->voxBlocks[0], (u32)route->nodeA4, ((TrickyState*)state)->unk28,
                                ((TrickyState*)state)->unk532, route->reverse);
                    fn_8004B31C(((TrickyState*)state)->voxBlocks[1], (u32)route->node9C, ((TrickyState*)state)->unk28,
                                ((TrickyState*)state)->unk532, route->reverse ^ 1);
                    found = 0;
                    for (step = 0; (step = step + 1) < 100 && (found != 1);)
                    {
                        found = fn_8004B218(((TrickyState*)state)->voxBlocks[0], 1);
                        if (found != 1)
                        {
                            found = fn_8004B218(((TrickyState*)state)->voxBlocks[1], 1);
                            if (found != 0)
                            {
                                if (found < 0)
                                {
                                    if (found >= -1)
                                    {
                                        found = 1;
                                    }
                                }
                                else if (found < 2)
                                {
                                    u32 rdir = (route->reverse ^ 1) & 0xff;
                                    if (rdir == 0)
                                    {
                                        RomCurve_stepClamped(route, lbl_803E23F8);
                                    }
                                    else
                                    {
                                        RomCurve_stepClamped(route, lbl_803E2448);
                                    }
                                    route->reverse = rdir;
                                    fn_800D9EE8(route);
                                }
                            }
                        }
                    }
                }
            }
        }
        dir = route->reverse;
        if (((dir == 0) && (route->atSegmentEnd != 0)) ||
            ((dir != 0 && (route->atSegmentEnd == 0))))
        {
            node = trickySelectRouteEntry(state, route->nodeA4, dir & 0xff);
            if (node != 0)
            {
                curveFn_800da23c(route);
                type = *(s8*)((u8*)route->node9C + 0x1a);
                switch (type)
                {
                case 2:
                case 7:
                    prod = ((TrickyState*)state)->stateFlags;
                    if ((prod & 0x2000) != 0)
                    {
                        ((TrickyState*)state)->stateFlags = prod & ~0x2000LL;
                    }
                    else
                    {
                        ((TrickyState*)state)->stateFlags = prod | 0x2000;
                    }
                    break;
                }
                goto walk_nodes_common;
            }
            ((TrickyState*)state)->unk09 = 0;
        }
        else
        {
            node = trickySelectRouteEntry(state, route->nodeA0, dir & 0xff);
            if (node == 0)
            {
                ((TrickyState*)state)->unk09 = 0;
            }
            else
            {
                if (node != route->nodeA4)
                {
                    fn_800D9F38(route);
                }
            walk_nodes_common:
                if ((((TrickyState*)state)->unk534 == 0) || (wg != ((TrickyState*)state)->unk534))
                {
                    yawA = getAngle(((TrickyState*)state)->prevLocalPosX - ((GameObject*)obj)->anim.localPosX,
                                    ((TrickyState*)state)->prevLocalPosZ - ((GameObject*)obj)->anim.localPosZ);
                    yawB = getAngle(((TrickyState*)state)->prevLocalPosX - route->posX,
                                    ((TrickyState*)state)->prevLocalPosZ - route->posZ);
                    diff = yawA - (u16)yawB;
                    if (0x8000 < diff)
                    {
                        diff = diff - 0xffff;
                    }
                    if (diff < -0x8000)
                    {
                        diff = diff + 0xffff;
                    }
                    if (diff > 0x4000)
                    {
                        diff -= 0x8000;
                    }
                    else if (diff < -0x4000)
                    {
                        diff += 0x8000;
                    }
                    d = (diff >= 0) ? diff : -diff;
                    if (0x1000 < d)
                    {
                        ((TrickyState*)state)->speed = velBefore;
                        trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &route->posX, 1);
                    }
                }
                trickyAdvanceRouteTargetAhead(obj, route, ((TrickyState*)state)->speed);
                moved = trickyMove(obj, &route->posX);
                type = *(s8*)((u8*)route->nodeA0 + 0x1a);
                switch (type)
                {
                case 1:
                    ((TrickyState*)state)->unk09 = 8;
                    break;
                case 5:
                    ((TrickyState*)state)->unk09 = 0xb;
                    break;
                case 6:
                    ((TrickyState*)state)->unk09 = 0xd;
                    break;
                }
            }
        }
        break;
    case 8:
        trickyDebugPrint(strs + 0x49c);
        v = lbl_803E2420 * timeDelta + velBefore;
        ((TrickyState*)state)->speed = (v > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : v;
        if ((((TrickyState*)state)->unk534 != 0) && (wg == ((TrickyState*)state)->unk534))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            ((TrickyState*)state)->speed = (v < lbl_803E23DC) ? lbl_803E23DC : v;
        }
        yawA = getAngle(((TrickyState*)state)->prevLocalPosX - ((GameObject*)obj)->anim.localPosX,
                        ((TrickyState*)state)->prevLocalPosZ - ((GameObject*)obj)->anim.localPosZ);
        yawB = getAngle(((TrickyState*)state)->prevLocalPosX - route->posX,
                        ((TrickyState*)state)->prevLocalPosZ - route->posZ);
        diff = yawA - (u16)yawB;
        if (0x8000 < diff)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff = diff + 0xffff;
        }
        if (diff > 0x4000)
        {
            diff -= 0x8000;
        }
        else if (diff < -0x4000)
        {
            diff += 0x8000;
        }
        d = (diff >= 0) ? diff : -diff;
        if (0x1000 < d)
        {
            ((TrickyState*)state)->speed = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &route->posX, 1);
        }
        trickyAdvanceRouteTargetAhead(obj, route, ((TrickyState*)state)->speed);
        trickyMove(obj, &route->posX);
        dir = route->reverse;
        if (((dir == 0) && (route->atSegmentEnd != 0)) ||
            ((dir != 0 && (route->atSegmentEnd == 0))))
        {
            node = trickySelectRouteEntry(state, route->nodeA4, dir & 0xff);
            if (node == 0)
            {
                ((TrickyState*)state)->unk09 = 0;
            }
            else
            {
                curveFn_800da23c(route);
                ((TrickyState*)state)->dirX =
                    *(f32*)((u8*)route->nodeA0 + 8) - ((GameObject*)obj)->anim.worldPosX;
                ((TrickyState*)state)->dirZ =
                    *(f32*)((u8*)route->nodeA0 + 0x10) - ((GameObject*)obj)->anim.worldPosZ;
                sqx = ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX;
                sqz = ((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ;
                len = sqrtf(sqx + sqz);
                if (lbl_803E23DC != len)
                {
                    ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / len;
                    ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / len;
                }
                ((TrickyState*)state)->speed = gTrickyFollowMaxSpeed;
                objAnimFn_8013a3f0(obj, 0x15, lbl_803E2468, 0x4000000);
                ((TrickyState*)state)->unk09 = 9;
                ((TrickyState*)state)->unk7A0f = lbl_803E2440;
            }
        }
        break;
    case 9:
        trickyDebugPrint(strs + 0x4ac);
        if ((u8)(((TrickyState*)state)->stateFlags & 0x10000000))
        {
            v = lbl_803E23F4 * timeDelta + velBefore;
            if (v < lbl_803E23DC)
            {
                v = lbl_803E23DC;
            }
        }
        else if (velBefore > (v = lbl_803E24A4))
        {
            k = lbl_803E241C * timeDelta + velBefore;
            v = (k < v) ? v : k;
        }
        else
        {
            k = lbl_803E2420 * timeDelta + velBefore;
            v = (k > v) ? v : k;
        }
        ((TrickyState*)state)->speed = v;
        {
            f32 dx;
            f32 dz;
            dx = ((GameObject*)((GameObject*)obj)->extra)->anim.velocityZ;
            sqx = dx * dx;
            dz = *(f32*)&((GameObject*)((GameObject*)obj)->extra)->anim.parent;
            sqz = dz * dz;
            if (sqx + sqz > lbl_803E23EC)
            {
                trickyTurnTowardYaw(obj, getAngle(-dx, -dz));
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E24A8)
        {
            ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(
                (int)obj, ((TrickyState*)state)->speed, &((TrickyState*)state)->moveProgress);
            ((GameObject*)obj)->anim.localPosX =
                timeDelta * (((TrickyState*)state)->dirX * ((TrickyState*)state)->speed) + ((GameObject*)obj)->anim.
                localPosX;
            ((GameObject*)obj)->anim.localPosZ =
                timeDelta * (((TrickyState*)state)->dirZ * ((TrickyState*)state)->speed) + ((GameObject*)obj)->anim.
                localPosZ;
        }
        else
        {
            ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(
                (int)obj, ((TrickyState*)state)->speed * lbl_803E24AC, &((TrickyState*)state)->moveProgress);
            k = lbl_803E24AC;
            ((GameObject*)obj)->anim.localPosX =
                timeDelta * (((TrickyState*)state)->dirX * (((TrickyState*)state)->speed * lbl_803E24AC)) +
                ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)obj)->anim.localPosZ =
                timeDelta * (((TrickyState*)state)->dirZ * (((TrickyState*)state)->speed * lbl_803E24AC)) +
                ((GameObject*)obj)->anim.localPosZ;
        }
        if ((((TrickyState*)state)->stateFlags & 0x8000000) != 0)
        {
            f32 dx;
            f32 dz;
            node = route->nodeA0;
            dx = ((GameObject*)node)->anim.rootMotionScale - ((GameObject*)obj)->anim.worldPosX;
            dz = ((GameObject*)node)->anim.localPosY - ((GameObject*)obj)->anim.worldPosZ;
            sqx = dx * dx;
            sqz = dz * dz;
            len = sqrtf(sqx + sqz);
            *(f32*)(state + 0x64) = len / lbl_803E24A4;
            *(f32*)(state + 0x68) = lbl_803E23DC;
            *(f32*)(state + 0x74) = ((GameObject*)obj)->anim.worldPosX;
            *(f32*)(state + 0x70) = ((GameObject*)obj)->anim.worldPosY;
            *(f32*)(state + 0x78) = ((GameObject*)obj)->anim.worldPosZ;
            *(f32*)(state + 0x7c) = ((GameObject*)node)->anim.rootMotionScale;
            *(f32*)(state + 0x80) = ((GameObject*)node)->anim.localPosY;
            k = *(f32*)(state + 0x64);
            *(f32*)(state + 0x6c) =
                -(gTrickyFollowArcCoefficient * k * k - (((GameObject*)node)->anim.localPosX - ((GameObject*)obj)->anim.worldPosY)) / k;
            objAnimFn_8013a3f0(obj, 0x16, lbl_803E23DC, 0x4000000);
            ((TrickyState*)state)->unk3C = *(f32*)(state + 0x68) / *(f32*)(state + 0x64);
            ((TrickyState*)state)->speed = lbl_803E24A4;
            ((TrickyState*)state)->unk09 = 10;
            if (route->reverse != 0)
            {
                while (route->atSegmentEnd != 0)
                {
                    RomCurve_stepClamped(route, lbl_803E2448);
                }
            }
            else
            {
                while (route->atSegmentEnd == 0)
                {
                    RomCurve_stepClamped(route, lbl_803E23F8);
                }
            }
        }
        break;
    case 10:
        trickyDebugPrint(strs + 0x4b8);
        *(f32*)(state + 0x68) = *(f32*)(state + 0x68) + timeDelta;
        if (*(f32*)(state + 0x68) >= *(f32*)(state + 0x64))
        {
            ((GameObject*)obj)->anim.localPosY = *(f32*)((u8*)route->nodeA0 + 0xc);
            ((TrickyState*)state)->unk3C = lbl_803E23E8;
            ((TrickyState*)state)->unk09 = 7;
        }
        else
        {
            f32 baseX = *(f32*)(state + 0x74);
            f32 baseZ;
            ((GameObject*)obj)->anim.localPosX =
                (*(f32*)(state + 0x7c) - baseX) *
                (*(f32*)(state + 0x68) / *(f32*)(state + 0x64)) + baseX;
            k = *(f32*)(state + 0x68);
            ((GameObject*)obj)->anim.localPosY =
                gTrickyFollowArcCoefficient * k * k + (*(f32*)(state + 0x6c) * k + *(f32*)(state + 0x70));
            baseZ = *(f32*)(state + 0x78);
            ((GameObject*)obj)->anim.localPosZ =
                (*(f32*)(state + 0x80) - baseZ) *
                (*(f32*)(state + 0x68) / *(f32*)(state + 0x64)) + baseZ;
            v = *(f32*)(state + 0x64);
            if (v <= lbl_803E24B4)
            {
                ((TrickyState*)state)->unk3C = *(f32*)(state + 0x68) / v;
            }
            else
            {
                k = *(f32*)(state + 0x68);
                if (k <= lbl_803E24B8)
                {
                    ((TrickyState*)state)->unk3C = k / lbl_803E24B4;
                }
                else if (k >= v - lbl_803E24B8)
                {
                    ((TrickyState*)state)->unk3C = ((lbl_803E24B4 - v) + k) / lbl_803E24B4;
                }
                else
                {
                    ((TrickyState*)state)->unk3C =
                        ((k - lbl_803E24B8) / (v - lbl_803E24BC)) * lbl_803E24A8 +
                        lbl_803E24AC;
                }
            }
            objHitDetectFn_80062e84(obj, 0, 0);
            ((TrickyState*)state)->unk353 = 0;
        }
        break;
    case 0xb:
        trickyDebugPrint(strs + 0x4c4);
        v = lbl_803E2420 * timeDelta + velBefore;
        ((TrickyState*)state)->speed = (v > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : v;
        if ((((TrickyState*)state)->unk534 != 0) && (wg == ((TrickyState*)state)->unk534))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            ((TrickyState*)state)->speed = (v < lbl_803E23DC) ? lbl_803E23DC : v;
        }
        yawA = getAngle(((TrickyState*)state)->prevLocalPosX - ((GameObject*)obj)->anim.localPosX,
                        ((TrickyState*)state)->prevLocalPosZ - ((GameObject*)obj)->anim.localPosZ);
        yawB = getAngle(((TrickyState*)state)->prevLocalPosX - route->posX,
                        ((TrickyState*)state)->prevLocalPosZ - route->posZ);
        diff = yawA - (u16)yawB;
        if (0x8000 < diff)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff = diff + 0xffff;
        }
        if (diff > 0x4000)
        {
            diff -= 0x8000;
        }
        else if (diff < -0x4000)
        {
            diff += 0x8000;
        }
        d = (diff >= 0) ? diff : -diff;
        if (0x1000 < d)
        {
            ((TrickyState*)state)->speed = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &route->posX, 1);
        }
        trickyAdvanceRouteTargetAhead(obj, route, ((TrickyState*)state)->speed);
        trickyMove(obj, &route->posX);
        dir = route->reverse;
        if (((dir == 0) && (route->atSegmentEnd != 0)) ||
            ((dir != 0 && (route->atSegmentEnd == 0))))
        {
            node = trickySelectRouteEntry(state, route->nodeA4, dir & 0xff);
            if (node == 0)
            {
                ((TrickyState*)state)->unk09 = 0;
            }
            else
            {
                curveFn_800da23c(route);
                ((TrickyState*)state)->dirX =
                    *(f32*)((u8*)route->nodeA0 + 8) - ((GameObject*)obj)->anim.worldPosX;
                ((TrickyState*)state)->dirZ =
                    *(f32*)((u8*)route->nodeA0 + 0x10) - ((GameObject*)obj)->anim.worldPosZ;
                sqx = ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX;
                sqz = ((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ;
                len = sqrtf(sqx + sqz);
                if (lbl_803E23DC != len)
                {
                    ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / len;
                    ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / len;
                }
                if ((int)randomGetRange(0, 1) != 0)
                {
                    objAnimFn_8013a3f0(obj, 0x17, gTrickyFollowAnim17Speed, 0x40000c0);
                }
                else
                {
                    objAnimFn_8013a3f0(obj, 0x18, gTrickyFollowAnim18Speed, 0x40000c0);
                }
                ((TrickyState*)state)->verticalDelta =
                    (*(f32*)((u8*)route->nodeA0 + 0xc) - ((GameObject*)obj)->anim.worldPosY) /
                    gTrickyFollowVerticalDeltaDivisorA;
                ((TrickyState*)state)->unk09 = 0xc;
                if (route->reverse != 0)
                {
                    while (route->atSegmentEnd != 0)
                    {
                        RomCurve_stepClamped(route, lbl_803E2448);
                    }
                }
                else
                {
                    while (route->atSegmentEnd == 0)
                    {
                        RomCurve_stepClamped(route, lbl_803E23F8);
                    }
                }
                ((TrickyState*)state)->unk7A0f = lbl_803E2440;
            }
        }
        break;
    case 0xc:
    case 0xe:
        trickyDebugPrint(strs + 0x4d4);
        ((TrickyState*)state)->unk353 = 0;
        trickyAdvanceRouteTargetAhead(obj, route, ((TrickyState*)state)->speed);
        {
            f32 dx = ((GameObject*)((GameObject*)obj)->extra)->anim.velocityZ;
            f32 dz = *(f32*)&((GameObject*)((GameObject*)obj)->extra)->anim.parent;
            if (dx * dx + dz * dz > lbl_803E23EC)
            {
                trickyTurnTowardYaw(obj, getAngle(-dx, -dz));
            }
        }
        if ((((TrickyState*)state)->stateFlags & 0x8000000) != 0)
        {
            ((TrickyState*)state)->speed = lbl_803E24C0;
            trickyMove(obj, &route->posX);
            ((TrickyState*)state)->unk09 = 7;
        }
        break;
    case 0xd:
        trickyDebugPrint(strs + 0x4e8);
        v = lbl_803E2420 * timeDelta + velBefore;
        ((TrickyState*)state)->speed = (v > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : v;
        if ((((TrickyState*)state)->unk534 != 0) && (wg == ((TrickyState*)state)->unk534))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            ((TrickyState*)state)->speed = (v < lbl_803E23DC) ? lbl_803E23DC : v;
        }
        yawA = getAngle(((TrickyState*)state)->prevLocalPosX - ((GameObject*)obj)->anim.localPosX,
                        ((TrickyState*)state)->prevLocalPosZ - ((GameObject*)obj)->anim.localPosZ);
        yawB = getAngle(((TrickyState*)state)->prevLocalPosX - route->posX,
                        ((TrickyState*)state)->prevLocalPosZ - route->posZ);
        diff = yawA - (u16)yawB;
        if (0x8000 < diff)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff = diff + 0xffff;
        }
        if (diff > 0x4000)
        {
            diff -= 0x8000;
        }
        else if (diff < -0x4000)
        {
            diff += 0x8000;
        }
        d = (diff >= 0) ? diff : -diff;
        if (0x1000 < d)
        {
            ((TrickyState*)state)->speed = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &route->posX, 1);
        }
        trickyAdvanceRouteTargetAhead(obj, route, ((TrickyState*)state)->speed);
        trickyMove(obj, &route->posX);
        dir = route->reverse;
        if (((dir == 0) && (route->atSegmentEnd != 0)) ||
            ((dir != 0 && (route->atSegmentEnd == 0))))
        {
            node = trickySelectRouteEntry(state, route->nodeA4, dir & 0xff);
            if (node == 0)
            {
                ((TrickyState*)state)->unk09 = 0;
            }
            else
            {
                curveFn_800da23c(route);
                ((TrickyState*)state)->dirX =
                    *(f32*)((u8*)route->nodeA0 + 8) - ((GameObject*)obj)->anim.worldPosX;
                ((TrickyState*)state)->dirZ =
                    *(f32*)((u8*)route->nodeA0 + 0x10) - ((GameObject*)obj)->anim.worldPosZ;
                sqx = ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX;
                sqz = ((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ;
                len = sqrtf(sqx + sqz);
                if (lbl_803E23DC != len)
                {
                    ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / len;
                    ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / len;
                }
                objAnimFn_8013a3f0(obj, 0x19, lbl_803E249C, 0x40000c0);
                ((TrickyState*)state)->verticalDelta =
                    (((GameObject*)obj)->anim.worldPosY - *(f32*)((u8*)route->nodeA0 + 0xc)) /
                    gTrickyFollowVerticalDeltaDivisorB;
                ((TrickyState*)state)->unk09 = 0xe;
                if (route->reverse != 0)
                {
                    while (route->atSegmentEnd != 0)
                    {
                        RomCurve_stepClamped(route, lbl_803E2448);
                    }
                }
                else
                {
                    while (route->atSegmentEnd == 0)
                    {
                        RomCurve_stepClamped(route, lbl_803E23F8);
                    }
                }
                ((TrickyState*)state)->unk7A0f = lbl_803E2440;
            }
        }
        break;
    default:
        trickyDebugPrint(strs + 0x4f8);
    }
    if (((TrickyState*)state)->unk09 < 5)
    {
        if (isInWalkGroupOrPatch((f32*)(obj + 0x18)) != 0)
        {
            ((TrickyState*)state)->homePosX = ((GameObject*)obj)->anim.worldPosX;
            ((TrickyState*)state)->homePosY = ((GameObject*)obj)->anim.worldPosY;
            ((TrickyState*)state)->homePosZ = ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            (*gPathControlInterface)->attachObject(obj, &((TrickyState*)state)->pathControlFlags);
            ((GameObject*)obj)->anim.localPosX = ((TrickyState*)state)->homePosX;
            ((GameObject*)obj)->anim.localPosY = ((TrickyState*)state)->homePosY;
            ((GameObject*)obj)->anim.localPosZ = ((TrickyState*)state)->homePosZ;
            ((GameObject*)obj)->anim.worldPosX = ((TrickyState*)state)->homePosX;
            ((GameObject*)obj)->anim.worldPosY = ((TrickyState*)state)->homePosY;
            ((GameObject*)obj)->anim.worldPosZ = ((TrickyState*)state)->homePosZ;
            ObjHits_SyncObjectPosition(obj);
        }
    }
    step = ((TrickyState*)state)->unk09;
    if (((((step == 0) || (step == 2)) || (step == 4)) || (step == 3)) &&
        (lbl_803E23DC == ((TrickyState*)state)->speed))
    {
        return 2;
    }
    if (moved != 0)
    {
        return 1;
    }
    return 0;
}
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset
#undef route

void trickyUpdateApproachSpeed(u8* obj, f32 baseRadius, u8* state, f32* targetPos, u8 flag)
{
    struct
    {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } params;
    f32 delta[3];
    f32 dec;
    f32 v;
    f32 sum;
    f32 distSq;
    f32 thresh;
    f32 dist;
    f32 dx;
    f32 dz;
    f32 vel;
    f32 candidate;
    f32* otherTarget;
    u8* ctx;

    sum = lbl_803E2420;
    v = ((TrickyState*)state)->speed;
    {
        f32 td = timeDelta;
        dec = lbl_803E241C * td;
        while (v > lbl_803E23DC)
        {
            sum = v * td + sum;
            v = v + dec;
        }
    }
    thresh = baseRadius + sum;
    distSq = thresh;
    distSq = distSq * thresh;
    dist = getXZDistance(targetPos, (f32*)(obj + 0x18));
    if (dist < distSq)
    {
        candidate = ((TrickyState*)state)->speed;
        candidate = lbl_803E241C * timeDelta + candidate;
        ((TrickyState*)state)->speed =
            (candidate < lbl_803E23DC) ? lbl_803E23DC : candidate;
        return;
    }
    if (flag != 0)
    {
        delta[0] = targetPos[0] - ((GameObject*)obj)->anim.worldPosX;
        delta[1] = targetPos[1] - ((GameObject*)obj)->anim.worldPosY;
        delta[2] = targetPos[2] - ((GameObject*)obj)->anim.worldPosZ;
        params.angle = -((GameObject*)obj)->anim.rotX;
        params._pad0 = 0;
        params._pad1 = 0;
        vecRotateZXY(&params, delta);
        if (delta[2] > lbl_803E23DC)
        {
            candidate = ((TrickyState*)state)->speed;
            candidate = lbl_803E241C * timeDelta + candidate;
            ((TrickyState*)state)->speed =
                (candidate < lbl_803E23DC) ? lbl_803E23DC : candidate;
            return;
        }
    }
    if ((((TrickyState*)state)->stateFlags & 0x10000000) != 0)
    {
        ((TrickyState*)state)->speed =
            lbl_803E23F4 * timeDelta + ((TrickyState*)state)->speed;
        if (((TrickyState*)state)->speed < lbl_803E23DC)
        {
            ((TrickyState*)state)->speed = lbl_803E23DC;
        }
        return;
    }
    {
        f32 deltaSpeed = lbl_803E2488 + thresh;
        f32 deltaSpeedSq = deltaSpeed * deltaSpeed;
        ctx = ((GameObject*)obj)->extra;
        otherTarget = (f32*)((TrickyState*)ctx)->unk28;
        if (otherTarget == ((TrickyState*)ctx)->previousPathPoint)
        {
            dx = ((TrickyState*)ctx)->previousPathX - ((GameObject*)obj)->anim.worldPosX;
            dz = ((TrickyState*)ctx)->previousPathZ - ((GameObject*)obj)->anim.worldPosZ;
            vel = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
            dx = *(f32*)((u8*)otherTarget + 0) - ((GameObject*)obj)->anim.worldPosX;
            dz = *(f32*)((u8*)otherTarget + 8) - ((GameObject*)obj)->anim.worldPosZ;
            {
                f32 distOther = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
                candidate = distOther - vel;
            }
        }
        else
        {
            candidate = lbl_803E23DC;
        }
        if (dist < deltaSpeedSq)
        {
            if (candidate > lbl_803E23DC)
            {
                if (candidate < ((TrickyState*)state)->speed)
                {
                    f32 step = lbl_803E241C * timeDelta + ((TrickyState*)state)->speed;
                    ((TrickyState*)state)->speed = (step < candidate) ? candidate : step;
                    return;
                }
                else
                {
                    f32 step;
                    if (candidate > gTrickyFollowMaxSpeed)
                    {
                        step = lbl_803E2420 * timeDelta + ((TrickyState*)state)->speed;
                        ((TrickyState*)state)->speed =
                            (step > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : step;
                        return;
                    }
                    step = lbl_803E2420 * timeDelta + ((TrickyState*)state)->speed;
                    ((TrickyState*)state)->speed = (step > candidate) ? candidate : step;
                    return;
                }
            }
        }
    }
    if ((((TrickyState*)state)->stateFlags & 0x00100000) != 0)
    {
        ((TrickyState*)state)->speed =
            lbl_803E243C * timeDelta + ((TrickyState*)state)->speed;
        if (((TrickyState*)state)->speed > gTrickyFollowMaxSpeed)
        {
            ((TrickyState*)state)->speed = gTrickyFollowMaxSpeed;
        }
        return;
    }
    {
        f32 step = lbl_803E2420 * timeDelta + ((TrickyState*)state)->speed;
        ((TrickyState*)state)->speed = (step > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : step;
    }
}
