/*
 * trickyfollow - Tricky sidekick follow/path-walk movement (Tricky DLL 0x0C4;
 * the Hagabon DLL 0xDF is unrelated). trickyFn_8013b368 is
 * the per-frame movement step that resolves the target's walk/patch group and
 * drives motion through a substate machine and RomCurveWalker route;
 * trickyUpdateApproachSpeed ramps the follow speed toward a target point. The
 * lbl_803E2xxx externs are this DLL's .sdata2 float constants.
 */
#include "main/dll/baddie/trickyfollow.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/objfsa_query_api.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/track_dolphin_api.h"
#include "main/pi_dolphin_api.h"
#include "main/gamebits.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_0014_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00C4_tricky_api.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/skeetla.h"
#include "main/dll/objfsa.h"
#include "main/dll/skeetla_ext.h"
#include "main/dll/Hcurves_api.h"
#include "main/dll/objfsa_romcurve.h"

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

int trickyFn_8013b368(GameObject* obj, f32 vel, TrickyState* state)
{
    int tp;
    f32* target;
    char* strs = lbl_8031D2E8;
    u8 moved;
    int wg;
    int targetWg;
    u8 slot;
    u16 pp;
    int trickyPatch;
    s16 link;
    u32 prod;
    int dir;
    int i;
    ObjfsaRomCurveDef* node;
    u8* prevNode;
    f32* patchTarget;
    int d;
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
    f32 sqz;
    f32 sqx;
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
    void* routePtrs[9];

    moved = 1;
    if ((state->followPhase < 5) && (isInWalkGroupOrPatch(&obj->anim.worldPosX) == 0))
    {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
        obj->anim.localPosX = state->homePosX;
        obj->anim.localPosY = state->homePosY;
        obj->anim.localPosZ = state->homePosZ;
        obj->anim.worldPosX = state->homePosX;
        obj->anim.worldPosY = state->homePosY;
        obj->anim.worldPosZ = state->homePosZ;
        ObjHits_SyncObjectPosition(obj);
    }
    target = (f32*)state->targetPosPtr;
    wg = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0);
    if ((wg != 0) && (state->activeWalkGroup != wg))
    {
        state->activeWalkGroup = wg;
        *(s32*)&state->stateFlags &= ~(u64)0x400;
        state->patch[0] = 0;
        state->patch[1] = 0;
        state->patch[2] = 0;
        state->patch[3] = 0;
    }
    targetWg = Objfsa_GetWalkGroupIndexAtPoint(target, (ObjfsaWalkGroupPatchInfo*)&wgi);
    if (((wg != 0) && (targetWg == 0)) && ((ulink = getPatchGroup(target, wg)) != 0))
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
    if ((targetWg != 0) && (targetWg != state->walkGroup))
    {
        state->walkGroup = targetWg;
    }
    state->savedWalkGroup = state->walkGroup;
    trickyDebugPrint(strs + 0x1e8, state->activeWalkGroup, wg, targetWg,
                     state->walkGroup);
    if (state->activeWalkGroup == 0)
    {
        trickyReportError(strs + 0x214, obj->anim.worldPosX, obj->anim.worldPosY,
                          obj->anim.worldPosZ);
    }
    velBefore = state->speed;
    trickyUpdateApproachSpeed(obj, vel, state, target, 0);
    trickyDebugPrint(strs + 0x268, velBefore, state->speed);
    if (targetWg == state->activeWalkGroup)
    {
        state->stateFlags = state->stateFlags | 0x400;
        i = 0;
        mask = 1;
        for (; i < 4; i++, mask = mask << 1)
        {
            if (wgi.mask & mask)
            {
                state->patch[i] = wgi.patch[i];
                state->patchTargets[i].x = ((TrickyPoint3*)target)->x;
                state->patchTargets[i].y = ((TrickyPoint3*)target)->y;
                state->patchTargets[i].z = ((TrickyPoint3*)target)->z;
            }
        }
    }
    if ((targetWg != 0) && (targetWg == state->activeWalkGroup))
    {
        state->linkedWalkGroup = 0;
    }
    else
    {
        prod = targetWg * state->activeWalkGroup & 0xffff;
        if (prod != 0)
        {
            for (i = 0, link = prod; i < 4; i++)
            {
                if ((prod == wgi.patch[i]) && (((1 << i) & wgi.mask) != 0))
                {
                    state->linkedWalkGroup = link;
                    state->linkedPatchPos.x = ((TrickyPoint3*)target)->x;
                    state->linkedPatchPos.y = ((TrickyPoint3*)target)->y;
                    state->linkedPatchPos.z = ((TrickyPoint3*)target)->z;
                }
            }
        }
    }
    if (isInWalkGroupOrPatch(target) != 0)
    {
        trickyDebugPrint(strs + 0x284);
    }
    else
    {
        trickyDebugPrint(strs + 0x2b0);
    }
    trickyDebugPrint(strs + 0x2e4, getPatchGroup(target, state->activeWalkGroup));
    if ((state->stateFlags & 0x400) != 0)
    {
        for (i = 0; i < 4; i++)
        {
            if (state->patch[i] != 0)
            {
                trickyDebugPrint(strs + 0x308, i, state->patchTargets[i].x, state->patchTargets[i].y,
                                 state->patchTargets[i].z);
            }
        }
    }
    if (state->linkedWalkGroup != 0)
    {
        trickyDebugPrint(strs + 0x328, state->linkedPatchPos.x, state->linkedPatchPos.y,
                         state->linkedPatchPos.z);
    }
    tp = getPatchGroup(target, state->activeWalkGroup) & 0xffff;
    trickyPatch = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup) & 0xffff;
    if ((targetWg != 0) && (wg == targetWg))
    {
        state->followPhase = 1;
    }
    else
    {
        ulink = walkGroupFn_800db3e4(&obj->anim.worldPosX, target, state->activeWalkGroup);
        if (ulink != 0)
        {
            state->followPhase = 1;
            if (ulink != state->activeWalkGroup)
            {
                state->activeWalkGroup = ulink;
                *(s32*)&state->stateFlags &= ~(u64)0x400;
                state->patch[0] = 0;
                state->patch[1] = 0;
                state->patch[2] = 0;
                state->patch[3] = 0;
            }
        }
        else if (state->followPhase < 5)
        {
            if ((u32)tp != 0)
            {
                if (targetWg == 0)
                {
                    if (wg != 0)
                    {
                        for (i = 0; i < 4; i++)
                        {
                            if (state->patch[i] == tp)
                            {
                                slot = i;
                                state->followPhase = 2;
                                break;
                            }
                        }
                        if (i == 4)
                        {
                            if (tp & !(0xff - state->cachedWalkGroup))
                            {
                                state->walkGroup = (int)(tp & 0xff00) >> 8;
                            }
                            else
                            {
                                state->walkGroup = tp & 0xff;
                            }
                            state->followPhase = 5;
                        }
                    }
                    else
                    {
                        if ((u32)trickyPatch != 0)
                        {
                            for (i = 0; i < 4; i++)
                            {
                                if (state->patch[i] == trickyPatch)
                                {
                                    trickyPatch = i & 0xffff;
                                    state->followPhase = 2;
                                    break;
                                }
                            }
                            if (i == 4)
                            {
                                Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, trickyPatch);
                                state->followPhase = 4;
                            }
                        }
                        else
                        {
                            trickyReportError(strs + 0x344);
                            state->followPhase = 0;
                        }
                    }
                }
                else
                {
                    if (wg != 0)
                    {
                        for (i = 0; i < 4; i++)
                        {
                            if (state->patch[i] == tp)
                            {
                                slot = i;
                                state->followPhase = 2;
                                break;
                            }
                        }
                        if (i == 4)
                        {
                            state->followPhase = 5;
                        }
                    }
                    else
                    {
                        if (wg == 0 &&
                            (u32)(tp = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup) & 0xffff) !=
                                0)
                        {
                            if (state->linkedWalkGroup == tp)
                            {
                                state->followPhase = 3;
                            }
                            else
                            {
                                Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, (u16)tp);
                                state->followPhase = 4;
                            }
                        }
                        else
                        {
                            pp = tp;
                            i = isPointWithinPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup, pp);
                            trickyReportError(strs + 0x374, pp, targetWg, wg, state->activeWalkGroup, i);
                            state->followPhase = 0;
                        }
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
                            state->followPhase = 0;
                        }
                        else
                        {
                            state->walkGroup = pid & 0xff;
                            state->followPhase = 5;
                        }
                    }
                    else
                    {
                        state->followPhase = 0;
                    }
                }
                else
                {
                    if (wg != 0)
                    {
                        if (isPointWithinPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup,
                                                    (targetWg = targetWg * wg & 0xffff)) != 0)
                        {
                            if (state->linkedWalkGroup == targetWg)
                            {
                                state->followPhase = 3;
                            }
                            else
                            {
                                state->followPhase = 5;
                            }
                        }
                        else
                        {
                            for (i = 0; i < 4; i++)
                            {
                                if (state->patch[i] == targetWg)
                                {
                                    slot = i;
                                    state->followPhase = 2;
                                    break;
                                }
                            }
                            if ((i == 4) || (targetWg != state->linkedWalkGroup))
                            {
                                state->followPhase = 5;
                            }
                        }
                    }
                    else
                    {
                        u16 p = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup);
                        if (p != 0)
                        {
                            if (targetWg == state->activeWalkGroup)
                            {
                                for (i = 0; i < 4; i++)
                                {
                                    if (state->patch[i] == p)
                                    {
                                        slot = i;
                                        state->followPhase = 2;
                                        break;
                                    }
                                }
                                if (i == 4)
                                {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, (u16)p);
                                    state->followPhase = 4;
                                }
                            }
                            else if (state->linkedWalkGroup == p)
                            {
                                state->followPhase = 3;
                            }
                            else
                            {
                                Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, (u16)p);
                                state->followPhase = 4;
                            }
                        }
                        else
                        {
                            trickyReportError(strs + 0x3ec);
                            state->followPhase = 0;
                        }
                    }
                }
            }
        }
    }
    if (state->followPhase < 5)
    {
        state->stateFlags &= ~0x2000LL;
    }
    trickyDebugPrint(strs + 0x404, state->followPhase);
    switch (state->followPhase)
    {
    case 0:
        trickyDebugPrint(strs + 0x41c);
        v = lbl_803E241C * timeDelta + velBefore;
        state->speed = (v < 0.0f) ? 0.0f : v;
        if (0.0f == state->speed)
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
        state->speed = velBefore;
        trickyUpdateApproachSpeed(obj, 0.0f, state, patchTarget = &state->patchTargets[slot].x, 1);
        moved = trickyMove(obj, patchTarget);
        break;
    case 4:
        trickyDebugPrint(strs + 0x448);
        state->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, &state->patchExitPos.x, 1);
        moved = trickyMove(obj, &state->patchExitPos.x);
        break;
    case 3:
        trickyDebugPrint(strs + 0x45c);
        state->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, &state->linkedPatchPos.x, 1);
        moved = trickyMove(obj, &state->linkedPatchPos.x);
        break;
    case 6:
        trickyDebugPrint(strs + 0x46c, 10,
                         (int)getXZDistance(&state->routeSeedNode->x, &obj->anim.worldPosX));
        dist = getXZDistance(&state->routeSeedNode->x, &obj->anim.worldPosX);
        if (lbl_803E23E0 > dist)
        {
            state->route.reverse = state->routeSeedDir;
            prevNode = (u8*)state->routeSeedNode;
            node = trickySelectRouteEntry((u8*)state, prevNode, state->routeSeedDir);
            if (node == 0)
            {
                state->followPhase = 0;
            }
            else
            {
                    u8* nextNode = trickySelectRouteEntry((u8*)state, (u8*)node, state->routeSeedDir);
                    if (nextNode == 0)
                {
                    state->followPhase = 0;
                }
                else
                {
                        RomCurve_setupHermiteSegment(&state->route, prevNode, node, nextNode);
                    RomCurve_stepClamped(&state->route, lbl_803E2484);
                    yawA = getAngle(state->prevLocalPosX - obj->anim.localPosX,
                                    state->prevLocalPosZ - obj->anim.localPosZ);
                    yawB = getAngle(state->prevLocalPosX - state->route.posX,
                                    state->prevLocalPosZ - state->route.posZ);
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
                        state->speed = velBefore;
                        trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &state->route.posX, 1);
                    }
                    trickyAdvanceRouteTargetAhead((int)obj, &state->route, state->speed);
                    moved = trickyMove(obj, &state->route.posX);
                    switch (*(s8*)(prevNode + 0x1a))
                    {
                    case 1:
                        node = state->route.nodeA0;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (0.0f != len)
                        {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        state->speed = gTrickyFollowMaxSpeed;
                        objAnimFn_8013a3f0((int)obj, 0x15, lbl_803E2468, 0x4000000);
                        state->followPhase = 9;
                        state->voiceCooldown = lbl_803E2440;
                        break;
                    case 5:
                        node = state->route.nodeA0;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (0.0f != len)
                        {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        if ((int)randomGetRange(0, 1) != 0)
                        {
                            objAnimFn_8013a3f0((int)obj, 0x17, gTrickyFollowAnim17Speed, 0x40000c0);
                        }
                        else
                        {
                            objAnimFn_8013a3f0((int)obj, 0x18, gTrickyFollowAnim18Speed, 0x40000c0);
                        }
                        state->verticalDelta =
                            (((ObjfsaRomCurveDef*)state->route.nodeA0)->y - obj->anim.worldPosY) /
                            gTrickyFollowVerticalDeltaDivisorA;
                        state->followPhase = 0xc;
                        if (state->route.reverse != 0)
                        {
                            while (state->route.atSegmentEnd != 0)
                            {
                                RomCurve_stepClamped(&state->route, lbl_803E2448);
                            }
                        }
                        else
                        {
                            while (state->route.atSegmentEnd == 0)
                            {
                                RomCurve_stepClamped(&state->route, lbl_803E23F8);
                            }
                        }
                        state->voiceCooldown = lbl_803E2440;
                        break;
                    case 6:
                        node = state->route.nodeA0;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (0.0f != len)
                        {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        objAnimFn_8013a3f0((int)obj, 0x19, lbl_803E249C, 0x40000c0);
                        state->verticalDelta =
                            (obj->anim.worldPosY - ((ObjfsaRomCurveDef*)state->route.nodeA0)->y) /
                            gTrickyFollowVerticalDeltaDivisorB;
                        state->followPhase = 0xe;
                        if (state->route.reverse != 0)
                        {
                            while (state->route.atSegmentEnd != 0)
                            {
                                RomCurve_stepClamped(&state->route, lbl_803E2448);
                            }
                        }
                        else
                        {
                            while (state->route.atSegmentEnd == 0)
                            {
                                RomCurve_stepClamped(&state->route, lbl_803E23F8);
                            }
                        }
                        state->voiceCooldown = lbl_803E2440;
                        break;
                    case 2:
                    case 7:
                        state->stateFlags = state->stateFlags | 0x2000;
                    default:
                        state->followPhase = 7;
                    }
                }
            }
        }
        else
        {
            node = state->routeSeedNode;
            if (node == NULL)
            {
                node = NULL;
            }
            else if (((node->requiredBit != -1) && (mainGetBit(node->requiredBit) == 0)) ||
                     ((node->forbiddenBit != -1) && (mainGetBit(node->forbiddenBit) != 0)))
            {
                node = NULL;
            }
            if ((node != 0) || (wg == 0))
            {
                state->speed = velBefore;
                trickyUpdateApproachSpeed(obj, lbl_803E246C, state,
                                          &state->routeSeedNode->x, 1);
                moved = trickyMove(obj, &state->routeSeedNode->x);
            }
            else
            {
                state->followPhase = 0;
            }
        }
        break;
    case 5:
        trickyDebugPrint(strs + 0x480);
        trickyRankLinkedRouteCandidates(obj, routeFlags, (s16)wg, routePtrs);
        i = trickyFindReachableRouteIndex((u8*)state, routePtrs, routeFlags, state->walkGroup);
        if (i == -1)
        {
            state->speed = velBefore;
            return 2;
        }
        state->routeSeedDir = routeFlags[i];
        state->routeSeedNode = routePtrs[i];
        state->speed = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, &state->routeSeedNode->x, 1);
        moved = trickyMove(obj, &state->routeSeedNode->x);
        state->followPhase = 6;
        break;
    case 7:
        trickyDebugPrint(strs + 0x490);
        if ((state->savedWalkGroup != 0) && (wg == state->savedWalkGroup))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        node = state->route.nodeA0;
        if ((((ObjfsaRomCurveDef*)state->route.node9C)->unk1A != 9) && (node->unk1A != 9))
        {
            f32* tpos = (f32*)state->targetPosPtr;
            delta[0] = tpos[0] - obj->anim.worldPosX;
            delta[1] = tpos[1] - obj->anim.worldPosY;
            delta[2] = tpos[2] - obj->anim.worldPosZ;
            rot.angle = -obj->anim.rotX;
            rot._pad0 = 0;
            rot._pad1 = 0;
            vecRotateZXY(&rot.angle, delta);
            if ((delta[2] > 0.0f) && (0.0f != state->speed))
            {
                for (step = 0; step < 4; step++)
                {
                    u8 grp = node->linkSelectors[step];
                    if (grp == state->walkGroup)
                    {
                        break;
                    }
                }
                if (step == 4)
                {
                    pathSearchBegin(&state->pathSearches[0], (PathPoint*)state->route.nodeA4,
                                (f32*)state->targetPosPtr, state->walkGroup,
                                state->route.reverse);
                    pathSearchBegin(&state->pathSearches[1], (PathPoint*)state->route.node9C,
                                (f32*)state->targetPosPtr, state->walkGroup,
                                state->route.reverse ^ 1);
                    found = 0;
                    for (i = 0; (u8)(i = i + 1) < 100 && (found != 1);)
                    {
                        found = pathSearchStep(&state->pathSearches[0], 1);
                        if (found != 1)
                        {
                            found = pathSearchStep(&state->pathSearches[1], 1);
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
                                    prod = (state->route.reverse ^ 1) & 0xff;
                                    if (prod == 0)
                                    {
                                        RomCurve_stepClamped(&state->route, lbl_803E23F8);
                                    }
                                    else
                                    {
                                        RomCurve_stepClamped(&state->route, lbl_803E2448);
                                    }
                                    state->route.reverse = prod;
                                    RomCurve_swapEndpointNodes(&state->route);
                                }
                            }
                        }
                    }
                }
            }
        }
        dir = state->route.reverse;
        if (((dir == 0) && (state->route.atSegmentEnd != 0)) || ((dir != 0 && (state->route.atSegmentEnd == 0))))
        {
            node = trickySelectRouteEntry((u8*)state, state->route.nodeA4, dir & 0xff);
            if (node != 0)
            {
                curveFn_800da23c(&state->route, node);
                type = ((ObjfsaRomCurveDef*)state->route.node9C)->unk1A;
                switch (type)
                {
                case 2:
                case 7:
                    prod = state->stateFlags;
                    if ((prod & 0x2000) != 0)
                    {
                        state->stateFlags = prod & ~0x2000LL;
                    }
                    else
                    {
                        state->stateFlags = prod | 0x2000;
                    }
                    break;
                }
            }
            else
            {
                state->followPhase = 0;
                break;
            }
        }
        else
        {
            node = trickySelectRouteEntry((u8*)state, state->route.nodeA0, dir & 0xff);
            if (node == 0)
            {
                state->followPhase = 0;
                break;
            }
            if (node != state->route.nodeA4)
            {
                RomCurve_setSegmentEndNode(&state->route, node);
            }
        }
        if ((state->savedWalkGroup == 0) || (wg != state->savedWalkGroup))
        {
            yawA = getAngle(state->prevLocalPosX - obj->anim.localPosX,
                            state->prevLocalPosZ - obj->anim.localPosZ);
            yawB = getAngle(state->prevLocalPosX - state->route.posX,
                            state->prevLocalPosZ - state->route.posZ);
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
                state->speed = velBefore;
                trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &state->route.posX, 1);
            }
        }
        trickyAdvanceRouteTargetAhead((int)obj, &state->route, state->speed);
        moved = trickyMove(obj, &state->route.posX);
        type = ((ObjfsaRomCurveDef*)state->route.nodeA0)->unk1A;
        switch (type)
        {
        case 1:
            state->followPhase = 8;
            break;
        case 5:
            state->followPhase = 0xb;
            break;
        case 6:
            state->followPhase = 0xd;
            break;
        }
        break;
    case 8:
        trickyDebugPrint(strs + 0x49c);
        v = lbl_803E2420 * timeDelta + velBefore;
        state->speed = (v > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : v;
        if ((state->savedWalkGroup != 0) && (wg == state->savedWalkGroup))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        yawA = getAngle(state->prevLocalPosX - obj->anim.localPosX,
                        state->prevLocalPosZ - obj->anim.localPosZ);
        yawB = getAngle(state->prevLocalPosX - state->route.posX,
                        state->prevLocalPosZ - state->route.posZ);
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
            state->speed = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &state->route.posX, 1);
        }
        trickyAdvanceRouteTargetAhead((int)obj, &state->route, state->speed);
        trickyMove(obj, &state->route.posX);
        dir = state->route.reverse;
        if (((dir == 0) && (state->route.atSegmentEnd != 0)) || ((dir != 0 && (state->route.atSegmentEnd == 0))))
        {
            u8* nextRouteNode = trickySelectRouteEntry((u8*)state, state->route.nodeA4, dir & 0xff);
            if (nextRouteNode == 0)
            {
                state->followPhase = 0;
            }
            else
            {
                curveFn_800da23c(&state->route, nextRouteNode);
                node = state->route.nodeA0;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (0.0f != len)
                {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                state->speed = gTrickyFollowMaxSpeed;
                objAnimFn_8013a3f0((int)obj, 0x15, lbl_803E2468, 0x4000000);
                state->followPhase = 9;
                state->voiceCooldown = lbl_803E2440;
            }
        }
        break;
    case 9:
        trickyDebugPrint(strs + 0x4ac);
        if ((u8)(state->stateFlags & 0x10000000))
        {
            v = lbl_803E23F4 * timeDelta + velBefore;
            if (v < 0.0f)
            {
                v = 0.0f;
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
        state->speed = v;
        {
            f32 dz;
            f32 dx;
            dx = ((TrickyState*)obj->extra)->dirX;
            sqx = dx;
            sqx = sqx * sqx;
            dz = ((TrickyState*)obj->extra)->dirZ;
            sqz = dz;
            sqz = sqz * sqz;
            if (sqx + sqz > lbl_803E23EC)
            {
                trickyTurnTowardYaw((u8*)obj, (s16)getAngle(-dx, -dz));
            }
        }
        if (obj->anim.currentMoveProgress < lbl_803E24A8)
        {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed, &state->moveProgress);
            obj->anim.localPosX =
                timeDelta * (state->dirX * state->speed) +
                obj->anim.localPosX;
            obj->anim.localPosZ =
                timeDelta * (state->dirZ * state->speed) +
                obj->anim.localPosZ;
        }
        else
        {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed * lbl_803E24AC, &state->moveProgress);
            obj->anim.localPosX =
                timeDelta * (state->dirX * (state->speed * (k = lbl_803E24AC))) +
                obj->anim.localPosX;
            obj->anim.localPosZ =
                timeDelta * (state->dirZ * (state->speed * k)) +
                obj->anim.localPosZ;
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0)
        {
            f32 dx;
            f32 dz;
            f32 arcCoefficient;
            TrickyJumpArc* arc = &state->jumpArc;
            node = state->route.nodeA0;
            dx = node->x - obj->anim.worldPosX;
            sqx = dx * dx;
            dx = node->z - obj->anim.worldPosZ;
            dx = dx * dx;
            len = sqrtf(sqx + dx);
            arc->duration = len / lbl_803E24A4;
            arc->time = (v = 0.0f);
            arc->baseX = obj->anim.worldPosX;
            arc->baseY = obj->anim.worldPosY;
            arc->baseZ = obj->anim.worldPosZ;
            arc->landX = node->x;
            arc->landZ = node->z;
            k = arc->duration;
            arcCoefficient = gTrickyFollowArcCoefficient * k;
            arc->riseCoeff = -(arcCoefficient * k -
                               (node->y - obj->anim.worldPosY)) /
                              k;
            objAnimFn_8013a3f0((int)obj, 0x16, v, 0x4000000);
            state->arcMoveProgress = arc->time / arc->duration;
            state->speed = lbl_803E24A4;
            state->followPhase = 10;
            if (state->route.reverse != 0)
            {
                while (state->route.atSegmentEnd != 0)
                {
                    RomCurve_stepClamped(&state->route, lbl_803E2448);
                }
            }
            else
            {
                while (state->route.atSegmentEnd == 0)
                {
                    RomCurve_stepClamped(&state->route, lbl_803E23F8);
                }
            }
        }
        break;
    case 10:
    {
        TrickyJumpArc* arc = &state->jumpArc;
        trickyDebugPrint(strs + 0x4b8);
        arc->time = arc->time + timeDelta;
        if (arc->time >= arc->duration)
        {
            obj->anim.localPosY = ((ObjfsaRomCurveDef*)state->route.nodeA0)->y;
            state->arcMoveProgress = lbl_803E23E8;
            state->followPhase = 7;
        }
        else
        {
            f32 baseX = arc->baseX;
            f32 baseZ;
            obj->anim.localPosX = (arc->landX - baseX) * (arc->time / arc->duration) + baseX;
            k = arc->time;
            {
                f32 ck;
                ck = gTrickyFollowArcCoefficient * k;
                obj->anim.localPosY = ck * k + (arc->riseCoeff * k + arc->baseY);
            }
            baseZ = arc->baseZ;
            obj->anim.localPosZ = (arc->landZ - baseZ) * (arc->time / arc->duration) + baseZ;
            v = arc->duration;
            if (v <= lbl_803E24B4)
            {
                state->arcMoveProgress = arc->time / v;
            }
            else
            {
                k = arc->time;
                if (k <= lbl_803E24B8)
                {
                    state->arcMoveProgress = k / lbl_803E24B4;
                }
                else if (k >= v - lbl_803E24B8)
                {
                    f32 adj;
                    adj = lbl_803E24B4 - v;
                    state->arcMoveProgress = (adj + k) / lbl_803E24B4;
                }
                else
                {
                    k = (k - lbl_803E24B8) / (v - lbl_803E24BC);
                    state->arcMoveProgress = k * lbl_803E24A8 + lbl_803E24AC;
                }
            }
            objHitDetectFn_80062e84(obj, NULL, 0);
            state->heightUpdateActive = 0;
        }
        break;
    }
    case 0xb:
        trickyDebugPrint(strs + 0x4c4);
        v = lbl_803E2420 * timeDelta + velBefore;
        state->speed = (v > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : v;
        if ((state->savedWalkGroup != 0) && (wg == state->savedWalkGroup))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        yawA = getAngle(state->prevLocalPosX - obj->anim.localPosX,
                        state->prevLocalPosZ - obj->anim.localPosZ);
        yawB = getAngle(state->prevLocalPosX - state->route.posX,
                        state->prevLocalPosZ - state->route.posZ);
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
            state->speed = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &state->route.posX, 1);
        }
        trickyAdvanceRouteTargetAhead((int)obj, &state->route, state->speed);
        trickyMove(obj, &state->route.posX);
        dir = state->route.reverse;
        if (((dir == 0) && (state->route.atSegmentEnd != 0)) || ((dir != 0 && (state->route.atSegmentEnd == 0))))
        {
            u8* nextRouteNode = trickySelectRouteEntry((u8*)state, state->route.nodeA4, dir & 0xff);
            if (nextRouteNode == 0)
            {
                state->followPhase = 0;
            }
            else
            {
                curveFn_800da23c(&state->route, nextRouteNode);
                node = state->route.nodeA0;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (0.0f != len)
                {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                if ((int)randomGetRange(0, 1) != 0)
                {
                    objAnimFn_8013a3f0((int)obj, 0x17, gTrickyFollowAnim17Speed, 0x40000c0);
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 0x18, gTrickyFollowAnim18Speed, 0x40000c0);
                }
                state->verticalDelta =
                    (((ObjfsaRomCurveDef*)state->route.nodeA0)->y - obj->anim.worldPosY) /
                    gTrickyFollowVerticalDeltaDivisorA;
                state->followPhase = 0xc;
                if (state->route.reverse != 0)
                {
                    while (state->route.atSegmentEnd != 0)
                    {
                        RomCurve_stepClamped(&state->route, lbl_803E2448);
                    }
                }
                else
                {
                    while (state->route.atSegmentEnd == 0)
                    {
                        RomCurve_stepClamped(&state->route, lbl_803E23F8);
                    }
                }
                state->voiceCooldown = lbl_803E2440;
            }
        }
        break;
    case 0xc:
    case 0xe:
        trickyDebugPrint(strs + 0x4d4);
        state->heightUpdateActive = 0;
        trickyAdvanceRouteTargetAhead((int)obj, &state->route, state->speed);
        {
            f32 dz;
            f32 dx;
            dx = ((TrickyState*)obj->extra)->dirX;
            sqz = dx;
            sqz = sqz * sqz;
            dz = ((TrickyState*)obj->extra)->dirZ;
            sqx = dz;
            sqx = sqx * sqx;
            if (sqz + sqx > lbl_803E23EC)
            {
                trickyTurnTowardYaw((u8*)obj, (s16)getAngle(-dx, -dz));
            }
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0)
        {
            state->speed = lbl_803E24C0;
            trickyMove(obj, &state->route.posX);
            state->followPhase = 7;
        }
        break;
    case 0xd:
        trickyDebugPrint(strs + 0x4e8);
        v = lbl_803E2420 * timeDelta + velBefore;
        state->speed = (v > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : v;
        if ((state->savedWalkGroup != 0) && (wg == state->savedWalkGroup))
        {
            v = lbl_803E241C * timeDelta + velBefore;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        yawA = getAngle(state->prevLocalPosX - obj->anim.localPosX,
                        state->prevLocalPosZ - obj->anim.localPosZ);
        yawB = getAngle(state->prevLocalPosX - state->route.posX,
                        state->prevLocalPosZ - state->route.posZ);
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
            state->speed = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, &state->route.posX, 1);
        }
        trickyAdvanceRouteTargetAhead((int)obj, &state->route, state->speed);
        trickyMove(obj, &state->route.posX);
        dir = state->route.reverse;
        if (((dir == 0) && (state->route.atSegmentEnd != 0)) || ((dir != 0 && (state->route.atSegmentEnd == 0))))
        {
            u8* nextRouteNode = trickySelectRouteEntry((u8*)state, state->route.nodeA4, dir & 0xff);
            if (nextRouteNode == 0)
            {
                state->followPhase = 0;
            }
            else
            {
                curveFn_800da23c(&state->route, nextRouteNode);
                node = state->route.nodeA0;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (0.0f != len)
                {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                objAnimFn_8013a3f0((int)obj, 0x19, lbl_803E249C, 0x40000c0);
                state->verticalDelta =
                    (obj->anim.worldPosY - ((ObjfsaRomCurveDef*)state->route.nodeA0)->y) /
                    gTrickyFollowVerticalDeltaDivisorB;
                state->followPhase = 0xe;
                if (state->route.reverse != 0)
                {
                    while (state->route.atSegmentEnd != 0)
                    {
                        RomCurve_stepClamped(&state->route, lbl_803E2448);
                    }
                }
                else
                {
                    while (state->route.atSegmentEnd == 0)
                    {
                        RomCurve_stepClamped(&state->route, lbl_803E23F8);
                    }
                }
                state->voiceCooldown = lbl_803E2440;
            }
        }
        break;
    default:
        trickyDebugPrint(strs + 0x4f8);
    }
    if (state->followPhase < 5)
    {
        if (isInWalkGroupOrPatch(&obj->anim.worldPosX) != 0)
        {
            state->homePosX = obj->anim.worldPosX;
            state->homePosY = obj->anim.worldPosY;
            state->homePosZ = obj->anim.worldPosZ;
        }
        else
        {
            (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
            obj->anim.localPosX = state->homePosX;
            obj->anim.localPosY = state->homePosY;
            obj->anim.localPosZ = state->homePosZ;
            obj->anim.worldPosX = state->homePosX;
            obj->anim.worldPosY = state->homePosY;
            obj->anim.worldPosZ = state->homePosZ;
            ObjHits_SyncObjectPosition(obj);
        }
    }
    step = state->followPhase;
    if (((((step == 0) || (step == 2)) || (step == 4)) || (step == 3)) &&
        (0.0f == state->speed))
    {
        return 2;
    }
    if (moved != 0)
    {
        return 1;
    }
    return 0;
}

void trickyUpdateApproachSpeed(GameObject* obj, f32 baseRadius, TrickyState* state, f32* targetPos, u8 flag)
{
    struct
    {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } params;
    f32 delta[3];
    f32 dec;
    f32 td;
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
    TrickyState* ctx;
    f32 minSpeed;

    sum = lbl_803E2420;
    v = state->speed;
    td = timeDelta;
    dec = lbl_803E241C * td;
    minSpeed = 0.0f;
    while (v > minSpeed)
    {
        sum = v * td + sum;
        v = v + dec;
    }
    thresh = baseRadius + sum;
    distSq = thresh;
    distSq = distSq * thresh;
    dist = getXZDistance(targetPos, &obj->anim.worldPosX);
    if (dist < distSq)
    {
        candidate = state->speed;
        candidate = lbl_803E241C * timeDelta + candidate;
        state->speed = (candidate < 0.0f) ? 0.0f : candidate;
        return;
    }
    if (flag != 0)
    {
        delta[0] = targetPos[0] - obj->anim.worldPosX;
        delta[1] = targetPos[1] - obj->anim.worldPosY;
        delta[2] = targetPos[2] - obj->anim.worldPosZ;
        params.angle = -obj->anim.rotX;
        params._pad0 = 0;
        params._pad1 = 0;
        vecRotateZXY(&params.angle, delta);
        if (delta[2] > 0.0f)
        {
            candidate = state->speed;
            candidate = lbl_803E241C * timeDelta + candidate;
            state->speed = (candidate < 0.0f) ? 0.0f : candidate;
            return;
        }
    }
    if ((state->stateFlags & 0x10000000) != 0)
    {
        state->speed = lbl_803E23F4 * timeDelta + state->speed;
        if (state->speed < 0.0f)
        {
            state->speed = 0.0f;
        }
        return;
    }
    {
        f32 deltaSpeed = lbl_803E2488 + thresh;
        f32 deltaSpeedSq = deltaSpeed * deltaSpeed;
        ctx = obj->extra;
        otherTarget = (f32*)ctx->targetPosPtr;
        if (otherTarget == ctx->previousPathPoint)
        {
            dx = ctx->previousPathX - obj->anim.worldPosX;
            dz = ctx->previousPathZ - obj->anim.worldPosZ;
            vel = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
            dx = *(f32*)((u8*)otherTarget + 0) - obj->anim.worldPosX;
            dz = *(f32*)((u8*)otherTarget + 8) - obj->anim.worldPosZ;
            {
                f32 distOther = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
                candidate = distOther - vel;
            }
        }
        else
        {
            candidate = 0.0f;
        }
        if (dist < deltaSpeedSq)
        {
            if (candidate > 0.0f)
            {
                f32 curSpeed = state->speed;
                if (candidate < curSpeed)
                {
                    f32 step = lbl_803E241C * timeDelta + curSpeed;
                    state->speed = (step < candidate) ? candidate : step;
                    return;
                }
                else
                {
                    f32 step;
                    if (candidate > gTrickyFollowMaxSpeed)
                    {
                        step = lbl_803E2420 * timeDelta + state->speed;
                        state->speed = (step > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : step;
                        return;
                    }
                    step = lbl_803E2420 * timeDelta + state->speed;
                    state->speed = (step > candidate) ? candidate : step;
                    return;
                }
            }
        }
    }
    if ((state->stateFlags & 0x00100000) != 0)
    {
        state->speed = lbl_803E243C * timeDelta + state->speed;
        if (state->speed > gTrickyFollowMaxSpeed)
        {
            state->speed = gTrickyFollowMaxSpeed;
        }
        return;
    }
    {
        f32 step = state->speed;
        step = lbl_803E2420 * timeDelta + step;
        state->speed = (step > gTrickyFollowMaxSpeed) ? gTrickyFollowMaxSpeed : step;
    }
}
