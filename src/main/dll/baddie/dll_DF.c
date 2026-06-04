#include "ghidra_import.h"
#include "main/dll/baddie/dll_DF.h"

#pragma peephole off
#pragma scheduling off

extern double FUN_80017708();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_8002f6ac();
extern char fn_8004B394();
extern undefined4 FUN_80046cd0();
extern undefined4 FUN_80061a80();
extern undefined4 FUN_800d9a98();
extern undefined4 FUN_800d9b7c();
extern undefined4 FUN_800d9de0();
extern undefined4 FUN_800da594();
extern undefined4 FUN_800da5e8();
extern undefined4 FUN_800da850();
extern undefined4 FUN_800da860();
extern short FUN_800daa04();
extern uint FUN_800daf38();
extern ushort FUN_800db110();
extern int FUN_800db2f0();
extern undefined4 FUN_800db47c();
extern ushort FUN_800db690();
extern undefined4 FUN_80139800();
extern undefined4 FUN_80139910();
extern undefined4 FUN_80139a48();
extern undefined4 FUN_80139a4c();
extern int FUN_80139e1c();
extern void fn_8013AD50();
extern undefined4 FUN_8013a144();
extern undefined4 trickyFn_8013d8f0();
extern undefined4 FUN_80146f9c();
extern undefined4 FUN_80146fa0();
extern undefined8 FUN_80286828();
extern undefined4 FUN_80286874();
extern double FUN_80293900();
extern undefined4 SUB41();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd728;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3070;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e30ac;
extern f32 FLOAT_803e30b0;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d8;
extern f32 FLOAT_803e30f8;
extern f32 FLOAT_803e30fc;
extern f32 FLOAT_803e3114;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e311c;
extern f32 FLOAT_803e3120;
extern f32 FLOAT_803e3124;
extern f32 FLOAT_803e3128;
extern f32 FLOAT_803e312c;
extern f32 FLOAT_803e3130;
extern f32 FLOAT_803e3134;
extern f32 FLOAT_803e3138;
extern f32 FLOAT_803e313c;
extern f32 FLOAT_803e3140;
extern f32 FLOAT_803e3144;
extern f32 FLOAT_803e3148;
extern f32 FLOAT_803e314c;
extern f32 FLOAT_803e3150;

extern f32 timeDelta;
extern f32 oneOverTimeDelta;

extern f32 lbl_803E23DC;  /*  0.0f  */
extern f32 lbl_803E23F4;  /* -0.01f */
extern f32 lbl_803E241C;  /* -0.15f */
extern f32 lbl_803E2420;  /*  0.05f */
extern f32 lbl_803E243C;  /*  0.02f */
extern f32 lbl_803E2488;  /*  5.0f  */
extern f32 lbl_803E248C;  /*  3.0f  */

extern f32 getXZDistance(f32 *a, f32 *b);
extern void mathFn_80021ac8(void *params, void *outVec);
extern f32 sqrtf(f32 x);

extern f32 lbl_803E23E0;
extern f32 lbl_803E23E8;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F8;
extern f32 lbl_803E2440;
extern f32 lbl_803E2448;
extern f32 lbl_803E2468;
extern f32 lbl_803E246C;
extern f32 lbl_803E2484;
extern f32 lbl_803E2490;
extern f32 lbl_803E2494;
extern f32 lbl_803E2498;
extern f32 lbl_803E249C;
extern f32 lbl_803E24A0;
extern f32 lbl_803E24A4;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24AC;
extern f32 lbl_803E24B0;
extern f32 lbl_803E24B4;
extern f32 lbl_803E24B8;
extern f32 lbl_803E24BC;
extern f32 lbl_803E24C0;

extern char lbl_8031D2E8[];
extern u8 *gPathControlInterface;

extern int isInWalkGroupOrPatch(f32 *pos);
extern void ObjHits_SyncObjectPosition(u8 *obj);
extern u32 Objfsa_GetWalkGroupIndexAtPoint(f32 *pos, void *info);
extern int getPatchGroup(f32 *pos, int patchGroup);
extern void walkPath_writeU16LE(int pathId, u8 *out);
extern int trickyDebugPrint(const char *fmt, ...);
extern void trickyReportError(const char *fmt, ...);
extern s16 walkGroupFn_800db3e4(f32 *pos, f32 *target, int walkGroup);
extern u16 Objfsa_GetPatchGroupIdAtPoint(void *pos);
extern void fn_800DB240(void *pos, void *out, u32 patch);
extern int isPointWithinPatchGroup(f32 *pos, int walkGroup, u32 patch);
extern void trickyUpdateApproachSpeed(u8 *obj, f32 baseRadius, u8 *state, f32 *targetPos, u8 flag);
extern int trickyMove(u8 *obj, void *moveState);
extern void trickyRankLinkedRouteCandidates(u8 *obj, u8 *flags, int walkGroup, int *routes);
extern int trickyFindReachableRouteIndex(u8 *state, int *routes, u8 *flags, u16 group);
extern u8 *trickySelectRouteEntry(u8 *state, void *route, u8 dir);
extern void fn_800DA980(void *route, void *fromNode, void *toNode);
extern void RomCurve_stepClamped(void *route, f32 step);
extern s16 getAngle(f32 x, f32 z);
extern u32 GameBit_Get(int bit);
extern void trickyAdvanceRouteTargetAhead(u8 *obj, void *route, f32 speed);
extern u32 randomGetRange(int min, int max);
extern void objAnimFn_8013a3f0(u8 *obj, int animId, f32 speed, int flags);
extern void curveFn_800da23c(void *route);
extern void fn_800D9F38(void *route);
extern void fn_800D9EE8(void *route);
extern void fn_8004B31C(void *search, u32 route, void *target, int pathId, u32 dir);
extern int fn_8004B218(void *search, int timeout);
extern void trickyTurnTowardYaw(u8 *obj, int yaw);
extern void ObjAnim_SampleRootCurvePhase(u8 *obj, f32 speed, u8 *animState);
extern void objHitDetectFn_80062e84(u8 *obj, int a, int b);

/*
 * --INFO--
 *
 * Function: trickyFn_8013b368
 * EN v1.0 Address: 0x8013B368
 * EN v1.0 Size: 8764b
 * EN v1.1 Address: 0x8013B6F0
 * EN v1.1 Size: 8764b
 */
int trickyFn_8013b368(u8 *obj, u8 *state, f32 vel)
{
    u8 moved;
    int wg;
    char *strs = (char *)lbl_8031D2E8;
    u32 tp;
    u8 *target;
    int targetWg;
    u8 slot;
    u16 pp;
    u32 trickyPatch;
    u32 prod;
    u32 dir;
    int i;
    u8 *node;
    u8 *prevNode;
    int d;
    s16 link;
    u16 ulink;
    s16 yawA;
    u16 yawB;
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
    u8 pair[2];
    u8 routeFlags[8];
    struct {
        s16 yaw;
        s16 b;
        s16 c;
    } rot;
    f32 delta[3];
    struct {
        u8 pad;
        u8 mask;
        u16 patch[5];
    } wgi;
    int routePtrs[9];

    moved = 1;
    if ((*(u8 *)(state + 9) < 5) && (isInWalkGroupOrPatch((f32 *)(obj + 0x18)) == 0)) {
        ((void (*)(u8 *, u8 *))*(void **)(*(int *)gPathControlInterface + 0x20))(obj, state + 0xf8);
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xe0);
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 0xe4);
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0xe8);
        *(f32 *)(obj + 0x18) = *(f32 *)(state + 0xe0);
        *(f32 *)(obj + 0x1c) = *(f32 *)(state + 0xe4);
        *(f32 *)(obj + 0x20) = *(f32 *)(state + 0xe8);
        ObjHits_SyncObjectPosition(obj);
    }
    target = *(u8 **)(state + 0x28);
    wg = Objfsa_GetWalkGroupIndexAtPoint((f32 *)(obj + 0x18), 0);
    if ((wg != 0) && (*(u16 *)(state + 0xd0) != wg)) {
        *(u16 *)(state + 0xd0) = wg;
        {
            register u32 m;
            register u32 v;
            register u8 *st = state;
            asm {
                lwz v, 0x54(st)
                li m, -0x401
                and m, v, m
                stw m, 0x54(st)
            }
        }
        *(u16 *)(state + 0x98) = 0;
        *(u16 *)(state + 0x9a) = 0;
        *(u16 *)(state + 0x9c) = 0;
        *(u16 *)(state + 0x9e) = 0;
    }
    targetWg = Objfsa_GetWalkGroupIndexAtPoint((f32 *)target, &wgi);
    if (((wg != 0) && (targetWg == 0)) &&
        ((ulink = getPatchGroup((f32 *)target, wg)) != 0)) {
        walkPath_writeU16LE(ulink, pair);
        if (pair[0] == wg) {
            targetWg = pair[1];
        } else {
            targetWg = pair[0];
        }
    }
    if ((targetWg != 0) && (targetWg != *(u16 *)(state + 0x532))) {
        *(u16 *)(state + 0x532) = targetWg;
    }
    *(u16 *)(state + 0x534) = *(u16 *)(state + 0x532);
    trickyDebugPrint(strs + 0x1e8, *(u16 *)(state + 0xd0), wg, targetWg, *(u16 *)(state + 0x532));
    if (*(u16 *)(state + 0xd0) == 0) {
        trickyReportError(strs + 0x214, *(f32 *)(obj + 0x18), *(f32 *)(obj + 0x1c),
                          *(f32 *)(obj + 0x20));
    }
    velBefore = *(f32 *)(state + 0x14);
    trickyUpdateApproachSpeed(obj, vel, state, (f32 *)target, 0);
    trickyDebugPrint(strs + 0x268, velBefore, *(f32 *)(state + 0x14));
    if (targetWg == *(u16 *)(state + 0xd0)) {
        *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) | 0x400;
        i = 0;
        mask = 1;
        for (; i < 4; i++) {
            if (wgi.mask & mask) {
                *(s16 *)(state + 0x98 + i * 2) = wgi.patch[i];
                *(f32 *)(state + 0xa0 + i * 0xc) = *(f32 *)target;
                *(f32 *)(state + 0xa4 + i * 0xc) = *(f32 *)(target + 4);
                *(f32 *)(state + 0xa8 + i * 0xc) = *(f32 *)(target + 8);
            }
            mask = mask << 1;
        }
    }
    if ((targetWg != 0) && (targetWg == *(u16 *)(state + 0xd0))) {
        *(s16 *)(state + 0xd2) = 0;
    } else {
        prod = targetWg * *(u16 *)(state + 0xd0) & 0xffff;
        if (prod != 0) {
            for (i = 0; i < 4; i++) {
                if ((prod == wgi.patch[i]) && ((wgi.mask & (1 << i)) != 0)) {
                    *(s16 *)(state + 0xd2) = prod;
                    *(f32 *)(state + 0xd4) = *(f32 *)target;
                    *(f32 *)(state + 0xd8) = *(f32 *)(target + 4);
                    *(f32 *)(state + 0xdc) = *(f32 *)(target + 8);
                }
            }
        }
    }
    if (isInWalkGroupOrPatch((f32 *)target) == 0) {
        trickyDebugPrint(strs + 0x2b0);
    } else {
        trickyDebugPrint(strs + 0x284);
    }
    link = getPatchGroup((f32 *)target, *(u16 *)(state + 0xd0));
    trickyDebugPrint(strs + 0x2e4, link);
    if ((*(u32 *)(state + 0x54) & 0x400) != 0) {
        for (i = 0; i < 4; i++) {
            if (*(s16 *)(state + 0x98 + i * 2) != 0) {
                trickyDebugPrint(strs + 0x308, i, *(f32 *)(state + 0xa0 + i * 0xc),
                                 *(f32 *)(state + 0xa4 + i * 0xc), *(f32 *)(state + 0xa8 + i * 0xc));
            }
        }
    }
    if (*(s16 *)(state + 0xd2) != 0) {
        trickyDebugPrint(strs + 0x328, *(f32 *)(state + 0xd4), *(f32 *)(state + 0xd8),
                         *(f32 *)(state + 0xdc));
    }
    tp = getPatchGroup((f32 *)target, *(u16 *)(state + 0xd0)) & 0xffff;
    trickyPatch = getPatchGroup((f32 *)(obj + 0x18), *(u16 *)(state + 0xd0)) & 0xffff;
    if ((targetWg == 0) || (wg != targetWg)) {
        ulink = walkGroupFn_800db3e4((f32 *)(obj + 0x18), (f32 *)target, *(u16 *)(state + 0xd0));
        if (ulink != 0) {
            *(u8 *)(state + 9) = 1;
            if (ulink != *(u16 *)(state + 0xd0)) {
                *(s16 *)(state + 0xd0) = ulink;
                {
                    register u32 m;
                    register u32 v;
                    register u8 *st = state;
                    asm {
                        lwz v, 0x54(st)
                        li m, -0x401
                        and m, v, m
                        stw m, 0x54(st)
                    }
                }
                *(u16 *)(state + 0x98) = 0;
                *(u16 *)(state + 0x9a) = 0;
                *(u16 *)(state + 0x9c) = 0;
                *(u16 *)(state + 0x9e) = 0;
            }
        } else if (*(u8 *)(state + 9) < 5) {
            if (tp != 0) {
                if (targetWg == 0) {
                    if (wg != 0) {
                        for (i = 0; i < 4; i++) {
                            if (*(s16 *)(state + 0x98 + i * 2) == (int)tp) {
                                slot = i;
                                *(u8 *)(state + 9) = 2;
                                break;
                            }
                        }
                        if (i == 4) {
                            if (tp & (u32)!(0xff - *(u16 *)(state + 0x530))) {
                                *(u16 *)(state + 0x532) = (int)(tp & 0xff00) >> 8;
                            } else {
                                *(u16 *)(state + 0x532) = tp & 0xff;
                            }
                            *(u8 *)(state + 9) = 5;
                        }
                    } else {
                        if (trickyPatch != 0) {
                            for (i = 0; i < 4; i++) {
                                if (*(s16 *)(state + 0x98 + i * 2) == (int)trickyPatch) {
                                    trickyPatch = (u16)i;
                                    *(u8 *)(state + 9) = 2;
                                    break;
                                }
                            }
                            if (i == 4) {
                                fn_800DB240(target, state + 0xec, trickyPatch);
                                *(u8 *)(state + 9) = 4;
                            }
                        } else {
                            trickyReportError(strs + 0x344);
                            *(u8 *)(state + 9) = 0;
                        }
                    }
                } else {
                    if (wg != 0) {
                        for (i = 0; i < 4; i++) {
                            if (*(s16 *)(state + 0x98 + i * 2) == (int)tp) {
                                slot = i;
                                *(u8 *)(state + 9) = 2;
                                break;
                            }
                        }
                        if (i == 4) {
                            *(u8 *)(state + 9) = 5;
                        }
                    } else {
                        if (wg == 0) {
                            tp = (u16)getPatchGroup((f32 *)(obj + 0x18), *(u16 *)(state + 0xd0));
                            if (tp != 0) {
                                if (*(s16 *)(state + 0xd2) == (int)tp) {
                                    *(u8 *)(state + 9) = 3;
                                } else {
                                    fn_800DB240(target, state + 0xec, tp);
                                    *(u8 *)(state + 9) = 4;
                                }
                                goto state_selected;
                            }
                        }
                        pp = (u16)tp;
                        i = isPointWithinPatchGroup((f32 *)(obj + 0x18), *(u16 *)(state + 0xd0),
                                                    pp);
                        trickyReportError(strs + 0x374, pp, targetWg, wg, *(u16 *)(state + 0xd0),
                                          i);
                        *(u8 *)(state + 9) = 0;
                    }
                }
            } else {
                if (targetWg == 0) {
                    if (wg != 0) {
                        u16 pid = Objfsa_GetPatchGroupIdAtPoint(target);
                        if (pid == 0) {
                            *(u8 *)(state + 9) = 0;
                        } else {
                            *(u16 *)(state + 0x532) = pid & 0xff;
                            *(u8 *)(state + 9) = 5;
                        }
                    } else {
                        *(u8 *)(state + 9) = 0;
                    }
                } else {
                    if (wg != 0) {
                        targetWg = targetWg * wg & 0xffff;
                        if (isPointWithinPatchGroup((f32 *)(obj + 0x18), *(u16 *)(state + 0xd0),
                                                    targetWg) != 0) {
                            if (*(s16 *)(state + 0xd2) == (int)targetWg) {
                                *(u8 *)(state + 9) = 3;
                            } else {
                                *(u8 *)(state + 9) = 5;
                            }
                        } else {
                            for (i = 0; i < 4; i++) {
                                if (*(s16 *)(state + 0x98 + i * 2) == (int)targetWg) {
                                    slot = i;
                                    *(u8 *)(state + 9) = 2;
                                    break;
                                }
                            }
                            if ((i == 4) || (targetWg != *(s16 *)(state + 0xd2))) {
                                *(u8 *)(state + 9) = 5;
                            }
                        }
                    } else {
                        u32 p = (u16)getPatchGroup((f32 *)(obj + 0x18), *(u16 *)(state + 0xd0));
                        if (p == 0) {
                            trickyReportError(strs + 0x3ec);
                            *(u8 *)(state + 9) = 0;
                        } else if (targetWg == *(u16 *)(state + 0xd0)) {
                            for (i = 0; i < 4; i++) {
                                if (*(s16 *)(state + 0x98 + i * 2) == (int)p) {
                                    slot = i;
                                    *(u8 *)(state + 9) = 2;
                                    break;
                                }
                            }
                            if (i == 4) {
                                fn_800DB240(target, state + 0xec, p);
                                *(u8 *)(state + 9) = 4;
                            }
                        } else if (*(s16 *)(state + 0xd2) == (int)p) {
                            *(u8 *)(state + 9) = 3;
                        } else {
                            fn_800DB240(target, state + 0xec, p);
                            *(u8 *)(state + 9) = 4;
                        }
                    }
                }
            }
        }
    } else {
        *(u8 *)(state + 9) = 1;
    }
state_selected:
    if (*(u8 *)(state + 9) < 5) {
        {
            register u32 m;
            register u32 v;
            register u8 *st = state;
            asm {
                lwz v, 0x54(st)
                li m, -0x2001
                and m, v, m
                stw m, 0x54(st)
            }
        }
    }
    trickyDebugPrint(strs + 0x404, *(u8 *)(state + 9));
    switch (*(u8 *)(state + 9)) {
    case 0:
        trickyDebugPrint(strs + 0x41c);
        v = lbl_803E241C * timeDelta + velBefore;
        if (v < lbl_803E23DC) {
            v = lbl_803E23DC;
        }
        *(f32 *)(state + 0x14) = v;
        if (lbl_803E23DC == *(f32 *)(state + 0x14)) {
            moved = 0;
        } else {
            moved = trickyMove(obj, target);
        }
        break;
    case 1:
        trickyDebugPrint(strs + 0x428);
        moved = trickyMove(obj, target);
        break;
    case 2:
        trickyDebugPrint(strs + 0x434);
        *(f32 *)(state + 0x14) = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E23DC, state, (f32 *)(state + slot * 0xc + 0xa0), 1);
        moved = trickyMove(obj, state + slot * 0xc + 0xa0);
        break;
    case 3:
        trickyDebugPrint(strs + 0x45c);
        *(f32 *)(state + 0x14) = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, (f32 *)(state + 0xd4), 1);
        moved = trickyMove(obj, state + 0xd4);
        break;
    case 4:
        trickyDebugPrint(strs + 0x448);
        *(f32 *)(state + 0x14) = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, (f32 *)(state + 0xec), 1);
        moved = trickyMove(obj, state + 0xec);
        break;
    case 6:
        dist = getXZDistance((f32 *)(*(int *)(state + 0x418) + 8), (f32 *)(obj + 0x18));
        trickyDebugPrint(strs + 0x46c, 10, (int)dist);
        dist = getXZDistance((f32 *)(*(int *)(state + 0x418) + 8), (f32 *)(obj + 0x18));
        if (lbl_803E23E0 > dist) {
            *(u32 *)(state + 0x4a0) = *(u8 *)(state + 0x41c);
            prevNode = *(u8 **)(state + 0x418);
            node = trickySelectRouteEntry(state, prevNode, *(u8 *)(state + 0x41c));
            if (node == 0) {
                *(u8 *)(state + 9) = 0;
            } else {
                if (trickySelectRouteEntry(state, node, *(u8 *)(state + 0x41c)) == 0) {
                    *(u8 *)(state + 9) = 0;
                } else {
                    fn_800DA980(state + 0x420, prevNode, node);
                    RomCurve_stepClamped(state + 0x420, lbl_803E2484);
                    yawA = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(obj + 0xc),
                                    *(f32 *)(state + 0x94) - *(f32 *)(obj + 0x14));
                    yawB = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(state + 0x488),
                                    *(f32 *)(state + 0x94) - *(f32 *)(state + 0x490));
                    diff = yawA - yawB;
                    if (0x8000 < diff) {
                        diff = diff - 0xffff;
                    }
                    if (diff < -0x8000) {
                        diff = diff + 0xffff;
                    }
                    if (diff < 0x4001) {
                        if (diff < -0x4000) {
                            diff = diff - 0x8000;
                        }
                    } else {
                        diff = diff - 0x8000;
                    }
                    d = diff;
                    if (d < 0) {
                        d = -d;
                    }
                    if (0x1000 < d) {
                        *(f32 *)(state + 0x14) = velBefore;
                        trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32 *)(state + 0x488), 1);
                    }
                    trickyAdvanceRouteTargetAhead(obj, state + 0x420, *(f32 *)(state + 0x14));
                    moved = trickyMove(obj, state + 0x488);
                    switch (*(s8 *)(prevNode + 0x1a)) {
                    case 1:
                        *(f32 *)(state + 0x2c) =
                            *(f32 *)(*(int *)(state + 0x4c0) + 8) - *(f32 *)(obj + 0x18);
                        *(f32 *)(state + 0x30) =
                            *(f32 *)(*(int *)(state + 0x4c0) + 0x10) - *(f32 *)(obj + 0x20);
                        len = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) +
                                    *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                        if (lbl_803E23DC != len) {
                            *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / len;
                            *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / len;
                        }
                        *(f32 *)(state + 0x14) = lbl_803E248C;
                        objAnimFn_8013a3f0(obj, 0x15, lbl_803E2468, 0x4000000);
                        *(u8 *)(state + 9) = 9;
                        *(f32 *)(state + 0x7a0) = lbl_803E2440;
                        break;
                    case 5:
                        *(f32 *)(state + 0x2c) =
                            *(f32 *)(*(int *)(state + 0x4c0) + 8) - *(f32 *)(obj + 0x18);
                        *(f32 *)(state + 0x30) =
                            *(f32 *)(*(int *)(state + 0x4c0) + 0x10) - *(f32 *)(obj + 0x20);
                        len = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) +
                                    *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                        if (lbl_803E23DC != len) {
                            *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / len;
                            *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / len;
                        }
                        if (randomGetRange(0, 1) == 0) {
                            objAnimFn_8013a3f0(obj, 0x18, lbl_803E2494, 0x40000c0);
                        } else {
                            objAnimFn_8013a3f0(obj, 0x17, lbl_803E2490, 0x40000c0);
                        }
                        *(f32 *)(state + 0x48) =
                            (*(f32 *)(*(int *)(state + 0x4c0) + 0xc) - *(f32 *)(obj + 0x1c)) /
                            lbl_803E2498;
                        *(u8 *)(state + 9) = 0xc;
                        if (*(int *)(state + 0x4a0) != 0) {
                            while (*(int *)(state + 0x430) != 0) {
                                RomCurve_stepClamped(state + 0x420, lbl_803E2448);
                            }
                        } else {
                            while (*(int *)(state + 0x430) == 0) {
                                RomCurve_stepClamped(state + 0x420, lbl_803E23F8);
                            }
                        }
                        *(f32 *)(state + 0x7a0) = lbl_803E2440;
                        break;
                    case 6:
                        *(f32 *)(state + 0x2c) =
                            *(f32 *)(*(int *)(state + 0x4c0) + 8) - *(f32 *)(obj + 0x18);
                        *(f32 *)(state + 0x30) =
                            *(f32 *)(*(int *)(state + 0x4c0) + 0x10) - *(f32 *)(obj + 0x20);
                        len = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) +
                                    *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                        if (lbl_803E23DC != len) {
                            *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / len;
                            *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / len;
                        }
                        objAnimFn_8013a3f0(obj, 0x19, lbl_803E249C, 0x40000c0);
                        *(f32 *)(state + 0x48) =
                            (*(f32 *)(obj + 0x1c) - *(f32 *)(*(int *)(state + 0x4c0) + 0xc)) /
                            lbl_803E24A0;
                        *(u8 *)(state + 9) = 0xe;
                        if (*(int *)(state + 0x4a0) != 0) {
                            while (*(int *)(state + 0x430) != 0) {
                                RomCurve_stepClamped(state + 0x420, lbl_803E2448);
                            }
                        } else {
                            while (*(int *)(state + 0x430) == 0) {
                                RomCurve_stepClamped(state + 0x420, lbl_803E23F8);
                            }
                        }
                        *(f32 *)(state + 0x7a0) = lbl_803E2440;
                        break;
                    case 2:
                    case 7:
                        *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) | 0x2000;
                    default:
                        *(u8 *)(state + 9) = 7;
                    }
                }
            }
        } else {
            node = *(u8 **)(state + 0x418);
            if (node == 0) {
                node = 0;
            } else if (((*(s16 *)(node + 0x30) != -1) &&
                        (GameBit_Get(*(s16 *)(node + 0x30)) == 0)) ||
                       ((*(s16 *)(node + 0x32) != -1 &&
                         (GameBit_Get(*(s16 *)(node + 0x32)) != 0)))) {
                node = 0;
            }
            if ((node == 0) && (wg != 0)) {
                *(u8 *)(state + 9) = 0;
            } else {
                *(f32 *)(state + 0x14) = velBefore;
                trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32 *)(*(int *)(state + 0x418) + 8), 1);
                moved = trickyMove(obj, (u8 *)(*(int *)(state + 0x418) + 8));
            }
        }
        break;
    case 5:
        trickyDebugPrint(strs + 0x480);
        trickyRankLinkedRouteCandidates(obj, routeFlags, (s16)wg, routePtrs);
        i = trickyFindReachableRouteIndex(state, routePtrs, routeFlags, *(u16 *)(state + 0x532));
        if (i == -1) {
            *(f32 *)(state + 0x14) = velBefore;
            return 2;
        }
        *(u8 *)(state + 0x41c) = routeFlags[i];
        *(int *)(state + 0x418) = routePtrs[i];
        *(f32 *)(state + 0x14) = velBefore;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, (f32 *)(*(int *)(state + 0x418) + 8), 1);
        moved = trickyMove(obj, (u8 *)(*(int *)(state + 0x418) + 8));
        *(u8 *)(state + 9) = 6;
        break;
    case 7:
        trickyDebugPrint(strs + 0x490);
        if ((*(u16 *)(state + 0x534) != 0) && (wg == *(u16 *)(state + 0x534))) {
            v = lbl_803E241C * timeDelta + velBefore;
            if (v < lbl_803E23DC) {
                v = lbl_803E23DC;
            }
            *(f32 *)(state + 0x14) = v;
        }
        node = *(u8 **)(state + 0x4c0);
        if ((*(s8 *)(*(int *)(state + 0x4bc) + 0x1a) != 9) && (*(s8 *)(node + 0x1a) != 9)) {
            f32 *tpos = *(f32 **)(state + 0x28);
            delta[0] = tpos[0] - *(f32 *)(obj + 0x18);
            delta[1] = tpos[1] - *(f32 *)(obj + 0x1c);
            delta[2] = tpos[2] - *(f32 *)(obj + 0x20);
            rot.yaw = -*(s16 *)obj;
            rot.b = 0;
            rot.c = 0;
            mathFn_80021ac8(&rot, delta);
            if ((lbl_803E23DC < delta[2]) && (lbl_803E23DC != *(f32 *)(state + 0x14))) {
                step = 0;
                while ((step < 4) &&
                       ((u16)*(u8 *)(node + step + 4) != *(u16 *)(state + 0x532))) {
                    step = step + 1;
                }
                if (step == 4) {
                    fn_8004B31C(state + 0x538, *(u32 *)(state + 0x4c4), *(void **)(state + 0x28),
                                *(u16 *)(state + 0x532), *(u32 *)(state + 0x4a0));
                    fn_8004B31C(state + 0x568, *(u32 *)(state + 0x4bc), *(void **)(state + 0x28),
                                *(u16 *)(state + 0x532), *(u32 *)(state + 0x4a0) ^ 1);
                    found = 0;
                    step = 0;
                    while ((step = step + 1, step < 100 && (found != 1))) {
                        found = fn_8004B218(state + 0x538, 1);
                        if (found != 1) {
                            found = fn_8004B218(state + 0x568, 1);
                            if (found != 0) {
                                if (found < 0) {
                                    if (-2 < found) {
                                        found = 1;
                                    }
                                } else if (found < 2) {
                                    dir = (*(u32 *)(state + 0x4a0) ^ 1) & 0xff;
                                    if (dir == 0) {
                                        RomCurve_stepClamped(state + 0x420, lbl_803E23F8);
                                    } else {
                                        RomCurve_stepClamped(state + 0x420, lbl_803E2448);
                                    }
                                    *(u32 *)(state + 0x4a0) = dir;
                                    fn_800D9EE8(state + 0x420);
                                }
                            }
                        }
                    }
                }
            }
        }
        dir = *(u32 *)(state + 0x4a0);
        if (((dir == 0) && (*(int *)(state + 0x430) != 0)) ||
            ((dir != 0 && (*(int *)(state + 0x430) == 0)))) {
            node = trickySelectRouteEntry(state, *(void **)(state + 0x4c4), dir & 0xff);
            if (node != 0) {
                curveFn_800da23c(state + 0x420);
                type = *(s8 *)(*(int *)(state + 0x4bc) + 0x1a);
                if ((type == 7) || ((type < 7 && (type == 2)))) {
                    prod = *(u32 *)(state + 0x54);
                    if ((prod & 0x2000) != 0) {
                        register u32 m;
                        register u8 *st = state;
                        register u32 pv = prod;
                        asm {
                            li m, -0x2001
                            and m, pv, m
                            stw m, 0x54(st)
                        }
                    } else {
                        *(u32 *)(state + 0x54) = prod | 0x2000;
                    }
                }
                goto walk_nodes_common;
            }
            *(u8 *)(state + 9) = 0;
        } else {
            node = trickySelectRouteEntry(state, *(void **)(state + 0x4c0), dir & 0xff);
            if (node == 0) {
                *(u8 *)(state + 9) = 0;
            } else {
                if (node != *(u8 **)(state + 0x4c4)) {
                    fn_800D9F38(state + 0x420);
                }
            walk_nodes_common:
                if ((*(u16 *)(state + 0x534) == 0) || (wg != *(u16 *)(state + 0x534))) {
                    yawA = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(obj + 0xc),
                                    *(f32 *)(state + 0x94) - *(f32 *)(obj + 0x14));
                    yawB = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(state + 0x488),
                                    *(f32 *)(state + 0x94) - *(f32 *)(state + 0x490));
                    diff = yawA - yawB;
                    if (0x8000 < diff) {
                        diff = diff - 0xffff;
                    }
                    if (diff < -0x8000) {
                        diff = diff + 0xffff;
                    }
                    if (diff < 0x4001) {
                        if (diff < -0x4000) {
                            diff = diff - 0x8000;
                        }
                    } else {
                        diff = diff - 0x8000;
                    }
                    d = diff;
                    if (d < 0) {
                        d = -d;
                    }
                    if (0x1000 < d) {
                        *(f32 *)(state + 0x14) = velBefore;
                        trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32 *)(state + 0x488), 1);
                    }
                }
                trickyAdvanceRouteTargetAhead(obj, state + 0x420, *(f32 *)(state + 0x14));
                moved = trickyMove(obj, state + 0x488);
                type = *(s8 *)(*(int *)(state + 0x4c0) + 0x1a);
                if (type == 5) {
                    *(u8 *)(state + 9) = 0xb;
                } else if (type < 5) {
                    if (type == 1) {
                        *(u8 *)(state + 9) = 8;
                    }
                } else if (type < 7) {
                    *(u8 *)(state + 9) = 0xd;
                }
            }
        }
        break;
    case 8:
        trickyDebugPrint(strs + 0x49c);
        v = lbl_803E2420 * timeDelta + velBefore;
        if (lbl_803E248C < v) {
            v = lbl_803E248C;
        }
        *(f32 *)(state + 0x14) = v;
        if ((*(u16 *)(state + 0x534) != 0) && (wg == *(u16 *)(state + 0x534))) {
            v = lbl_803E241C * timeDelta + velBefore;
            if (v < lbl_803E23DC) {
                v = lbl_803E23DC;
            }
            *(f32 *)(state + 0x14) = v;
        }
        yawA = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(obj + 0xc),
                        *(f32 *)(state + 0x94) - *(f32 *)(obj + 0x14));
        yawB = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(state + 0x488),
                        *(f32 *)(state + 0x94) - *(f32 *)(state + 0x490));
        diff = yawA - yawB;
        if (0x8000 < diff) {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000) {
            diff = diff + 0xffff;
        }
        if (diff < 0x4001) {
            if (diff < -0x4000) {
                diff = diff - 0x8000;
            }
        } else {
            diff = diff - 0x8000;
        }
        d = diff;
        if (d < 0) {
            d = -d;
        }
        if (0x1000 < d) {
            *(f32 *)(state + 0x14) = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32 *)(state + 0x488), 1);
        }
        trickyAdvanceRouteTargetAhead(obj, state + 0x420, *(f32 *)(state + 0x14));
        trickyMove(obj, state + 0x488);
        dir = *(u32 *)(state + 0x4a0);
        if (((dir == 0) && (*(int *)(state + 0x430) != 0)) ||
            ((dir != 0 && (*(int *)(state + 0x430) == 0)))) {
            node = trickySelectRouteEntry(state, *(void **)(state + 0x4c4), dir & 0xff);
            if (node == 0) {
                *(u8 *)(state + 9) = 0;
            } else {
                curveFn_800da23c(state + 0x420);
                *(f32 *)(state + 0x2c) =
                    *(f32 *)(*(int *)(state + 0x4c0) + 8) - *(f32 *)(obj + 0x18);
                *(f32 *)(state + 0x30) =
                    *(f32 *)(*(int *)(state + 0x4c0) + 0x10) - *(f32 *)(obj + 0x20);
                len = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) +
                            *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                if (lbl_803E23DC != len) {
                    *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / len;
                    *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / len;
                }
                *(f32 *)(state + 0x14) = lbl_803E248C;
                objAnimFn_8013a3f0(obj, 0x15, lbl_803E2468, 0x4000000);
                *(u8 *)(state + 9) = 9;
                *(f32 *)(state + 0x7a0) = lbl_803E2440;
            }
        }
        break;
    case 9:
        trickyDebugPrint(strs + 0x4ac);
        if ((u8)(*(u32 *)(state + 0x54) & 0x10000000)) {
            v = lbl_803E23F4 * timeDelta + velBefore;
            if (v < lbl_803E23DC) {
                v = lbl_803E23DC;
            }
        } else if (velBefore > lbl_803E24A4) {
            v = lbl_803E241C * timeDelta + velBefore;
            if (v < lbl_803E24A4) {
                v = lbl_803E24A4;
            }
        } else {
            v = lbl_803E2420 * timeDelta + velBefore;
            if (lbl_803E24A4 < v) {
                v = lbl_803E24A4;
            }
        }
        *(f32 *)(state + 0x14) = v;
        {
            f32 dx = *(f32 *)(*(int *)(obj + 0xb8) + 0x2c);
            f32 dz = *(f32 *)(*(int *)(obj + 0xb8) + 0x30);
            if (lbl_803E23EC < dx * dx + dz * dz) {
                yawA = getAngle(-dx, -dz);
                trickyTurnTowardYaw(obj, yawA);
            }
        }
        if (lbl_803E24A8 <= *(f32 *)(obj + 0x98)) {
            ObjAnim_SampleRootCurvePhase(obj, *(f32 *)(state + 0x14) * lbl_803E24AC, state + 0x34);
            k = lbl_803E24AC;
            *(f32 *)(obj + 0xc) =
                timeDelta * *(f32 *)(state + 0x2c) * *(f32 *)(state + 0x14) * k +
                *(f32 *)(obj + 0xc);
            *(f32 *)(obj + 0x14) =
                timeDelta * *(f32 *)(state + 0x30) * *(f32 *)(state + 0x14) * k +
                *(f32 *)(obj + 0x14);
        } else {
            ObjAnim_SampleRootCurvePhase(obj, *(f32 *)(state + 0x14), state + 0x34);
            *(f32 *)(obj + 0xc) =
                timeDelta * *(f32 *)(state + 0x2c) * *(f32 *)(state + 0x14) + *(f32 *)(obj + 0xc);
            *(f32 *)(obj + 0x14) =
                timeDelta * *(f32 *)(state + 0x30) * *(f32 *)(state + 0x14) + *(f32 *)(obj + 0x14);
        }
        if ((*(u32 *)(state + 0x54) & 0x8000000) != 0) {
            f32 dx;
            f32 dz;
            node = *(u8 **)(state + 0x4c0);
            dx = *(f32 *)(node + 8) - *(f32 *)(obj + 0x18);
            dz = *(f32 *)(node + 0x10) - *(f32 *)(obj + 0x20);
            len = sqrtf(dx * dx + dz * dz);
            *(f32 *)(state + 0x64) = len / lbl_803E24A4;
            *(f32 *)(state + 0x68) = lbl_803E23DC;
            *(u32 *)(state + 0x74) = *(u32 *)(obj + 0x18);
            *(u32 *)(state + 0x70) = *(u32 *)(obj + 0x1c);
            *(u32 *)(state + 0x78) = *(u32 *)(obj + 0x20);
            *(u32 *)(state + 0x7c) = *(u32 *)(node + 8);
            *(u32 *)(state + 0x80) = *(u32 *)(node + 0x10);
            k = *(f32 *)(state + 0x64);
            *(f32 *)(state + 0x6c) =
                -(lbl_803E24B0 * k * k - (*(f32 *)(node + 0xc) - *(f32 *)(obj + 0x1c))) / k;
            objAnimFn_8013a3f0(obj, 0x16, lbl_803E23DC, 0x4000000);
            *(f32 *)(state + 0x3c) = *(f32 *)(state + 0x68) / *(f32 *)(state + 0x64);
            *(f32 *)(state + 0x14) = lbl_803E24A4;
            *(u8 *)(state + 9) = 10;
            if (*(int *)(state + 0x4a0) != 0) {
                while (*(int *)(state + 0x430) != 0) {
                    RomCurve_stepClamped(state + 0x420, lbl_803E2448);
                }
            } else {
                while (*(int *)(state + 0x430) == 0) {
                    RomCurve_stepClamped(state + 0x420, lbl_803E23F8);
                }
            }
        }
        break;
    case 10:
        trickyDebugPrint(strs + 0x4b8);
        *(f32 *)(state + 0x68) = *(f32 *)(state + 0x68) + timeDelta;
        if (*(f32 *)(state + 0x68) < *(f32 *)(state + 0x64)) {
            *(f32 *)(obj + 0xc) =
                (*(f32 *)(state + 0x7c) - *(f32 *)(state + 0x74)) *
                    (*(f32 *)(state + 0x68) / *(f32 *)(state + 0x64)) +
                *(f32 *)(state + 0x74);
            k = *(f32 *)(state + 0x68);
            *(f32 *)(obj + 0x10) =
                lbl_803E24B0 * k * k + *(f32 *)(state + 0x6c) * k + *(f32 *)(state + 0x70);
            *(f32 *)(obj + 0x14) =
                (*(f32 *)(state + 0x80) - *(f32 *)(state + 0x78)) *
                    (*(f32 *)(state + 0x68) / *(f32 *)(state + 0x64)) +
                *(f32 *)(state + 0x78);
            v = *(f32 *)(state + 0x64);
            if (lbl_803E24B4 < v) {
                k = *(f32 *)(state + 0x68);
                if (lbl_803E24B8 < k) {
                    if (k < v - lbl_803E24B8) {
                        *(f32 *)(state + 0x3c) =
                            ((k - lbl_803E24B8) / (v - lbl_803E24BC)) * lbl_803E24A8 +
                            lbl_803E24AC;
                    } else {
                        *(f32 *)(state + 0x3c) = ((lbl_803E24B4 - v) + k) / lbl_803E24B4;
                    }
                } else {
                    *(f32 *)(state + 0x3c) = k / lbl_803E24B4;
                }
            } else {
                *(f32 *)(state + 0x3c) = *(f32 *)(state + 0x68) / v;
            }
            objHitDetectFn_80062e84(obj, 0, 0);
            *(u8 *)(state + 0x353) = 0;
        } else {
            *(u32 *)(obj + 0x10) = *(u32 *)(*(int *)(state + 0x4c0) + 0xc);
            *(f32 *)(state + 0x3c) = lbl_803E23E8;
            *(u8 *)(state + 9) = 7;
        }
        break;
    case 0xb:
        trickyDebugPrint(strs + 0x4c4);
        v = lbl_803E2420 * timeDelta + velBefore;
        if (lbl_803E248C < v) {
            v = lbl_803E248C;
        }
        *(f32 *)(state + 0x14) = v;
        if ((*(u16 *)(state + 0x534) != 0) && (wg == *(u16 *)(state + 0x534))) {
            v = lbl_803E241C * timeDelta + velBefore;
            if (v < lbl_803E23DC) {
                v = lbl_803E23DC;
            }
            *(f32 *)(state + 0x14) = v;
        }
        yawA = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(obj + 0xc),
                        *(f32 *)(state + 0x94) - *(f32 *)(obj + 0x14));
        yawB = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(state + 0x488),
                        *(f32 *)(state + 0x94) - *(f32 *)(state + 0x490));
        diff = yawA - yawB;
        if (0x8000 < diff) {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000) {
            diff = diff + 0xffff;
        }
        if (diff < 0x4001) {
            if (diff < -0x4000) {
                diff = diff - 0x8000;
            }
        } else {
            diff = diff - 0x8000;
        }
        d = diff;
        if (d < 0) {
            d = -d;
        }
        if (0x1000 < d) {
            *(f32 *)(state + 0x14) = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32 *)(state + 0x488), 1);
        }
        trickyAdvanceRouteTargetAhead(obj, state + 0x420, *(f32 *)(state + 0x14));
        trickyMove(obj, state + 0x488);
        dir = *(u32 *)(state + 0x4a0);
        if (((dir == 0) && (*(int *)(state + 0x430) != 0)) ||
            ((dir != 0 && (*(int *)(state + 0x430) == 0)))) {
            node = trickySelectRouteEntry(state, *(void **)(state + 0x4c4), dir & 0xff);
            if (node == 0) {
                *(u8 *)(state + 9) = 0;
            } else {
                curveFn_800da23c(state + 0x420);
                *(f32 *)(state + 0x2c) =
                    *(f32 *)(*(int *)(state + 0x4c0) + 8) - *(f32 *)(obj + 0x18);
                *(f32 *)(state + 0x30) =
                    *(f32 *)(*(int *)(state + 0x4c0) + 0x10) - *(f32 *)(obj + 0x20);
                len = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) +
                            *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                if (lbl_803E23DC != len) {
                    *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / len;
                    *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / len;
                }
                if (randomGetRange(0, 1) == 0) {
                    objAnimFn_8013a3f0(obj, 0x18, lbl_803E2494, 0x40000c0);
                } else {
                    objAnimFn_8013a3f0(obj, 0x17, lbl_803E2490, 0x40000c0);
                }
                *(f32 *)(state + 0x48) =
                    (*(f32 *)(*(int *)(state + 0x4c0) + 0xc) - *(f32 *)(obj + 0x1c)) /
                    lbl_803E2498;
                *(u8 *)(state + 9) = 0xc;
                if (*(int *)(state + 0x4a0) != 0) {
                    while (*(int *)(state + 0x430) != 0) {
                        RomCurve_stepClamped(state + 0x420, lbl_803E2448);
                    }
                } else {
                    while (*(int *)(state + 0x430) == 0) {
                        RomCurve_stepClamped(state + 0x420, lbl_803E23F8);
                    }
                }
                *(f32 *)(state + 0x7a0) = lbl_803E2440;
            }
        }
        break;
    case 0xc:
    case 0xe:
        trickyDebugPrint(strs + 0x4d4);
        *(u8 *)(state + 0x353) = 0;
        trickyAdvanceRouteTargetAhead(obj, state + 0x420, *(f32 *)(state + 0x14));
        {
            f32 dx = *(f32 *)(*(int *)(obj + 0xb8) + 0x2c);
            f32 dz = *(f32 *)(*(int *)(obj + 0xb8) + 0x30);
            if (lbl_803E23EC < dx * dx + dz * dz) {
                yawA = getAngle(-dx, -dz);
                trickyTurnTowardYaw(obj, yawA);
            }
        }
        if ((*(u32 *)(state + 0x54) & 0x8000000) != 0) {
            *(f32 *)(state + 0x14) = lbl_803E24C0;
            trickyMove(obj, state + 0x488);
            *(u8 *)(state + 9) = 7;
        }
        break;
    case 0xd:
        trickyDebugPrint(strs + 0x4e8);
        v = lbl_803E2420 * timeDelta + velBefore;
        if (lbl_803E248C < v) {
            v = lbl_803E248C;
        }
        *(f32 *)(state + 0x14) = v;
        if ((*(u16 *)(state + 0x534) != 0) && (wg == *(u16 *)(state + 0x534))) {
            v = lbl_803E241C * timeDelta + velBefore;
            if (v < lbl_803E23DC) {
                v = lbl_803E23DC;
            }
            *(f32 *)(state + 0x14) = v;
        }
        yawA = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(obj + 0xc),
                        *(f32 *)(state + 0x94) - *(f32 *)(obj + 0x14));
        yawB = getAngle(*(f32 *)(state + 0x8c) - *(f32 *)(state + 0x488),
                        *(f32 *)(state + 0x94) - *(f32 *)(state + 0x490));
        diff = yawA - yawB;
        if (0x8000 < diff) {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000) {
            diff = diff + 0xffff;
        }
        if (diff < 0x4001) {
            if (diff < -0x4000) {
                diff = diff - 0x8000;
            }
        } else {
            diff = diff - 0x8000;
        }
        d = diff;
        if (d < 0) {
            d = -d;
        }
        if (0x1000 < d) {
            *(f32 *)(state + 0x14) = velBefore;
            trickyUpdateApproachSpeed(obj, lbl_803E246C, state, (f32 *)(state + 0x488), 1);
        }
        trickyAdvanceRouteTargetAhead(obj, state + 0x420, *(f32 *)(state + 0x14));
        trickyMove(obj, state + 0x488);
        dir = *(u32 *)(state + 0x4a0);
        if (((dir == 0) && (*(int *)(state + 0x430) != 0)) ||
            ((dir != 0 && (*(int *)(state + 0x430) == 0)))) {
            node = trickySelectRouteEntry(state, *(void **)(state + 0x4c4), dir & 0xff);
            if (node == 0) {
                *(u8 *)(state + 9) = 0;
            } else {
                curveFn_800da23c(state + 0x420);
                *(f32 *)(state + 0x2c) =
                    *(f32 *)(*(int *)(state + 0x4c0) + 8) - *(f32 *)(obj + 0x18);
                *(f32 *)(state + 0x30) =
                    *(f32 *)(*(int *)(state + 0x4c0) + 0x10) - *(f32 *)(obj + 0x20);
                len = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) +
                            *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                if (lbl_803E23DC != len) {
                    *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / len;
                    *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / len;
                }
                objAnimFn_8013a3f0(obj, 0x19, lbl_803E249C, 0x40000c0);
                *(f32 *)(state + 0x48) =
                    (*(f32 *)(obj + 0x1c) - *(f32 *)(*(int *)(state + 0x4c0) + 0xc)) /
                    lbl_803E24A0;
                *(u8 *)(state + 9) = 0xe;
                if (*(int *)(state + 0x4a0) != 0) {
                    while (*(int *)(state + 0x430) != 0) {
                        RomCurve_stepClamped(state + 0x420, lbl_803E2448);
                    }
                } else {
                    while (*(int *)(state + 0x430) == 0) {
                        RomCurve_stepClamped(state + 0x420, lbl_803E23F8);
                    }
                }
                *(f32 *)(state + 0x7a0) = lbl_803E2440;
            }
        }
        break;
    default:
        trickyDebugPrint(strs + 0x4f8);
    }
    if (*(u8 *)(state + 9) < 5) {
        if (isInWalkGroupOrPatch((f32 *)(obj + 0x18)) != 0) {
            *(f32 *)(state + 0xe0) = *(f32 *)(obj + 0x18);
            *(f32 *)(state + 0xe4) = *(f32 *)(obj + 0x1c);
            *(f32 *)(state + 0xe8) = *(f32 *)(obj + 0x20);
        } else {
            ((void (*)(u8 *, u8 *))*(void **)(*(int *)gPathControlInterface + 0x20))(obj, state + 0xf8);
            *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xe0);
            *(f32 *)(obj + 0x10) = *(f32 *)(state + 0xe4);
            *(f32 *)(obj + 0x14) = *(f32 *)(state + 0xe8);
            *(f32 *)(obj + 0x18) = *(f32 *)(state + 0xe0);
            *(f32 *)(obj + 0x1c) = *(f32 *)(state + 0xe4);
            *(f32 *)(obj + 0x20) = *(f32 *)(state + 0xe8);
            ObjHits_SyncObjectPosition(obj);
        }
    }
    type = *(u8 *)(state + 9);
    if (((((type == 0) || (type == 2)) || (type == 4)) || (type == 3)) &&
        (lbl_803E23DC == *(f32 *)(state + 0x14))) {
        return 2;
    }
    if (moved != 0) {
        return 1;
    }
    return 0;
}

void trickyUpdateApproachSpeed(u8 *obj, f32 baseRadius, u8 *state, f32 *targetPos, u8 flag)
{
    struct {
        s16 a;
        s16 angle;
        s16 c;
    } params;
    f32 delta[3];
    f32 sum;
    f32 v;
    f32 dec;
    f32 thresh;
    f32 distSq;
    f32 dist;
    f32 dx;
    f32 dz;
    f32 vel;
    f32 candidate;
    f32 *otherTarget;
    u8 *ctx;

    sum = lbl_803E2420;
    v = *(f32 *)(state + 0x14);
    dec = lbl_803E241C * timeDelta;
    while (v > lbl_803E23DC) {
        sum = sum + v * timeDelta;
        v = v + dec;
    }
    thresh = baseRadius + sum;
    distSq = thresh * thresh;
    dist = getXZDistance(targetPos, (f32 *)(obj + 0x18));
    if (dist < distSq) {
        candidate = lbl_803E241C * timeDelta + *(f32 *)(state + 0x14);
        if (candidate < lbl_803E23DC) {
            candidate = lbl_803E23DC;
        }
        *(f32 *)(state + 0x14) = candidate;
        return;
    }
    if (flag != 0) {
        delta[0] = *(f32 *)(targetPos + 0) - *(f32 *)(obj + 0x18);
        delta[1] = *(f32 *)(targetPos + 1) - *(f32 *)(obj + 0x1c);
        delta[2] = *(f32 *)(targetPos + 2) - *(f32 *)(obj + 0x20);
        params.a = -*(s16 *)(obj + 0x0);
        params.angle = 0;
        params.c = 0;
        mathFn_80021ac8(&params, delta);
        if (delta[2] > lbl_803E23DC) {
            candidate = lbl_803E241C * timeDelta + *(f32 *)(state + 0x14);
            if (candidate < lbl_803E23DC) {
                candidate = lbl_803E23DC;
            }
            *(f32 *)(state + 0x14) = candidate;
            return;
        }
    }
    if ((*(u32 *)(state + 0x54) & 0x10000000) != 0) {
        *(f32 *)(state + 0x14) =
            lbl_803E23F4 * timeDelta + *(f32 *)(state + 0x14);
        if (*(f32 *)(state + 0x14) < lbl_803E23DC) {
            *(f32 *)(state + 0x14) = lbl_803E23DC;
        }
        return;
    }
    {
        f32 deltaSpeed = lbl_803E2488 + thresh;
        f32 deltaSpeedSq = deltaSpeed * deltaSpeed;
        ctx = *(u8 **)(obj + 0xb8);
        otherTarget = *(f32 **)(ctx + 0x28);
        if (otherTarget == *(f32 **)(ctx + 0x6f0)) {
            dx = *(f32 *)(ctx + 0x6f4) - *(f32 *)(obj + 0x18);
            dz = *(f32 *)(ctx + 0x6fc) - *(f32 *)(obj + 0x20);
            vel = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
            dx = *(f32 *)((u8 *)otherTarget + 0) - *(f32 *)(obj + 0x18);
            dz = *(f32 *)((u8 *)otherTarget + 8) - *(f32 *)(obj + 0x20);
            {
                f32 distOther = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
                candidate = distOther - vel;
            }
        } else {
            candidate = lbl_803E23DC;
        }
        if (dist < deltaSpeedSq) {
            if (candidate > lbl_803E23DC) {
                if (candidate < *(f32 *)(state + 0x14)) {
                    f32 step = lbl_803E241C * timeDelta + *(f32 *)(state + 0x14);
                    if (step < candidate) {
                        step = candidate;
                    }
                    *(f32 *)(state + 0x14) = step;
                    return;
                } else {
                    f32 step;
                    if (candidate > lbl_803E248C) {
                        step = lbl_803E2420 * timeDelta + *(f32 *)(state + 0x14);
                        if (step > lbl_803E248C) {
                            step = lbl_803E248C;
                        }
                        *(f32 *)(state + 0x14) = step;
                        return;
                    }
                    step = lbl_803E2420 * timeDelta + *(f32 *)(state + 0x14);
                    if (step > candidate) {
                        step = candidate;
                    }
                    *(f32 *)(state + 0x14) = step;
                    return;
                }
            }
        }
    }
    if ((*(u32 *)(state + 0x54) & 0x00100000) != 0) {
        *(f32 *)(state + 0x14) =
            lbl_803E243C * timeDelta + *(f32 *)(state + 0x14);
        if (*(f32 *)(state + 0x14) > lbl_803E248C) {
            *(f32 *)(state + 0x14) = lbl_803E248C;
        }
        return;
    }
    {
        f32 step = lbl_803E2420 * timeDelta + *(f32 *)(state + 0x14);
        if (step > lbl_803E248C) {
            step = lbl_803E248C;
        }
        *(f32 *)(state + 0x14) = step;
    }
}
