#include "ghidra_import.h"
#include "main/dll/cannon.h"

#define TRICKY_STATE_FLAGS_OFFSET 0x54
#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400
#define TRICKY_STATE_RESET_FLAG_10 0x00000010
#define TRICKY_STATE_HELPERS_ACTIVE_FLAG 0x00000800
#define TRICKY_STATE_HELPERS_FINISHED_FLAG 0x00001000
#define TRICKY_STATE_RESET_FLAG_10000 0x00010000
#define TRICKY_STATE_RESET_FLAG_20000 0x00020000
#define TRICKY_STATE_RESET_FLAG_40000 0x00040000

#define TRICKY_CLEAR_TARGET_DIRTY(st) \
    (*(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_TARGET_DIRTY_FLAG)

#define TRICKY_MARK_HELPERS_FINISHED(st) \
    { \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_HELPERS_ACTIVE_FLAG; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) |= TRICKY_STATE_HELPERS_FINISHED_FLAG; \
    }

#define TRICKY_CLEAR_RESET_FLAGS(st) \
    { \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_10; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_10000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_20000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_40000; \
        *(s8 *)((st) + 0xd) = -1; \
    }

#pragma peephole off

extern bool FUN_800067f0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern double FUN_80017708();
extern int FUN_80017730();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80039468();
extern int FUN_800da5f0();
extern int FUN_800db47c();
extern int Objfsa_GetWalkGroupIndexAtPoint(float *pos, void *flag);
extern f32 getXZDistance(float *a, float *b);
extern undefined4 FUN_80139910();
extern int FUN_80139a48();
extern undefined4 FUN_80139a4c();
extern int trickyFn_8013b368(void *p1, f32 f, void *p2);
extern void trickyFn_8013d8f0(u8 *arg1, u8 *arg2);
extern undefined4 FUN_80146fa0();
extern undefined4 FUN_801778d0();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

int trickyGuardFindBaddieTarget(int p);

extern undefined4* DAT_803dd71c;
extern f32 lbl_803DC074;
extern f32 lbl_803E306C;
extern f32 lbl_803E3074;
extern f32 lbl_803E307C;
extern f32 lbl_803E3084;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30B0;
extern f32 lbl_803E30CC;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E310C;
extern f32 lbl_803E3118;
extern f32 lbl_803E313C;
extern f32 lbl_803E3154;
extern f32 lbl_803E3160;
extern f32 lbl_803E3168;
extern f32 lbl_803E3188;
extern f32 lbl_803E3194;

/* FUN_8013ffb8 removed: in v1.0 this address is the start of trickyGuard. */

/* FUN_8013ffbc removed: duplicate of trickyGuardFindBaddieTarget. */

/* FUN_801400fc removed: duplicate of trickyGuard. */



extern int trickyDebugPrint(const char *fmt, ...);
extern int Objfsa_FindNearestCurveType24(float *pos, int p2, int p3);
extern int trickyUpdateApproachSpeed(int p1, int p2, f32 f, void *target, int p4);
extern int trickyMove(int p1, void *p2);
extern void trickyTurnTowardYaw(int p1, s16 angle);
extern void objAnimFn_8013a3f0(int obj, int p2, f32 f, int p4);
extern void *Obj_AllocObjectSetup(int p1, int p2);
extern int Obj_SetupObject(void *setup, int p2, int p3, int p4, void *p5);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int chan);
extern int Obj_IsLoadingLocked(void);
extern void objSetAnimSpeedTo1(void *obj);
extern void objAudioFn_800393f8(int obj, void *p2, int p3, int p4, int p5, int p6);

extern char lbl_8031D2E8[];
extern void **gRomCurveInterface;
extern f32 timeDelta;
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern int getAngle(f32 x, f32 z);
extern int randomGetRange(int min, int max);
extern f32 getXZDistance(float *a, float *b);
extern void *ObjGroup_GetObjects(int group, int *count);
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F4;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2420;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f64 lbl_803E2460;
extern f32 lbl_803E247C;
extern f32 lbl_803E24C4;
extern f32 lbl_803E24D0;
extern f32 lbl_803E24D8;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E4;
extern f32 lbl_803E2418;
extern f32 lbl_803E2488;
extern f32 lbl_803E24AC;
extern f32 lbl_803E24F8;
extern f32 lbl_803E2504;

/*
 * --INFO--
 *
 * Function: trickyFlame
 * EN v1.0 Address: 0x801409DC
 * EN v1.0 Size: 2224b
 */
#pragma peephole off
#pragma scheduling off
void trickyFlame(int p1, int p2) {
    register char *strBase = lbl_8031D2E8;
    void **slot;
    int i;
    void *setup;
    void *state;
    void *target;
    int dieFlag;
    int newTarget;
    f32 fz;

    switch (*(u8 *)(p2 + 0xa)) {
    case 0:
        trickyDebugPrint(strBase + 0x700);
        *(int *)(p2 + 0x71c) = Objfsa_FindNearestCurveType24((float *)(*(int *)(p2 + 0x24) + 0x18), -1, 4);
        if (*(u8 *)(*(int *)(p2 + 0x71c) + 0x3) != 0) {
            newTarget = *(int *)(p2 + 0x71c) + 0x8;
            if (*(uint *)(p2 + 0x28) != (uint)newTarget) {
                *(int *)(p2 + 0x28) = newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(p2);
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 1;
        } else {
            *(int *)(p2 + 0x720) = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(*(int *)(*(int *)(p2 + 0x71c) + 0x1c));
            newTarget = *(int *)(p2 + 0x720) + 0x8;
            if (*(uint *)(p2 + 0x28) != (uint)newTarget) {
                *(int *)(p2 + 0x28) = newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(p2);
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 3;
        }
        trickyFn_8013b368((void *)p1, lbl_803E2488, (void *)p2);
        break;
    case 3:
        trickyDebugPrint(strBase + 0x70c);
        trickyFn_8013b368((void *)p1, lbl_803E2488, (void *)p2);
        if ((u8)*(u8 *)(*(int *)(p2 + 0x720) + 0x3) == Objfsa_GetWalkGroupIndexAtPoint((float *)(p1 + 0x18), (void *)0x0)) {
            *(u8 *)(p2 + 0x9) = 1;
            *(u8 *)(p2 + 0xa) = 4;
        }
        break;
    case 4:
        trickyDebugPrint(strBase + 0x720);
        target = (void *)(*(int *)(p2 + 0x71c) + 0x8);
        trickyUpdateApproachSpeed(p1, p2, lbl_803E2488, target, 1);
        trickyMove(p1, target);
        if (Objfsa_GetWalkGroupIndexAtPoint((float *)(p1 + 0x18), (void *)0x0) == 0) {
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x10;
            *(u8 *)(p2 + 0xa) = 5;
        }
        break;
    case 5:
        trickyDebugPrint(strBase + 0x734);
        target = (void *)(*(int *)(p2 + 0x71c) + 0x8);
        trickyUpdateApproachSpeed(p1, p2, lbl_803E2488, target, 1);
        if (trickyMove(p1, target) == 0) {
            objAnimFn_8013a3f0(p1, 0x1a, lbl_803E23E4, 0x4000000);
            *(u8 *)(p2 + 0xa) = 7;
            (*(u8 *)*(int *)p2) -= 4;
        }
        break;
    case 7:
        trickyDebugPrint(strBase + 0x744);
        {
            s16 srcAng = (s16)((s8)*(u8 *)(*(int *)(p2 + 0x71c) + 0x2c) << 8);
            s16 delta = (s16)(srcAng - (u16)*(s16 *)p1);
            int absDelta;
            if (delta > 0x8000) {
                delta = (s16)(delta - 0xFFFF);
            }
            if (delta < -0x8000) {
                delta = (s16)(delta + 0xFFFF);
            }
            absDelta = delta;
            if (absDelta >= 0) {
            } else {
                absDelta = -absDelta;
            }
            if (absDelta >= 0x4000) {
                srcAng = (s16)(srcAng + 0x8000);
            }
            trickyTurnTowardYaw(p1, srcAng);
        }
        if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E24AC) {
            if ((*(u32 *)(p2 + 0x54) & 0x800) == 0) {
                if ((u8)Obj_IsLoadingLocked() != 0) {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x800;
                    for (i = 0, slot = (void **)p2; i < 7; i++) {
                        setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                        *(u8 *)((char *)setup + 0x4) = 2;
                        *(u8 *)((char *)setup + 0x5) = 1;
                        *(s16 *)((char *)setup + 0x1a) = (s16)i;
                        slot[0x700 / 4] = (void *)Obj_SetupObject(setup, 5, *(s8 *)(p1 + 0xac), -1, *(void **)(p1 + 0x30));
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
                dieFlag = 1;
            } else {
                int (*cb)(int, int) = *(int (**)(int, int))(p2 + 0x724);
                if (cb != NULL && cb(*(int *)(p2 + 0x24), 1) == 0) {
                    dieFlag = 1;
                } else if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E2504) {
                    TRICKY_MARK_HELPERS_FINISHED(p2);
                    for (i = 0, slot = (void **)p2; i < 7; i++) {
                        objSetAnimSpeedTo1(slot[0x700 / 4]);
                        slot++;
                    }
                    Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
                    state = *(void **)(p1 + 0xb8);
                    if ((((u32)*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                        s16 a0 = *(s16 *)(p1 + 0xa0);
                        if (a0 >= 0x30 || a0 < 0x29) {
                            if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                                objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                            }
                        }
                    }
                    dieFlag = 0;
                } else {
                    dieFlag = 1;
                }
            }
        } else {
            dieFlag = 1;
        }
        if (dieFlag == 0) {
            *(u8 *)(p2 + 0xa) = 8;
            *(f32 *)(p2 + 0x728) = lbl_803E24F8;
        }
        break;
    case 1:
        trickyDebugPrint(strBase + 0x750);
        {
            int r = trickyFn_8013b368((void *)p1, lbl_803E2488, (void *)p2);
            if (r == 0) {
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x10;
                *(u8 *)(p2 + 0xa) = 2;
            } else if (r == 2) {
                *(u8 *)(p2 + 0x8) = 1;
                *(u8 *)(p2 + 0xa) = 0;
                fz = lbl_803E23DC;
                *(f32 *)(p2 + 0x71c) = fz;
                *(f32 *)(p2 + 0x720) = fz;
                TRICKY_CLEAR_RESET_FLAGS(p2);
            }
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x764);
        target = (void *)(*(int *)(p2 + 0x24) + 0x18);
        trickyUpdateApproachSpeed(p1, p2, lbl_803E2418, target, 1);
        if (trickyMove(p1, target) == 0) {
            objAnimFn_8013a3f0(p1, 0x1a, lbl_803E23E4, 0x4000000);
            *(u8 *)(p2 + 0xa) = 6;
            (*(u8 *)*(int *)p2) -= 4;
        }
        break;
    case 6:
        trickyDebugPrint(strBase + 0x778);
        if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E24AC) {
            if ((*(u32 *)(p2 + 0x54) & 0x800) == 0) {
                if ((u8)Obj_IsLoadingLocked() != 0) {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x800;
                    for (i = 0, slot = (void **)p2; i < 7; i++) {
                        setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                        *(u8 *)((char *)setup + 0x4) = 2;
                        *(u8 *)((char *)setup + 0x5) = 1;
                        *(s16 *)((char *)setup + 0x1a) = (s16)i;
                        slot[0x700 / 4] = (void *)Obj_SetupObject(setup, 5, *(s8 *)(p1 + 0xac), -1, *(void **)(p1 + 0x30));
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
                dieFlag = 1;
            } else {
                int (*cb)(int, int) = *(int (**)(int, int))(p2 + 0x724);
                if (cb != NULL && cb(*(int *)(p2 + 0x24), 1) == 0) {
                    dieFlag = 1;
                } else if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E2504) {
                    TRICKY_MARK_HELPERS_FINISHED(p2);
                    for (i = 0, slot = (void **)p2; i < 7; i++) {
                        objSetAnimSpeedTo1(slot[0x700 / 4]);
                        slot++;
                    }
                    Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
                    state = *(void **)(p1 + 0xb8);
                    if ((((u32)*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                        s16 a0 = *(s16 *)(p1 + 0xa0);
                        if (a0 >= 0x30 || a0 < 0x29) {
                            if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                                objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                            }
                        }
                    }
                    dieFlag = 0;
                } else {
                    dieFlag = 1;
                }
            }
        } else {
            dieFlag = 1;
        }
        if (dieFlag == 0) {
            *(u8 *)(p2 + 0x8) = 1;
            *(u8 *)(p2 + 0xa) = 0;
            fz = lbl_803E23DC;
            *(f32 *)(p2 + 0x71c) = fz;
            *(f32 *)(p2 + 0x720) = fz;
            TRICKY_CLEAR_RESET_FLAGS(p2);
        }
        break;
    case 8:
        trickyDebugPrint(strBase + 0x784);
        *(f32 *)(p2 + 0x728) = *(f32 *)(p2 + 0x728) - timeDelta;
        if (*(f32 *)(p2 + 0x728) <= lbl_803E23DC) {
            target = (void *)(*(int *)(p2 + 0x720) + 0x8);
            trickyUpdateApproachSpeed(p1, p2, lbl_803E2488, target, 1);
            trickyMove(p1, target);
            if (Objfsa_GetWalkGroupIndexAtPoint((float *)(p1 + 0x18), (void *)0x0) != 0) {
                *(u8 *)(p2 + 0x8) = 1;
                *(u8 *)(p2 + 0xa) = 0;
                fz = lbl_803E23DC;
                *(f32 *)(p2 + 0x71c) = fz;
                *(f32 *)(p2 + 0x720) = fz;
                TRICKY_CLEAR_RESET_FLAGS(p2);
            }
        }
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: trickyGuard
 * EN v1.0 Address: 0x8013FFB8
 * EN v1.0 Size: 2276b
 */
static int trickyGuardIsBaddieTargetValid(int p) {
    int target = *(int *)(p + 0x72c);
    int count;
    int *list;
    int i;

    list = (int *)ObjGroup_GetObjects(3, &count);
    for (i = 0; (s16)i < count; i++) {
        if (*list == target) {
            return 1;
        }
        list++;
    }
    return 0;
}

#pragma scheduling off
void trickyGuard(int p1, int p2) {
    char *strBase = lbl_8031D2E8;
    int i;
    void **slot;
    void *setup;
    void *state;
    int found;
    int newTarget;

    switch (*(u8 *)(p2 + 0xa)) {
    case 0:
        trickyDebugPrint(strBase + 0x648);
        *(int *)(p2 + 0x730) = Objfsa_GetWalkGroupIndexAtPoint((float *)(*(int *)(p2 + 0x28)), (void *)0x0);
        *(f32 *)(p2 + 0x71c) = (f32)(*(f32 *)(*(int *)(p2 + 0x24) + 0x18) - lbl_803E247C *
            fn_80293E80((lbl_803E2454 * (int)*(s16 *)*(int *)(p2 + 0x24)) / lbl_803E2458));
        *(f32 *)(p2 + 0x720) = *(f32 *)(*(int *)(p2 + 0x24) + 0x1c);
        *(f32 *)(p2 + 0x724) = (f32)(*(f32 *)(*(int *)(p2 + 0x24) + 0x20) - lbl_803E247C *
            sin((lbl_803E2454 * (int)*(s16 *)*(int *)(p2 + 0x24)) / lbl_803E2458));
        *(u8 *)(p2 + 0x734) = 0;
        *(u8 *)(p2 + 0xa) = 1;
        break;
    case 1:
        trickyDebugPrint(strBase + 0x654);
        trickyFn_8013b368((void *)p1, lbl_803E2488, (void *)p2);
        if (*(int *)(p2 + 0x730) == Objfsa_GetWalkGroupIndexAtPoint((float *)(p1 + 0x18), (void *)0x0)) {
            *(u8 *)(p2 + 0xa) = 2;
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x664);
        if (trickyFn_8013b368((void *)p1, lbl_803E2488, (void *)p2) == 0) {
            if (*(uint *)(p2 + 0x28) != (uint)(p2 + 0x71c)) {
                *(int *)(p2 + 0x28) = p2 + 0x71c;
                TRICKY_CLEAR_TARGET_DIRTY(p2);
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 3;
        } else {
            trickyGuardFindBaddieTarget(p2);
        }
        break;
    case 3:
        trickyDebugPrint(strBase + 0x674);
        if (trickyFn_8013b368((void *)p1, lbl_803E2488, (void *)p2) == 0) {
            if (lbl_803E23DC == *(f32 *)(p2 + 0x2ac)) {
                found = 0;
            } else if (lbl_803E2410 == *(f32 *)(p2 + 0x2b0)) {
                found = 1;
            } else if ((*(f32 *)(p2 + 0x2b4) - *(f32 *)(p2 + 0x2b0)) > lbl_803E2414) {
                found = 1;
            } else {
                found = 0;
            }
            if (found != 0) {
                objAnimFn_8013a3f0(p1, 0x8, lbl_803E243C, 0);
                *(f32 *)(p2 + 0x79c) = lbl_803E2440;
                *(f32 *)(p2 + 0x838) = lbl_803E23DC;
                trickyDebugPrint(strBase + 0x184);
            } else {
                objAnimFn_8013a3f0(p1, 0, lbl_803E2444, 0);
                trickyDebugPrint(strBase + 0x190);
            }
        }
        trickyGuardFindBaddieTarget(p2);
        break;
    case 4:
        trickyDebugPrint(strBase + 0x684);
        if (trickyFn_8013b368((void *)p1, lbl_803E247C, (void *)p2) == 0) {
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x10;
            if (*(u8 *)*(int *)p2 != 0 && *(u8 *)(p2 + 0x734) != 0) {
                if ((u8)Obj_IsLoadingLocked() != 0) {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x800;
                    for (i = 0, slot = (void **)p2; i < 7; i++) {
                        setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                        *(u8 *)((char *)setup + 0x4) = 2;
                        *(u8 *)((char *)setup + 0x5) = 1;
                        *(s16 *)((char *)setup + 0x1a) = (s16)i;
                        slot[0x700 / 4] = (void *)Obj_SetupObject(setup, 5, *(s8 *)(p1 + 0xac), -1, *(void **)(p1 + 0x30));
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
                (*(u8 *)*(int *)p2)--;
                objAnimFn_8013a3f0(p1, 0x34, lbl_803E2444, 0x4000000);
                *(u8 *)(p2 + 0xa) = 5;
            } else {
                objAnimFn_8013a3f0(p1, 0x32, lbl_803E23EC, 0x4000000);
                *(u8 *)(p2 + 0xa) = 6;
            }
        } else {
            if (*(int *)(p2 + 0x730) == Objfsa_GetWalkGroupIndexAtPoint((float *)(*(int *)(p2 + 0x28)), (void *)0x0)) {
                break;
            }
            newTarget = *(int *)(p2 + 0x24) + 0x18;
            if (*(uint *)(p2 + 0x28) != (uint)newTarget) {
                *(int *)(p2 + 0x28) = newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(p2);
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 2;
            break;
        }
        /* falls through into case 5 */
    case 5:
        trickyDebugPrint(strBase + 0x694);
        if ((double)*(f32 *)(p1 + 0x98) >= (double)lbl_803E24D0) {
            TRICKY_MARK_HELPERS_FINISHED(p2);
            for (i = 0, slot = (void **)p2; i < 7; i++) {
                objSetAnimSpeedTo1(slot[0x700 / 4]);
                slot++;
            }
            Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
            state = *(void **)(p1 + 0xb8);
            if ((((u32)*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                s16 a0 = *(s16 *)(p1 + 0xa0);
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                        objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                    }
                }
            }
            *(u32 *)(p2 + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_10;
            if (trickyGuardFindBaddieTarget(p2) == 0) {
                newTarget = *(int *)(p2 + 0x24) + 0x18;
                if (*(uint *)(p2 + 0x28) != (uint)newTarget) {
                    *(int *)(p2 + 0x28) = newTarget;
                    TRICKY_CLEAR_TARGET_DIRTY(p2);
                    *(u16 *)(p2 + 0xd2) = 0;
                }
                *(u8 *)(p2 + 0xa) = 2;
            }
        } else if (trickyGuardIsBaddieTargetValid(p2) != 0) {
            int targ = *(int *)(*(int *)(p1 + 0xb8) + 0x28);
            trickyTurnTowardYaw(p1, (s16)getAngle(
                -(*(f32 *)targ - *(f32 *)(p1 + 0x18)),
                -(*(f32 *)(targ + 0x8) - *(f32 *)(p1 + 0x20))));
        }
        break;
    case 6:
        trickyDebugPrint(strBase + 0x6a4);
        if ((double)*(f32 *)(p1 + 0x98) >= (double)lbl_803E24D0) {
            objAnimFn_8013a3f0(p1, 0x33, lbl_803E2444, 0x4000000);
            *(f32 *)(p2 + 0x728) = lbl_803E23DC;
            state = *(void **)(p1 + 0xb8);
            if ((((u32)*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                s16 a0 = *(s16 *)(p1 + 0xa0);
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                        objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
            *(u8 *)(p2 + 0xa) = 7;
        } else if (trickyGuardIsBaddieTargetValid(p2) != 0) {
            int targ = *(int *)(*(int *)(p1 + 0xb8) + 0x28);
            trickyTurnTowardYaw(p1, (s16)getAngle(
                -(*(f32 *)targ - *(f32 *)(p1 + 0x18)),
                -(*(f32 *)(targ + 0x8) - *(f32 *)(p1 + 0x20))));
        }
        break;
    case 7:
        trickyDebugPrint(strBase + 0x6b8);
        if (randomGetRange(0, 10) == 0) {
            state = *(void **)(p1 + 0xb8);
            if ((((u32)*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                s16 a0 = *(s16 *)(p1 + 0xa0);
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                        objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
        }
        *(f32 *)(p2 + 0x728) = *(f32 *)(p2 + 0x728) + timeDelta;
        if (((double)*(f32 *)(p2 + 0x728) >= (double)lbl_803E24D8 &&
             (double)getXZDistance((float *)*(int *)(p2 + 0x28), (float *)(p1 + 0x18)) >= (double)lbl_803E24C4) ||
            trickyGuardIsBaddieTargetValid(p2) == 0) {
            objAnimFn_8013a3f0(p1, 0x32, lbl_803E23F4, 0x4000000);
            *(u8 *)(p2 + 0xa) = 8;
        } else {
            int targ = *(int *)(*(int *)(p1 + 0xb8) + 0x28);
            trickyTurnTowardYaw(p1, (s16)getAngle(
                -(*(f32 *)targ - *(f32 *)(p1 + 0x18)),
                -(*(f32 *)(targ + 0x8) - *(f32 *)(p1 + 0x20))));
        }
        break;
    case 8:
        trickyDebugPrint(strBase + 0x6c8);
        if ((double)*(f32 *)(p1 + 0x98) <= (double)lbl_803E2420) {
            *(u32 *)(p2 + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_10;
            if (trickyGuardFindBaddieTarget(p2) == 0) {
                newTarget = *(int *)(p2 + 0x24) + 0x18;
                if (*(uint *)(p2 + 0x28) != (uint)newTarget) {
                    *(int *)(p2 + 0x28) = newTarget;
                    TRICKY_CLEAR_TARGET_DIRTY(p2);
                    *(u16 *)(p2 + 0xd2) = 0;
                }
                *(u8 *)(p2 + 0xa) = 2;
            }
        }
        break;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyGuardFindBaddieTarget
 * EN v1.0 Address: 0x8014089C
 * EN v1.0 Size: 320b
 */
#pragma scheduling off
int trickyGuardFindBaddieTarget(int p) {
    int count;
    f32 d;
    f32 bestDist;
    int *list;
    int i;
    uint best = 0;

    list = (int *)ObjGroup_GetObjects(3, &count);
    for (i = 0; (s16)i < count; i++) {
        d = (f32)getXZDistance((float *)(*list + 0x18), (float *)(p + 0x71c));
        if (best == 0) {
            if (*(int *)(p + 0x730) == Objfsa_GetWalkGroupIndexAtPoint((float *)(*list + 0x18), (void *)0x0)) {
                bestDist = d;
                best = *list;
            }
        } else if (d < bestDist) {
            if (*(int *)(p + 0x730) == Objfsa_GetWalkGroupIndexAtPoint((float *)(*list + 0x18), (void *)0x0)) {
                bestDist = d;
                best = *list;
            }
        }
        list++;
    }
    if (best != 0) {
        *(int *)(p + 0x72c) = best;
        if (*(uint *)(p + 0x28) != (best + 0x18)) {
            *(int *)(p + 0x28) = best + 0x18;
            TRICKY_CLEAR_TARGET_DIRTY(p);
            *(u16 *)(p + 0xd2) = 0;
        }
        *(u8 *)(p + 0xa) = 4;
        return 1;
    }
    return 0;
}
#pragma scheduling on

/* Trivial 4b 0-arg blr leaves. */
void fn_8014128C(void) {}
