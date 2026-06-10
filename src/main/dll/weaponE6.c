#include "main/dll/weaponE6.h"
#include "main/game_object.h"
#include "main/dll/tricky_state.h"

#define TRICKY_STATE_FLAGS_OFFSET 0x54
#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400
#define TRICKY_STATE_RESET_FLAG_10 0x00000010
#define TRICKY_STATE_RESET_FLAG_10000 0x00010000
#define TRICKY_STATE_RESET_FLAG_20000 0x00020000
#define TRICKY_STATE_RESET_FLAG_40000 0x00040000

#define TRICKY_CLEAR_TARGET_DIRTY(st) \
    (*(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_TARGET_DIRTY_FLAG)

#define TRICKY_CLEAR_RESET_FLAGS(st) \
    { \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_10; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_10000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_20000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_40000; \
        *(s8 *)((st) + 0xd) = -1; \
    }

extern uint GameBit_Get(int bit);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern u32 randomGetRange(int min, int max);
extern void objAudioFn_800393f8(int obj, void *audio, int sfxId, int volume, int param5, int param6);
extern void objAnimFn_8013a3f0(int obj, int animId, f32 blend, int flags);
extern int trickyFn_8013b368(int obj, f32 speed, int state);
extern int trickyFoodFn_8014460c(int obj, int state);
extern void trickyDebugPrint(const char *fmt, ...);
extern int tumbleweedbush_findNearestActive(void);
extern int fn_801CDE70(int);
extern f32 sqrtf(f32);
extern int fn_80179650(int slot);
extern void fn_80179678(int slot, int obj);
extern void fn_8017962C(int slot);
extern int fn_801793A4(int obj);
extern void fn_801796BC(int slot, int obj, double a, double b, double c);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int ViewFrustum_IsSphereVisible(int posPtr, float radius);
extern void Obj_FreeObject(int obj);

extern char sInWaterMessage[];
extern char lbl_8031D478[];
extern f32 timeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E8;
extern f32 lbl_803E2408;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f64 lbl_803E2460;
extern f32 lbl_803E247C;
extern f32 lbl_803E2488;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24D0;
extern f32 lbl_803E24D4;
extern f32 lbl_803E24EC;
extern f32 lbl_803E24F0;
extern f32 lbl_803E24F4;
extern f32 lbl_803E24F8;
extern f32 lbl_803E24FC;
extern f32 lbl_803E2500;

void fn_8013F100(int obj, register int state)
{
    int iVar2;
    int iVar3;
    int iVar4;
    short sVar;
    double dVar;
    f32 fz;
    u8 *pTgt;

    switch (((TrickyState *)state)->substate) {
    case 0:
        *(int *)&((TrickyState *)state)->unk700 = *(int *)&((TrickyState *)state)->followObj;
        *(float *)&((TrickyState *)state)->unk704 = lbl_803E24EC;
        ((TrickyState *)state)->substate = 1;
        ((TrickyState *)state)->unk7A4 = (f32)(s32)randomGetRange(150, 300);
        if (fn_80179650(*(int *)&((TrickyState *)state)->unk700) != 0) {
            iVar2 = trickyFn_8013b368(obj, lbl_803E24F0, state);
            if (iVar2 == 0) {
                if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                    iVar4 = 1;
                } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 28, lbl_803E24F4, 0x4000000);
                } else {
                    objAnimFn_8013a3f0(obj, 17, lbl_803E24F4, 0x4000000);
                }
                *(int *)&((TrickyState *)state)->stateFlags |= 0x10;
                ((TrickyState *)state)->substate = 3;
                fn_80179678(*(int *)&((TrickyState *)state)->unk700, obj);
            } else if (iVar2 == 2) {
                iVar3 = *(int *)&((GameObject *)obj)->extra;
                if ((((uint)*(u8 *)(iVar3 + 0x58) >> 6) & 1) == 0) {
                    sVar = ((GameObject *)obj)->anim.currentMove;
                    if (sVar >= 48 || sVar < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objAudioFn_800393f8(obj, (void *)(iVar3 + 936), 861, 1280, -1, 0);
                        }
                    }
                }
                ((TrickyState *)state)->unk08 = 1;
                ((TrickyState *)state)->substate = 0;
                fz = lbl_803E23DC;
                ((TrickyState *)state)->unk71C = fz;
                ((TrickyState *)state)->unk720 = fz;
                TRICKY_CLEAR_RESET_FLAGS(state);
            }
        } else {
            iVar2 = trickyFn_8013b368(obj, lbl_803E2408, state);
            if (iVar2 == 0) {
                if (*(float *)&((TrickyState *)state)->unk704 > lbl_803E23DC) {
                    if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                        iVar4 = 0;
                    } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                        iVar4 = 1;
                    } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                        iVar4 = 1;
                    } else {
                        iVar4 = 0;
                    }
                    if (iVar4 != 0) {
                        objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                        ((TrickyState *)state)->unk79C = lbl_803E2440;
                        ((TrickyState *)state)->unk838 = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(lbl_8031D478);
                    }
                    *(float *)&((TrickyState *)state)->unk704 -= timeDelta;
                    if (*(float *)&((TrickyState *)state)->unk704 <= lbl_803E23DC) {
                        if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                            iVar4 = 0;
                        } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                            iVar4 = 1;
                        } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                            iVar4 = 1;
                        } else {
                            iVar4 = 0;
                        }
                        if (iVar4 != 0) {
                            *(float *)&((TrickyState *)state)->unk704 = lbl_803E24EC;
                        } else {
                            *(float *)&((TrickyState *)state)->unk708 = lbl_803E24F8;
                        }
                    }
                } else {
                    objAnimFn_8013a3f0(obj, 16, lbl_803E243C, 0x4000000);
                    *(float *)&((TrickyState *)state)->unk708 -= timeDelta;
                    if (*(float *)&((TrickyState *)state)->unk708 <= lbl_803E23DC) {
                        *(float *)&((TrickyState *)state)->unk704 = lbl_803E24EC;
                    }
                }
            } else if (iVar2 == 1) {
                ((TrickyState *)state)->unk7A4 -= timeDelta;
                if (((TrickyState *)state)->unk7A4 <= lbl_803E23DC) {
                    ((TrickyState *)state)->unk7A4 = (f32)(s32)randomGetRange(150, 300);
                    iVar3 = *(int *)&((GameObject *)obj)->extra;
                    if ((((uint)*(u8 *)(iVar3 + 0x58) >> 6) & 1) != 0) {
                        break;
                    }
                    sVar = ((GameObject *)obj)->anim.currentMove;
                    if (sVar < 48) {
                        if (sVar >= 41) {
                            break;
                        }
                    }
                    if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                        objAudioFn_800393f8(obj, (void *)(iVar3 + 936), 865, 1280, -1, 0);
                    }
                }
            } else {
                if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                    iVar4 = 1;
                } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                    ((TrickyState *)state)->unk79C = lbl_803E2440;
                    ((TrickyState *)state)->unk838 = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        }
        break;
    case 1:
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E24FC) {
            iVar2 = *(int *)&((TrickyState *)state)->unk700;
            *(float *)(iVar2 + 0x10) += lbl_803E2488;
            dVar = -mathCosf(lbl_803E2454 * (f32)(s32)*(short *)obj / lbl_803E2458);
            fn_801796BC(*(int *)&((TrickyState *)state)->unk700, obj,
                        -mathSinf(lbl_803E2454 * (f32)(s32)*(short *)obj / lbl_803E2458),
                        lbl_803E23E8, dVar);
            ((TrickyState *)state)->substate = 2;
        }
        break;
    case 2:
        if ((((TrickyState *)state)->stateFlags & 0x8000000) != 0) {
            *(float *)(state + 0x828) = lbl_803E2408;
            iVar2 = ((TrickyState *)state)->progressPtr;
            if (*(u8 *)(iVar2 + 2) >= 0xef) {
                *(u8 *)(iVar2 + 2) = 0;
            } else {
                *(u8 *)(iVar2 + 2) += 1;
            }
            *(u32 *)(state + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_10;
            ((TrickyState *)state)->substate = 7;
            pTgt = ((TrickyState *)state)->followObj + 24;
            if (((TrickyState *)state)->unk28 != pTgt) {
                ((TrickyState *)state)->unk28 = pTgt;
                TRICKY_CLEAR_TARGET_DIRTY(state);
                *(short *)&((TrickyState *)state)->unkD2 = 0;
            }
        }
        break;
    case 3:
        iVar2 = trickyFn_8013b368(obj, lbl_803E2408, state);
        if (iVar2 != 1) {
            if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                iVar4 = 0;
            } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                iVar4 = 1;
            } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                iVar4 = 1;
            } else {
                iVar4 = 0;
            }
            if (iVar4 != 0) {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState *)state)->unk79C = lbl_803E2440;
                ((TrickyState *)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(lbl_8031D478);
            }
            return;
        }
        if (fn_801793A4(*(int *)&((TrickyState *)state)->followObj) != 0) {
            *(float *)&((TrickyState *)state)->unk704 = lbl_803E24EC;
            ((TrickyState *)state)->substate = 1;
        }
        break;
    case 4:
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E24A8) {
            ((TrickyState *)state)->substate = 4;
        }
        break;
    case 5:
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E24D0) {
            pTgt = *(u8 **)&((TrickyState *)state)->playerObj + 24;
            if (((TrickyState *)state)->unk28 != pTgt) {
                ((TrickyState *)state)->unk28 = pTgt;
                TRICKY_CLEAR_TARGET_DIRTY(state);
                *(short *)&((TrickyState *)state)->unkD2 = 0;
            }
            ((TrickyState *)state)->substate = 5;
            if (trickyFn_8013b368(obj, lbl_803E24C8, state) == 0) {
                if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                    iVar4 = 1;
                } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 29, lbl_803E24F4, 0x4000000);
                } else {
                    objAnimFn_8013a3f0(obj, 19, lbl_803E24F4, 0x4000000);
                }
                ((TrickyState *)state)->substate = 6;
            }
        }
        break;
    case 6:
    case 7:
        break;
    }
    if (((((TrickyState *)state)->stateFlags & 0x10000) != 0) &&
        ViewFrustum_IsSphereVisible(obj + 0xc, lbl_803E2500) == 0) {
        Obj_FreeObject(*(int *)&((TrickyState *)state)->followObj);
    } else {
        fn_8017962C(*(int *)&((TrickyState *)state)->unk700);
    }
}

void fn_8013F9E4(int obj, int state)
{
    int iVar3;
    int iVar4;
    short sVar;

    if (trickyFoodFn_8014460c(obj, state) == 0) {
        if (trickyFn_8013b368(obj, lbl_803E2488, state) == 0) {
            ((TrickyState *)state)->unk740 -= timeDelta;
            if (((TrickyState *)state)->unk740 <= lbl_803E23DC) {
                ((TrickyState *)state)->unk740 = (f32)(s32)randomGetRange(500, 750);
                iVar3 = *(int *)&((GameObject *)obj)->extra;
                if ((((uint)*(u8 *)(iVar3 + 0x58) >> 6) & 1) == 0) {
                    sVar = ((GameObject *)obj)->anim.currentMove;
                    if (sVar >= 48 || sVar < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objAudioFn_800393f8(obj, (void *)(iVar3 + 936), 864, 1280, -1, 0);
                        }
                    }
                }
            }
            if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                iVar4 = 0;
            } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                iVar4 = 1;
            } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                iVar4 = 1;
            } else {
                iVar4 = 0;
            }
            if (iVar4 != 0) {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState *)state)->unk79C = lbl_803E2440;
                ((TrickyState *)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch (((GameObject *)obj)->anim.currentMove) {
                case 13:
                    if ((((TrickyState *)state)->stateFlags & 0x8000000) != 0) {
                        objAnimFn_8013a3f0(obj, 49, lbl_803E243C, 0);
                    }
                    break;
                case 49:
                    break;
                default:
                    objAnimFn_8013a3f0(obj, 13, lbl_803E2444, 0);
                    break;
                }
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}

typedef struct {
    u8 hi : 4;
    u8 lo : 4;
} WeaponNibble;

void fn_8013FBE4(int obj, register int state)
{
    int iVar4;
    float dx;
    float dz;
    float distance;
    f32 fz;
    float *targetPos;
    u8 *trackedObj;
    uint currentBit;
    u8 bitIndex;
    u8 newBit;

    switch (((TrickyState *)state)->substate) {
    case 0:
        newBit = GameBit_Get(0x48b);
        ((WeaponNibble *)(state + 0x700))->hi = newBit;
        *(int *)&((TrickyState *)state)->unk710 = 0;
        ((TrickyState *)state)->substate = 1;
        /* fall through */
    case 1:
        currentBit = GameBit_Get(0x48b);
        bitIndex = ((WeaponNibble *)(state + 0x700))->hi;
        if (bitIndex != currentBit) {
            ((WeaponNibble *)(state + 0x700))->hi = bitIndex + 1;
            **(u8 **)state -= 2;
        }
        targetPos = (float *)fn_801CDE70(*(int *)&((TrickyState *)state)->followObj);
        trackedObj = (u8 *)tumbleweedbush_findNearestActive();
        if (trackedObj != 0 && **(u8 **)state != 0) {
            if (trackedObj != *(u8 **)&((TrickyState *)state)->unk710 &&
                ((TrickyState *)state)->unk28 != (u8 *)(state + 0x704)) {
                ((TrickyState *)state)->unk28 = (u8 *)(state + 0x704);
                TRICKY_CLEAR_TARGET_DIRTY(state);
                *(short *)&((TrickyState *)state)->unkD2 = 0;
            }
            dx = *targetPos - ((GameObject *)obj)->anim.worldPosX;
            dz = targetPos[2] - ((GameObject *)obj)->anim.worldPosZ;
            distance = sqrtf(dx * dx + dz * dz);
            if (lbl_803E23DC != distance) {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = lbl_803E24D4;
            *(float *)&((TrickyState *)state)->unk704 = -(distance * dx - *(float *)(trackedObj + 0x18));
            *(float *)&((TrickyState *)state)->unk708 = *(float *)(trackedObj + 0x1c);
            *(float *)&((TrickyState *)state)->unk70C = -(distance * dz - *(float *)(trackedObj + 0x20));
            if (trickyFn_8013b368(obj, lbl_803E2488, state) == 0) {
                if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                    iVar4 = 1;
                } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                    ((TrickyState *)state)->unk79C = lbl_803E2440;
                    ((TrickyState *)state)->unk838 = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        } else {
            ((TrickyState *)state)->unk08 = 1;
            ((TrickyState *)state)->substate = 0;
            fz = lbl_803E23DC;
            ((TrickyState *)state)->unk71C = fz;
            ((TrickyState *)state)->unk720 = fz;
            TRICKY_CLEAR_RESET_FLAGS(state);
        }
        break;
    }
}

void fn_8013FEC0(int obj, int state)
{
    bool inWater;
    int result;

    result = trickyFn_8013b368(obj, lbl_803E247C, state);
    if (result == 0) {
        if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
            inWater = false;
        } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
            inWater = true;
        } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
            inWater = true;
        } else {
            inWater = false;
        }
        if (inWater) {
            objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
            ((TrickyState *)state)->unk79C = lbl_803E2440;
            ((TrickyState *)state)->unk838 = lbl_803E23DC;
            trickyDebugPrint(sInWaterMessage);
        } else {
            objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
            trickyDebugPrint(lbl_8031D478);
        }
    }
}
