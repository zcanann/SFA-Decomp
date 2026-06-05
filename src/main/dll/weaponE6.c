#include "ghidra_import.h"
#include "main/dll/weaponE6.h"

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
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
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

#pragma peephole off
#pragma scheduling off
void fn_8013F100(int obj, register int state)
{
    int iVar2;
    int iVar3;
    int iVar4;
    short sVar;
    double dVar;
    f32 fz;
    u8 *pTgt;

    switch (*(u8 *)(state + 0xa)) {
    case 0:
        *(int *)(state + 0x700) = *(int *)(state + 0x24);
        *(float *)(state + 0x704) = lbl_803E24EC;
        *(u8 *)(state + 0xa) = 1;
        *(float *)(state + 0x7a4) = (f32)(s32)randomGetRange(150, 300);
        if (fn_80179650(*(int *)(state + 0x700)) != 0) {
            iVar2 = trickyFn_8013b368(obj, lbl_803E24F0, state);
            if (iVar2 == 0) {
                if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                    iVar4 = 1;
                } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 28, lbl_803E24F4, 0x4000000);
                } else {
                    objAnimFn_8013a3f0(obj, 17, lbl_803E24F4, 0x4000000);
                }
                *(int *)(state + 0x54) |= 0x10;
                *(u8 *)(state + 0xa) = 3;
                fn_80179678(*(int *)(state + 0x700), obj);
            } else if (iVar2 == 2) {
                iVar3 = *(int *)(obj + 0xb8);
                if ((((uint)*(u8 *)(iVar3 + 0x58) >> 6) & 1) == 0) {
                    sVar = *(short *)(obj + 0xa0);
                    if (sVar >= 48 || sVar < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objAudioFn_800393f8(obj, (void *)(iVar3 + 936), 861, 1280, -1, 0);
                        }
                    }
                }
                *(u8 *)(state + 8) = 1;
                *(u8 *)(state + 0xa) = 0;
                fz = lbl_803E23DC;
                *(float *)(state + 0x71c) = fz;
                *(float *)(state + 0x720) = fz;
                /* MWCC materializes these mask constants (li/lis;addi + and)
                   where clean C folds to rlwinm - sanctioned asm */
                {
                    register u32 m;
                    register u32 t;
                    register u32 v;
                    asm {
                        lwz t, 0x54(state)
                        li m, -17
                        and m, t, m
                        stw m, 0x54(state)
                        lwz v, 0x54(state)
                        lis t, -1
                        addi m, t, -1
                        and m, v, m
                        stw m, 0x54(state)
                        lwz v, 0x54(state)
                        lis t, -2
                        addi m, t, -1
                        and m, v, m
                        stw m, 0x54(state)
                        lwz v, 0x54(state)
                        lis t, -4
                        addi m, t, -1
                        and m, v, m
                        stw m, 0x54(state)
                    }
                }
                *(s8 *)(state + 0xd) = -1;
            }
        } else {
            iVar2 = trickyFn_8013b368(obj, lbl_803E2408, state);
            if (iVar2 == 0) {
                if (*(float *)(state + 0x704) > lbl_803E23DC) {
                    if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                        iVar4 = 0;
                    } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                        iVar4 = 1;
                    } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                        iVar4 = 1;
                    } else {
                        iVar4 = 0;
                    }
                    if (iVar4 != 0) {
                        objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                        *(float *)(state + 0x79c) = lbl_803E2440;
                        *(float *)(state + 0x838) = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(lbl_8031D478);
                    }
                    *(float *)(state + 0x704) -= timeDelta;
                    if (*(float *)(state + 0x704) <= lbl_803E23DC) {
                        if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                            iVar4 = 0;
                        } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                            iVar4 = 1;
                        } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                            iVar4 = 1;
                        } else {
                            iVar4 = 0;
                        }
                        if (iVar4 != 0) {
                            *(float *)(state + 0x704) = lbl_803E24EC;
                        } else {
                            *(float *)(state + 0x708) = lbl_803E24F8;
                        }
                    }
                } else {
                    objAnimFn_8013a3f0(obj, 16, lbl_803E243C, 0x4000000);
                    *(float *)(state + 0x708) -= timeDelta;
                    if (*(float *)(state + 0x708) <= lbl_803E23DC) {
                        *(float *)(state + 0x704) = lbl_803E24EC;
                    }
                }
            } else if (iVar2 == 1) {
                *(float *)(state + 0x7a4) -= timeDelta;
                if (*(float *)(state + 0x7a4) <= lbl_803E23DC) {
                    *(float *)(state + 0x7a4) = (f32)(s32)randomGetRange(150, 300);
                    iVar3 = *(int *)(obj + 0xb8);
                    if ((((uint)*(u8 *)(iVar3 + 0x58) >> 6) & 1) != 0) {
                        break;
                    }
                    sVar = *(short *)(obj + 0xa0);
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
                if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                    iVar4 = 1;
                } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                    *(float *)(state + 0x79c) = lbl_803E2440;
                    *(float *)(state + 0x838) = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        }
        break;
    case 1:
        if (*(float *)(obj + 0x98) >= lbl_803E24FC) {
            iVar2 = *(int *)(state + 0x700);
            *(float *)(iVar2 + 0x10) += lbl_803E2488;
            dVar = -sin(lbl_803E2454 * (f32)(s32)*(short *)obj / lbl_803E2458);
            fn_801796BC(*(int *)(state + 0x700), obj,
                        -fn_80293E80(lbl_803E2454 * (f32)(s32)*(short *)obj / lbl_803E2458),
                        lbl_803E23E8, dVar);
            *(u8 *)(state + 0xa) = 2;
        }
        break;
    case 2:
        if ((*(uint *)(state + 0x54) & 0x8000000) != 0) {
            *(float *)(state + 0x828) = lbl_803E2408;
            iVar2 = *(int *)(state + 0);
            if (*(u8 *)(iVar2 + 2) >= 0xef) {
                *(u8 *)(iVar2 + 2) = 0;
            } else {
                *(u8 *)(iVar2 + 2) += 1;
            }
            /* MWCC materializes the mask constant - sanctioned asm */
            {
                register u32 m;
                register u32 v;
                asm {
                    lwz v, 0x54(state)
                    li m, -17
                    and m, v, m
                    stw m, 0x54(state)
                }
            }
            *(u8 *)(state + 0xa) = 7;
            pTgt = *(u8 **)(state + 0x24) + 24;
            if (*(u8 **)(state + 0x28) != pTgt) {
                *(u8 **)(state + 0x28) = pTgt;
                /* MWCC materializes the mask constant - sanctioned asm */
                {
                    register u32 m;
                    register u32 v;
                    asm {
                        lwz v, 0x54(state)
                        li m, -1025
                        and m, v, m
                        stw m, 0x54(state)
                    }
                }
                *(short *)(state + 0xd2) = 0;
            }
        }
        break;
    case 3:
        iVar2 = trickyFn_8013b368(obj, lbl_803E2408, state);
        if (iVar2 != 1) {
            if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                iVar4 = 0;
            } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                iVar4 = 1;
            } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                iVar4 = 1;
            } else {
                iVar4 = 0;
            }
            if (iVar4 != 0) {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                *(float *)(state + 0x79c) = lbl_803E2440;
                *(float *)(state + 0x838) = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(lbl_8031D478);
            }
            return;
        }
        if (fn_801793A4(*(int *)(state + 0x24)) != 0) {
            *(float *)(state + 0x704) = lbl_803E24EC;
            *(u8 *)(state + 0xa) = 1;
        }
        break;
    case 4:
        if (*(float *)(obj + 0x98) >= lbl_803E24A8) {
            *(u8 *)(state + 0xa) = 4;
        }
        break;
    case 5:
        if (*(float *)(obj + 0x98) >= lbl_803E24D0) {
            pTgt = *(u8 **)(state + 4) + 24;
            if (*(u8 **)(state + 0x28) != pTgt) {
                *(u8 **)(state + 0x28) = pTgt;
                /* MWCC materializes the mask constant - sanctioned asm */
                {
                    register u32 m;
                    register u32 v;
                    asm {
                        lwz v, 0x54(state)
                        li m, -1025
                        and m, v, m
                        stw m, 0x54(state)
                    }
                }
                *(short *)(state + 0xd2) = 0;
            }
            *(u8 *)(state + 0xa) = 5;
            if (trickyFn_8013b368(obj, lbl_803E24C8, state) == 0) {
                if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                    iVar4 = 1;
                } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 29, lbl_803E24F4, 0x4000000);
                } else {
                    objAnimFn_8013a3f0(obj, 19, lbl_803E24F4, 0x4000000);
                }
                *(u8 *)(state + 0xa) = 6;
            }
        }
        break;
    case 6:
    case 7:
        break;
    }
    if (((*(uint *)(state + 0x54) & 0x10000) != 0) &&
        ViewFrustum_IsSphereVisible(obj + 0xc, lbl_803E2500) == 0) {
        Obj_FreeObject(*(int *)(state + 0x24));
    } else {
        fn_8017962C(*(int *)(state + 0x700));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void fn_8013F9E4(int obj, int state)
{
    int iVar3;
    int iVar4;
    short sVar;

    if (trickyFoodFn_8014460c(obj, state) == 0) {
        if (trickyFn_8013b368(obj, lbl_803E2488, state) == 0) {
            *(float *)(state + 0x740) -= timeDelta;
            if (*(float *)(state + 0x740) <= lbl_803E23DC) {
                *(float *)(state + 0x740) = (f32)(s32)randomGetRange(500, 750);
                iVar3 = *(int *)(obj + 0xb8);
                if ((((uint)*(u8 *)(iVar3 + 0x58) >> 6) & 1) == 0) {
                    sVar = *(short *)(obj + 0xa0);
                    if (sVar >= 48 || sVar < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objAudioFn_800393f8(obj, (void *)(iVar3 + 936), 864, 1280, -1, 0);
                        }
                    }
                }
            }
            if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                iVar4 = 0;
            } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                iVar4 = 1;
            } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                iVar4 = 1;
            } else {
                iVar4 = 0;
            }
            if (iVar4 != 0) {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                *(float *)(state + 0x79c) = lbl_803E2440;
                *(float *)(state + 0x838) = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch (*(short *)(obj + 0xa0)) {
                case 13:
                    if ((*(uint *)(state + 0x54) & 0x8000000) != 0) {
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
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 hi : 4;
    u8 lo : 4;
} WeaponNibble;

#pragma peephole off
#pragma scheduling off
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

    switch (*(u8 *)(state + 0xa)) {
    case 0:
        newBit = GameBit_Get(0x48b);
        ((WeaponNibble *)(state + 0x700))->hi = newBit;
        *(int *)(state + 0x710) = 0;
        *(u8 *)(state + 0xa) = 1;
        /* fall through */
    case 1:
        currentBit = GameBit_Get(0x48b);
        bitIndex = ((WeaponNibble *)(state + 0x700))->hi;
        if (bitIndex != currentBit) {
            ((WeaponNibble *)(state + 0x700))->hi = bitIndex + 1;
            **(u8 **)state -= 2;
        }
        targetPos = (float *)fn_801CDE70(*(int *)(state + 0x24));
        trackedObj = (u8 *)tumbleweedbush_findNearestActive();
        if (trackedObj != 0 && **(u8 **)state != 0) {
            if (trackedObj != *(u8 **)(state + 0x710) &&
                *(u8 **)(state + 0x28) != (u8 *)(state + 0x704)) {
                *(u8 **)(state + 0x28) = (u8 *)(state + 0x704);
                /* MWCC materializes the mask constant (li -1025) - sanctioned asm */
                {
                    register u32 m;
                    register u32 v;
                    asm {
                        lwz v, 0x54(state)
                        li m, -1025
                        and m, v, m
                        stw m, 0x54(state)
                    }
                }
                *(short *)(state + 0xd2) = 0;
            }
            dx = *targetPos - *(float *)(obj + 0x18);
            dz = targetPos[2] - *(float *)(obj + 0x20);
            distance = sqrtf(dx * dx + dz * dz);
            if (lbl_803E23DC != distance) {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = lbl_803E24D4;
            *(float *)(state + 0x704) = -(distance * dx - *(float *)(trackedObj + 0x18));
            *(float *)(state + 0x708) = *(float *)(trackedObj + 0x1c);
            *(float *)(state + 0x70c) = -(distance * dz - *(float *)(trackedObj + 0x20));
            if (trickyFn_8013b368(obj, lbl_803E2488, state) == 0) {
                if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
                    iVar4 = 0;
                } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
                    iVar4 = 1;
                } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
                    iVar4 = 1;
                } else {
                    iVar4 = 0;
                }
                if (iVar4 != 0) {
                    objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                    *(float *)(state + 0x79c) = lbl_803E2440;
                    *(float *)(state + 0x838) = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        } else {
            *(u8 *)(state + 8) = 1;
            *(u8 *)(state + 0xa) = 0;
            fz = lbl_803E23DC;
            *(float *)(state + 0x71c) = fz;
            *(float *)(state + 0x720) = fz;
            /* MWCC materializes these mask constants - sanctioned asm */
            {
                register u32 m;
                register u32 t;
                register u32 v;
                asm {
                    lwz t, 0x54(state)
                    li m, -17
                    and m, t, m
                    stw m, 0x54(state)
                    lwz v, 0x54(state)
                    lis t, -1
                    addi m, t, -1
                    and m, v, m
                    stw m, 0x54(state)
                    lwz v, 0x54(state)
                    lis t, -2
                    addi m, t, -1
                    and m, v, m
                    stw m, 0x54(state)
                    lwz v, 0x54(state)
                    lis t, -4
                    addi m, t, -1
                    and m, v, m
                    stw m, 0x54(state)
                }
            }
            *(s8 *)(state + 0xd) = -1;
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void fn_8013FEC0(int obj, int state)
{
    bool inWater;
    int result;

    result = trickyFn_8013b368(obj, lbl_803E247C, state);
    if (result == 0) {
        if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
            inWater = false;
        } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
            inWater = true;
        } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
            inWater = true;
        } else {
            inWater = false;
        }
        if (inWater) {
            objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
            *(float *)(state + 0x79c) = lbl_803E2440;
            *(float *)(state + 0x838) = lbl_803E23DC;
            trickyDebugPrint(sInWaterMessage);
        } else {
            objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
            trickyDebugPrint(lbl_8031D478);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
