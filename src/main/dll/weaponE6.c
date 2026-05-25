#include "ghidra_import.h"
#include "main/dll/weaponE6.h"

extern uint GameBit_Get(int bit);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern u32 randomGetRange(int min, int max);
extern void objAudioFn_800393f8(int obj, void *audio, int sfxId, int volume, int param5, int param6);
extern void objAnimFn_8013a3f0(double blend, int obj, int animId, int flags);
extern int trickyFn_8013b368(double speed, int obj, int state);
extern int trickyFoodFn_8014460c(int obj, int state);
extern void trickyDebugPrint(const char *fmt, ...);
extern int fn_801638BC(void);
extern int fn_801CDE70(int);
extern double sqrtf(double);
extern int fn_80179650(int slot);
extern void fn_80179678(int slot, int obj);
extern void fn_8017962C(int slot);
extern int fn_801793A4(int obj);
extern void fn_801796BC(int slot, int obj, double a, double b, double c);
extern double fn_80293E80(double x);
extern double sin(double x);
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

void fn_8013F100(int obj, int state)
{
    int iVar2;
    int iVar3;
    int iVar4;
    short sVar;
    double dVar;

    switch (*(u8 *)(state + 0xa)) {
    case 0:
        *(int *)(state + 0x700) = *(int *)(state + 0x24);
        *(float *)(state + 0x704) = lbl_803E24EC;
        *(u8 *)(state + 0xa) = 1;
        *(float *)(state + 0x7a4) = (f32)(s32)randomGetRange(150, 300);
        if (fn_80179650(*(int *)(state + 0x700)) != 0) {
            iVar2 = trickyFn_8013b368(lbl_803E24F0, obj, state);
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
                    objAnimFn_8013a3f0(lbl_803E24F4, obj, 28, 0x4000000);
                } else {
                    objAnimFn_8013a3f0(lbl_803E24F4, obj, 17, 0x4000000);
                }
                *(int *)(state + 0x54) |= 0x10;
                *(u8 *)(state + 0xa) = 3;
                fn_80179678(*(int *)(state + 0x700), obj);
            } else if (iVar2 == 2) {
                iVar3 = *(int *)(obj + 0xb8);
                if (((*(u8 *)(iVar3 + 0x58) >> 6) & 1) == 0) {
                    sVar = *(short *)(obj + 0xa0);
                    if (sVar >= 48 || sVar < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objAudioFn_800393f8(obj, (void *)(iVar3 + 936), 861, 1280, -1, 0);
                        }
                    }
                }
                *(u8 *)(state + 8) = 1;
                *(u8 *)(state + 0xa) = 0;
                *(float *)(state + 0x71c) = lbl_803E23DC;
                *(float *)(state + 0x720) = lbl_803E23DC;
                *(int *)(state + 0x54) &= ~0x10;
                *(int *)(state + 0x54) &= ~0x10000;
                *(int *)(state + 0x54) &= ~0x20000;
                *(int *)(state + 0x54) &= ~0x40000;
                *(s8 *)(state + 0xd) = -1;
            }
        } else {
            iVar2 = trickyFn_8013b368(lbl_803E2408, obj, state);
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
                        objAnimFn_8013a3f0(lbl_803E243C, obj, 8, 0);
                        *(float *)(state + 0x79c) = lbl_803E2440;
                        *(float *)(state + 0x838) = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        objAnimFn_8013a3f0(lbl_803E2444, obj, 0, 0);
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
                    objAnimFn_8013a3f0(lbl_803E243C, obj, 16, 0x4000000);
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
                    if (((*(u8 *)(iVar3 + 0x58) >> 6) & 1) != 0) {
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
                    objAnimFn_8013a3f0(lbl_803E243C, obj, 8, 0);
                    *(float *)(state + 0x79c) = lbl_803E2440;
                    *(float *)(state + 0x838) = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    objAnimFn_8013a3f0(lbl_803E2444, obj, 0, 0);
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
        if ((*(int *)(state + 0x54) & 0x8000000) != 0) {
            *(float *)(state + 0x828) = lbl_803E2408;
            iVar2 = *(int *)(state + 0);
            if (*(u8 *)(iVar2 + 2) >= 0xef) {
                *(u8 *)(iVar2 + 2) = 0;
            } else {
                *(u8 *)(iVar2 + 2) = *(u8 *)(iVar2 + 2) + 1;
            }
            *(int *)(state + 0x54) &= ~0x10;
            *(u8 *)(state + 0xa) = 7;
            iVar3 = *(int *)(state + 0x24) + 24;
            if (*(int *)(state + 0x28) != iVar3) {
                *(int *)(state + 0x28) = iVar3;
                *(int *)(state + 0x54) &= ~0x400;
                *(short *)(state + 0xd2) = 0;
            }
        }
        break;
    case 3:
        iVar2 = trickyFn_8013b368(lbl_803E2408, obj, state);
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
                objAnimFn_8013a3f0(lbl_803E243C, obj, 8, 0);
                *(float *)(state + 0x79c) = lbl_803E2440;
                *(float *)(state + 0x838) = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                objAnimFn_8013a3f0(lbl_803E2444, obj, 0, 0);
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
            iVar3 = *(int *)(state + 4) + 24;
            if (*(int *)(state + 0x28) != iVar3) {
                *(int *)(state + 0x28) = iVar3;
                *(int *)(state + 0x54) &= ~0x400;
                *(short *)(state + 0xd2) = 0;
            }
            *(u8 *)(state + 0xa) = 5;
            if (trickyFn_8013b368(lbl_803E24C8, obj, state) == 0) {
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
                    objAnimFn_8013a3f0(lbl_803E24F4, obj, 29, 0x4000000);
                } else {
                    objAnimFn_8013a3f0(lbl_803E24F4, obj, 19, 0x4000000);
                }
                *(u8 *)(state + 0xa) = 6;
            }
        }
        break;
    case 6:
    case 7:
        break;
    }
    if (((*(int *)(state + 0x54) & 0x10000) != 0) &&
        ViewFrustum_IsSphereVisible(obj + 0xc, lbl_803E2500) == 0) {
        Obj_FreeObject(*(int *)(state + 0x24));
    } else {
        fn_8017962C(*(int *)(state + 0x700));
    }
}

void fn_8013F9E4(int obj, int state)
{
    short animState;
    bool inWater;
    int result;
    uint range;
    int playerState;

    result = trickyFoodFn_8014460c(obj, state);
    if ((result == 0) && (result = trickyFn_8013b368((double)lbl_803E2488, obj, state), result == 0)) {
        *(float *)(state + 0x740) = *(float *)(state + 0x740) - timeDelta;
        if (*(float *)(state + 0x740) <= lbl_803E23DC) {
            range = randomGetRange(500, 0x2ee);
            *(float *)(state + 0x740) =
                (float)((double)CONCAT44(0x43300000, range ^ 0x80000000) - lbl_803E2460);
            playerState = *(int *)(obj + 0xb8);
            if (((*(byte *)(playerState + 0x58) >> 6 & 1) == 0) &&
                (((0x2f < *(short *)(obj + 0xa0) || (*(short *)(obj + 0xa0) < 0x29)) &&
                  (result = Sfx_IsPlayingFromObjectChannel(obj, 0x10), result == 0)))) {
                objAudioFn_800393f8(obj, (void *)(playerState + 0x3a8), 0x360, 0x500, -1, 0);
            }
        }
        if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
            inWater = false;
        } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
            inWater = true;
        } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) <= lbl_803E2414) {
            inWater = false;
        } else {
            inWater = true;
        }
        if (inWater) {
            objAnimFn_8013a3f0((double)lbl_803E243C, obj, 8, 0);
            *(float *)(state + 0x79c) = lbl_803E2440;
            *(float *)(state + 0x838) = lbl_803E23DC;
            trickyDebugPrint(sInWaterMessage);
        } else {
            animState = *(short *)(obj + 0xa0);
            if (animState != 0x31) {
                if ((animState < 0x31) && (animState == 0xd)) {
                    if ((*(uint *)(state + 0x54) & 0x8000000) != 0) {
                        objAnimFn_8013a3f0((double)lbl_803E243C, obj, 0x31, 0);
                    }
                } else {
                    objAnimFn_8013a3f0((double)lbl_803E2444, obj, 0xd, 0);
                }
            }
            trickyDebugPrint(lbl_8031D478);
        }
    }
}

#pragma scheduling off
void fn_8013FBE4(int obj, char **state)
{
    byte bitIndex;
    bool inWater;
    float fVar3;
    uint currentBit;
    float *targetPos;
    char *trackedObj;
    int result;
    float dx;
    float dz;
    float distance;

    if (*(char *)((int)state + 10) != 1) {
        if (*(char *)((int)state + 10) != 0) {
            return;
        }
        currentBit = GameBit_Get(0x48b);
        *(byte *)(state + 0x1c0) = (byte)((currentBit & 0xff) << 4) | *(byte *)(state + 0x1c0) & 0xf;
        state[0x1c4] = (char *)0;
        *(undefined *)((int)state + 10) = 1;
    }
    currentBit = GameBit_Get(0x48b);
    bitIndex = *(byte *)(state + 0x1c0) >> 4;
    if (bitIndex != currentBit) {
        *(byte *)(state + 0x1c0) = (bitIndex + 1) * 0x10 | *(byte *)(state + 0x1c0) & 0xf;
        **state = **state - 2;
    }
    targetPos = (float *)fn_801CDE70((int)state[9]);
    trackedObj = (char *)fn_801638BC();
    if ((trackedObj == (char *)0) || (**state == 0)) {
        *(undefined *)(state + 2) = 1;
        *(undefined *)((int)state + 10) = 0;
        fVar3 = lbl_803E23DC;
        *(float *)(state + 0x1c7) = lbl_803E23DC;
        *(float *)(state + 0x1c8) = fVar3;
        state[0x15] = (char *)((uint)state[0x15] & 0xffffffef);
        state[0x15] = (char *)((uint)state[0x15] & 0xfffeffff);
        state[0x15] = (char *)((uint)state[0x15] & 0xfffdffff);
        state[0x15] = (char *)((uint)state[0x15] & 0xfffbffff);
        *(undefined *)((int)state + 0xd) = 0xff;
    } else {
        if ((trackedObj != state[0x1c4]) && ((char **)state[10] != state + 0x1c1)) {
            state[10] = (char *)(state + 0x1c1);
            state[0x15] = (char *)((uint)state[0x15] & 0xfffffbff);
            *(undefined2 *)((int)state + 0xd2) = 0;
        }
        dx = *targetPos - *(float *)(obj + 0x18);
        dz = targetPos[2] - *(float *)(obj + 0x20);
        distance = sqrtf(dx * dx + dz * dz);
        if (lbl_803E23DC != distance) {
            dx = dx / distance;
            dz = dz / distance;
        }
        distance = lbl_803E24D4;
        *(float *)(state + 0x1c1) = -(distance * dx - *(float *)(trackedObj + 0x18));
        *(undefined4 *)(state + 0x1c2) = *(undefined4 *)(trackedObj + 0x1c);
        *(float *)(state + 0x1c3) = -(distance * dz - *(float *)(trackedObj + 0x20));
        result = trickyFn_8013b368((double)lbl_803E2488, obj, (int)state);
        if (result == 0) {
            if (lbl_803E23DC == *(float *)(state + 0xab)) {
                inWater = false;
            } else if (lbl_803E2410 == *(float *)(state + 0xac)) {
                inWater = true;
            } else if (*(float *)(state + 0xad) - *(float *)(state + 0xac) <= lbl_803E2414) {
                inWater = false;
            } else {
                inWater = true;
            }
            if (inWater) {
                objAnimFn_8013a3f0((double)lbl_803E243C, obj, 8, 0);
                *(float *)(state + 0x1e7) = lbl_803E2440;
                *(float *)(state + 0x20e) = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                objAnimFn_8013a3f0((double)lbl_803E2444, obj, 0, 0);
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}
#pragma scheduling reset

void fn_8013FEC0(undefined4 obj, int state)
{
    bool inWater;
    int result;

    result = trickyFn_8013b368((double)lbl_803E247C, (int)obj, state);
    if (result == 0) {
        if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
            inWater = false;
        } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
            inWater = true;
        } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) <= lbl_803E2414) {
            inWater = false;
        } else {
            inWater = true;
        }
        if (inWater) {
            objAnimFn_8013a3f0((double)lbl_803E243C, obj, 8, 0);
            *(float *)(state + 0x79c) = lbl_803E2440;
            *(float *)(state + 0x838) = lbl_803E23DC;
            trickyDebugPrint(sInWaterMessage);
        } else {
            objAnimFn_8013a3f0((double)lbl_803E2444, obj, 0, 0);
            trickyDebugPrint(lbl_8031D478);
        }
    }
}
