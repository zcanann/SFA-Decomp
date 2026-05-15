#include "ghidra_import.h"
#include "main/dll/backpack.h"

extern void tumbleweed_updateStateMachine(int obj);
extern void tumbleweed_updateTargetedStateMachine(int obj);
extern void tumbleweed_updateEffects(int obj);
extern int GameBit_Set(int eventId, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_SetHitVolumeSlot(int obj, int a, int b, int c);
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

extern void* lbl_803DCAB8;
extern void* lbl_803DCA8C;
extern void* lbl_803DCAA8;
extern void* pDll_expgfx;
extern f32 lbl_803E2FC8;
extern f32 lbl_803E2FCC;
extern f32 lbl_803E2FD0;
extern f32 lbl_803E2FB4;
extern u8 lbl_803DBD40[8];
extern u8 lbl_80320288[0xc];

extern u32 randomGetRange(int min, int max);
extern void ObjGroup_AddObject(int obj, int group);
extern void ObjMsg_AllocQueue(int obj, int capacity);

extern void ObjHits_EnableObject(int obj);
extern int ObjHits_GetPriorityHit(int obj, int *outHitObject, int *outSphereIndex, u32 *outHitVolume);
extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);
extern void Obj_FreeObject(int obj);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 getXZDistance(f32 *p1, f32 *p2);
extern void gameBitIncrement(int eventId);
extern int ObjMsg_Pop(int obj, u32 *outMessage, u32 *outSender, u32 *outParam);
extern void ObjMsg_SendToObject(int obj, int message, int sender, int *param);
extern void ObjMsg_SendToObjects(int targetId, u32 flags, void *sender, u32 message, u32 param);
extern void ObjAnim_SetCurrentMove(int obj, int moveId, f32 moveProgress, int flags);
extern void tumbleweed_updateRollingMotion(int obj, int aux);
extern void fn_80163990(int obj, int aux);
extern void fn_80165B3C(int obj, int state);
extern void fn_80165C8C(int obj, int state);
extern void fn_80166444(int obj, int state);
extern void fn_80166A50(f32 x, f32 y, f32 z, f32 scale, int obj);

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F68;
extern f32 lbl_803E2F98;
extern f32 lbl_803E2F9C;
extern f32 lbl_803E2FA0;
extern f32 lbl_803E2FA4;
extern f32 lbl_803E2FA8;
extern f32 lbl_803E2FAC;
extern f32 lbl_803E2FB0;
extern f32 lbl_803E2FB8;
extern f32 lbl_803E2FBC;
extern f32 lbl_803E2FC0;
extern f32 lbl_803E2FC4;
extern f64 lbl_803E2F90;
extern f32 lbl_803E2FD8;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FE0;
extern f32 lbl_803E2FE4;
extern f32 lbl_803E2FE8;
extern f32 lbl_803E2FEC;
extern f32 lbl_803E2FF0;
extern f32 lbl_803E2FF4;
extern f32 lbl_803E2FF8;
extern f32 lbl_803E2FFC;
extern f32 lbl_803E3000;

extern f32 sqrtf(f32 x);

typedef void (*ExpgfxSpawnObjectFn)(int obj, int objectId, void *params, int mode,
                                    int preferredPoolIdx, void *outObj);

#define TUMBLEWEED_TYPE_1 0x39d
#define TUMBLEWEED_TYPE_3 0x4ba
#define TUMBLEWEED_TYPE_4 0x4c1

#define TUMBLEWEED_EFFECT_BURST_SPECIAL 0x34d
#define TUMBLEWEED_EFFECT_BURST_DEFAULT 0x32e
#define TUMBLEWEED_EFFECT_PUFF_SPECIAL 0x34c
#define TUMBLEWEED_EFFECT_PUFF_DEFAULT 0x32d
#define TUMBLEWEED_EFFECT_SPAWN_COUNT 0x14
#define TUMBLEWEED_EXPGFX_MODE_ACTIVE 2

/*
 * --INFO--
 *
 * Function: tumbleweed_update
 * EN v1.0 Address: 0x80164EE4
 * EN v1.0 Size: 72b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_update(int obj) {
    if (*(s16*)(obj + 0x46) == TUMBLEWEED_TYPE_1) {
        tumbleweed_updateTargetedStateMachine(obj);
    } else {
        tumbleweed_updateStateMachine(obj);
    }
    tumbleweed_updateEffects(obj);
}
#pragma pop

/* 8b "li r3, N; blr" returners. */
int fn_801650D0(void) { return 0x0; }

/*
 * --INFO--
 *
 * Function: tumbleweed_updateStateMachine
 * EN v1.0 Address: 0x801641B0
 * EN v1.0 Size: 1936b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_updateStateMachine(int obj) {
    int aux;
    int sphereIndex;
    u32 hitVolume;
    int hitObject;
    u32 popMsg;
    int *player;
    int *tricky;

    aux = *(int*)(obj + 0xb8);
    {
        u32 state = *(u8*)(aux + 0x278);
    if (state == 0) {
        if (*(f32*)(obj + 0x8) < *(f32*)(aux + 0x26c)) {
            *(f32*)(obj + 0x8) = *(f32*)(aux + 0x270) * timeDelta + *(f32*)(obj + 0x8);
        } else {
            *(u8*)(aux + 0x278) = 1;
        }
    } else if (state == 1) {
        if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0) {
            ObjHits_EnableObject(obj);
            *(u8*)(aux + 0x278) = 2;
            *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 3);
            if (*(s16*)(obj + 0x46) == TUMBLEWEED_TYPE_4) {
                *(f32*)(aux + 0x2a0) = lbl_803E2F9C;
            }
        }
    } else if (state == 2) {
        f32 dx, dz, dist2;
        f32 d;
        player = (int*)Obj_GetPlayerObject();
        dx = *(f32*)(obj + 0xc) - *(f32*)((char*)player + 0xc);
        dz = *(f32*)(obj + 0x14) - *(f32*)((char*)player + 0x14);
        dist2 = dx*dx + dz*dz;
        tricky = (int*)getTrickyObject();
        if (tricky != 0 && *(s16*)((char*)tricky + 0x46) == 0x24) {
            f32 ndx, ndz, ndist2;
            if (dist2 < lbl_803E2FA0) {
                (*(int(**)(int, int, int, int))(*(int*)((char*)tricky + 0x68) + 0x28))((int)tricky, obj, 0, 1);
            }
            ndx = *(f32*)(obj + 0xc) - *(f32*)((char*)tricky + 0xc);
            ndz = *(f32*)(obj + 0x14) - *(f32*)((char*)tricky + 0x14);
            ndist2 = ndx*ndx + ndz*ndz;
            if (ndist2 < dist2) {
                dx = ndx;
                dz = ndz;
                dist2 = ndist2;
            }
        }
        d = sqrtf(dist2);
        *(s16*)(aux + 0x268) = (s32)d;
        {
            f32 dpx = *(f32*)(obj + 0xc) - *(f32*)(aux + 0x288);
            f32 dpz = *(f32*)(obj + 0x14) - *(f32*)(aux + 0x28c);
            longlong local_70 = (longlong)(s32)sqrtf(dpx*dpx + dpz*dpz);
            u32 uStack_64;
            *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~8);
            uStack_64 = *(u16*)(aux + 0x268);
            if ((f32)((f64)CONCAT44(0x43300000, uStack_64) - lbl_803E2F90) < lbl_803E2FA4 && uStack_64 != 0) {
                f32 denom = lbl_803E2FA8 * ((f32)((f64)CONCAT44(0x43300000, uStack_64) - lbl_803E2F90) - lbl_803E2FA4);
                *(f32*)(obj + 0x24) = *(f32*)(obj + 0x24) - dx / denom;
                uStack_64 = *(u16*)(aux + 0x268);
                *(f32*)(obj + 0x2c) = *(f32*)(obj + 0x2c) - dz / denom;
                *(s16*)(aux + 0x27c) = (s32)(lbl_803E2FAC * *(f32*)(obj + 0x24));
                *(s16*)(aux + 0x27e) = (s32)(lbl_803E2FAC * *(f32*)(obj + 0x2c));
                *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 8);
            } else {
                u32 dpdi = (s32)local_70 & 0xffff;
                if ((f32)((f64)CONCAT44(0x43300000, dpdi) - lbl_803E2F90) > lbl_803E2F5C && dpdi != 0) {
                    f32 denom = lbl_803E2F5C * ((f32)((f64)CONCAT44(0x43300000, dpdi) - lbl_803E2F90));
                    *(f32*)(obj + 0x24) = *(f32*)(obj + 0x24) - dpx / denom;
                    *(f32*)(obj + 0x2c) = *(f32*)(obj + 0x2c) - dpz / denom;
                }
            }
        }
        tumbleweed_updateRollingMotion(obj, aux);
        (*(int(**)(int, int, f32))(*(int*)lbl_803DCAA8 + 0x18))(obj, aux, timeDelta);
        *(f32*)(aux + 0x2a0) = *(f32*)(aux + 0x2a0) - timeDelta;
        if (*(f32*)(aux + 0x2a0) >= lbl_803E2F68) {
            if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                *(s16*)(hitObject + 0x46) != *(s16*)(obj + 0x46)) {
                if (*(s16*)(obj + 0x46) == TUMBLEWEED_TYPE_3) {
                    *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 3);
                    *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~0x10);
                    *(u8*)(aux + 0x278) = 3;
                    *(f32*)(aux + 0x270) = lbl_803E2FB0;
                    *(f32*)(aux + 0x2a0) = lbl_803E2FB4;
                    Obj_SetActiveModelIndex(obj, 1);
                } else {
                    *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 7);
                }
            }
        } else {
            *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 7);
        }
    } else if (state == 3) {
        f32 d;
        player = (int*)Obj_GetPlayerObject();
        d = getXZDistance((f32*)((char*)player + 0x18), (f32*)(obj + 0x18));
        if (d < lbl_803E2FB8) {
            *(s16*)(aux + 0x298) = 0x195;
            *(s16*)(aux + 0x29a) = 0;
            *(f32*)(aux + 0x29c) = lbl_803E2F98;
            ObjMsg_SendToObject((int)player, 0x7000a, obj, (int*)(aux + 0x298));
            *(u8*)(aux + 0x278) = 4;
        } else {
            *(f32*)(aux + 0x270) = *(f32*)(aux + 0x270) - timeDelta;
            *(f32*)(aux + 0x2a0) = *(f32*)(aux + 0x2a0) - timeDelta;
            if (*(f32*)(aux + 0x2a0) < lbl_803E2F68) {
                *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 7);
            } else if (*(f32*)(aux + 0x270) <= lbl_803E2F68) {
                *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 7);
            } else {
                if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                    *(s16*)(hitObject + 0x46) != *(s16*)(obj + 0x46)) {
                    *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 7);
                }
            }
            fn_80163990(obj, aux);
            (*(int(**)(int, int, f32))(*(int*)lbl_803DCAA8 + 0x18))(obj, aux, timeDelta);
        }
    } else if (state == 4) {
        while (ObjMsg_Pop(obj, &popMsg, (u32*)0, (u32*)0) != 0) {
            if (popMsg == 0x7000b) {
                gameBitIncrement(0x194);
                Sfx_PlayFromObject(obj, 0x49);
                *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 7);
            }
        }
    } else if (state == 6) {
        f32 *target = *(f32**)(aux + 0x290);
        f32 vx, vy, vz, d;
        vx = target[0] - *(f32*)(obj + 0xc);
        vy = target[1] - *(f32*)(obj + 0x10);
        vz = target[2] - *(f32*)(obj + 0x14);
        d = sqrtf(vx*vx + vy*vy + vz*vz);
        vx /= d; vy /= d; vz /= d;
        *(f32*)(aux + 0x294) = timeDelta * lbl_803E2F98 + *(f32*)(aux + 0x294);
        *(f32*)(obj + 0x24) = lbl_803E2FBC * vx * *(f32*)(aux + 0x294);
        *(f32*)(obj + 0x28) = lbl_803E2FBC * vy * *(f32*)(aux + 0x294);
        *(f32*)(obj + 0x2c) = lbl_803E2FBC * vz * *(f32*)(aux + 0x294);
        d = getXZDistance((f32*)(obj + 0xc), *(f32**)(aux + 0x290));
        objMove(obj, *(f32*)(obj + 0x24) * timeDelta, *(f32*)(obj + 0x28) * timeDelta, *(f32*)(obj + 0x2c) * timeDelta);
        if (getXZDistance((f32*)(obj + 0xc), *(f32**)(aux + 0x290)) > d) {
            *(f32*)(obj + 0xc) = (*(f32**)(aux + 0x290))[0] + (*(f32*)(obj + 0xc) - (*(f32**)(aux + 0x290))[0]) * lbl_803E2F98;
            *(f32*)(obj + 0x10) = (*(f32**)(aux + 0x290))[1] + (*(f32*)(obj + 0x10) - (*(f32**)(aux + 0x290))[1]) * lbl_803E2F98;
            *(f32*)(obj + 0x14) = (*(f32**)(aux + 0x290))[2] + (*(f32*)(obj + 0x14) - (*(f32**)(aux + 0x290))[2]) * lbl_803E2F98;
        }
    } else if (state == 7) {
        u32 j;
        for (j = 0; (s32)(j & 0xffff) < (s32)timeDelta; j = j + 1) {
            *(f32*)(obj + 0x8) = *(f32*)(obj + 0x8) * lbl_803E2FC0;
        }
        *(f32*)(obj + 0xc) = (*(f32**)(aux + 0x290))[0];
        *(f32*)(obj + 0x10) = (*(f32**)(aux + 0x290))[1];
        *(f32*)(obj + 0x14) = (*(f32**)(aux + 0x290))[2];
    } else {
        if (*(f32*)(aux + 0x270) <= lbl_803E2F68) {
            Obj_FreeObject(obj);
        } else {
            *(f32*)(aux + 0x270) = *(f32*)(aux + 0x270) - timeDelta;
        }
    }
    }
}
#pragma pop

/*
 * --INFO--
 *
 * Function: tumbleweed_init
 * EN v1.0 Address: 0x80164F2C
 * EN v1.0 Size: 420b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_init(int obj, int defData) {
    int aux = *(int*)(obj + 0xb8);

    *(f32*)(aux + 0x288) = *(f32*)(obj + 0xc);
    *(f32*)(aux + 0x28c) = *(f32*)(obj + 0x14);
    *(s16*)(aux + 0x26a) = (short)(lbl_803E2FCC * *(f32*)(defData + 0x1c));
    *(u8*)(aux + 0x279) = *(u8*)(defData + 0x1b);
    *(f32*)(aux + 0x26c) = *(f32*)(obj + 0x8);
    *(f32*)(aux + 0x270) = *(f32*)(aux + 0x26c) / (f32)(s32)randomGetRange(0xc8, 0x1f4);
    *(u32*)(aux + 0x284) = 0;
    *(f32*)(obj + 0x8) = lbl_803E2FD0;
    (*(int(**)(int, int, int, int))(*(int*)lbl_803DCAA8 + 0x4))(aux, 0, 0x40000, 1);
    (*(int(**)(int, int, void*, void*, int))(*(int*)lbl_803DCAA8 + 0x8))(aux, 1, lbl_80320288, lbl_803DBD40, 8);
    (*(int(**)(int, int))(*(int*)lbl_803DCAA8 + 0x20))(obj, aux);
    *(u8*)(aux + 0x278) = 0;
    *(f32*)(aux + 0x2a0) = lbl_803E2FB4 + (f32)(s32)randomGetRange(-0x12c, 0x12c);
    ObjGroup_AddObject(obj, 3);
    ObjGroup_AddObject(obj, 0x31);
    ObjHits_DisableObject(obj);
    ObjMsg_AllocQueue(obj, 1);
    if (*(s16*)(obj + 0x46) == TUMBLEWEED_TYPE_3) {
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 0x10);
    }
}
#pragma pop

/*
 * --INFO--
 *
 * Function: tumbleweed_updateEffects
 * EN v1.0 Address: 0x80164C44
 * EN v1.0 Size: 672b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_updateEffects(int obj) {
    int aux = *(int*)(obj + 0xb8);
    int i;
    s16 type;

    if ((*(u8*)(aux + 0x27a) & 1) != 0) {
        switch (*(s16*)(obj + 0x46)) {
        case TUMBLEWEED_TYPE_3:
        case TUMBLEWEED_TYPE_1:
        case TUMBLEWEED_TYPE_4:
            i = TUMBLEWEED_EFFECT_SPAWN_COUNT;
            do {
                ((ExpgfxSpawnObjectFn)(*(u32 *)(*(int *)pDll_expgfx + 0x8)))
                    (obj, TUMBLEWEED_EFFECT_BURST_SPECIAL, 0,
                     TUMBLEWEED_EXPGFX_MODE_ACTIVE, -1, 0);
                i = i - 1;
            } while (i != 0);
            break;
        default:
            i = TUMBLEWEED_EFFECT_SPAWN_COUNT;
            do {
                ((ExpgfxSpawnObjectFn)(*(u32 *)(*(int *)pDll_expgfx + 0x8)))
                    (obj, TUMBLEWEED_EFFECT_BURST_DEFAULT, 0,
                     TUMBLEWEED_EXPGFX_MODE_ACTIVE, -1, 0);
                i = i - 1;
            } while (i != 0);
            break;
        }
        Sfx_PlayFromObject(obj, 0x27d);
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~1);
    }

    if ((*(u8*)(aux + 0x27a) & 2) != 0) {
        switch (*(s16*)(obj + 0x46)) {
        case TUMBLEWEED_TYPE_3:
        case TUMBLEWEED_TYPE_1:
        case TUMBLEWEED_TYPE_4:
            ((ExpgfxSpawnObjectFn)(*(u32 *)(*(int *)pDll_expgfx + 0x8)))
                (obj, TUMBLEWEED_EFFECT_PUFF_SPECIAL, 0, TUMBLEWEED_EXPGFX_MODE_ACTIVE, -1, 0);
            break;
        default:
            ((ExpgfxSpawnObjectFn)(*(u32 *)(*(int *)pDll_expgfx + 0x8)))
                (obj, TUMBLEWEED_EFFECT_PUFF_DEFAULT, 0, TUMBLEWEED_EXPGFX_MODE_ACTIVE, -1, 0);
            break;
        }
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~2);
    }

    if ((*(u8*)(aux + 0x27a) & 4) != 0) {
        *(u8*)(obj + 0x36) = 0;
        *(u8*)(aux + 0x278) = 5;
        *(f32*)(aux + 0x270) = lbl_803E2FC8;
        ObjHits_DisableObject(obj);
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~4);
    }

    if ((*(u8*)(aux + 0x27a) & 0x10) != 0 && (*(u16*)(obj + 0xb0) & 0x800) != 0) {
        u32 r;
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        r = *(u8*)(aux + 0x27b);
        r = r + 1;
        *(u8*)(aux + 0x27b) = (u8)r;
        if ((int)(r & 0xff) % 6 == 0) {
            fn_80098B18(obj, *(f32*)(obj + 0x8), 1, 0, 0, 0);
        } else {
            fn_80098B18(obj, *(f32*)(obj + 0x8), 1, 3, 0, 0);
        }
        Sfx_KeepAliveLoopedObjectSound(obj, 0x451);
    }
}
#pragma pop

/*
 * --INFO--
 *
 * Function: fn_801650D8
 * EN v1.0 Address: 0x801650D8
 * EN v1.0 Size: 176b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
int fn_801650D8(int obj, int target) {
    int *aux = *(int**)(obj + 0xb8);
    if ((s8)*(u8*)(target + 0x27a) != 0) {
        (*(int(**)(int, int, int, int))(*(int*)lbl_803DCAB8 + 0x4c))(obj, (int)*(s16*)((char*)aux + 0x3f0), -1, 0);
        (*(int(**)(int, int, int, int, int))(*(int*)lbl_803DCA8C + 0x58))(obj, target, 0x3c, 0xa, 0);
        GameBit_Set((int)*(s16*)((char*)aux + 0x3f2), 1);
        *(u8*)((char*)aux + 0x405) = 0;
    }
    return 0;
}
#pragma pop

/*
 * --INFO--
 *
 * Function: fn_80165188
 * EN v1.0 Address: 0x80165188
 * EN v1.0 Size: 592b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
int fn_80165188(int obj, u32 *stateWord) {
    f32 horizontalDamping;
    int state;

    state = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
    *(u8 *)((int)stateWord + 0x34d) = 3;
    if (*(s8 *)((int)stateWord + 0x27a) != 0) {
        ObjHits_DisableObject(obj);
        *(f32 *)(obj + 0x24) = -*(f32 *)(obj + 0x24);
        *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) + lbl_803E2FD8;
        *(f32 *)(obj + 0x2c) = -*(f32 *)(obj + 0x2c);
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2FDC, 0);
        *(f32 *)(state + 0x44) = lbl_803E2FE0;
    }
    *(u8 *)(*(int *)(obj + 0x54) + 0x6d) = 0;
    *stateWord = *stateWord | 0x4000;
    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) * (horizontalDamping = lbl_803E2FE4);
    *(f32 *)(obj + 0x28) = lbl_803E2FE8 * (*(f32 *)(obj + 0x28) - lbl_803E2FEC);
    *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) * horizontalDamping;
    objMove(obj, *(f32 *)(obj + 0x24), *(f32 *)(obj + 0x28), *(f32 *)(obj + 0x2c));
    if (*(f32 *)(obj + 0xc) < *(f32 *)(state + 0x48)) {
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x48);
        *(f32 *)(obj + 0x24) = lbl_803E2FF0 * -*(f32 *)(obj + 0x24);
    }
    if (*(f32 *)(obj + 0xc) > *(f32 *)(state + 0x4c)) {
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x4c);
        *(f32 *)(obj + 0x24) = lbl_803E2FF0 * -*(f32 *)(obj + 0x24);
    }
    if (*(f32 *)(obj + 0x10) < *(f32 *)(state + 0x5c)) {
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x5c);
        *(f32 *)(obj + 0x28) = lbl_803E2FF0 * -*(f32 *)(obj + 0x28);
    }
    if (*(f32 *)(obj + 0x10) > *(f32 *)(state + 0x58)) {
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x58);
        *(f32 *)(obj + 0x28) = lbl_803E2FF0 * -*(f32 *)(obj + 0x28);
    }
    if (*(f32 *)(obj + 0x14) < *(f32 *)(state + 0x54)) {
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x54);
        *(f32 *)(obj + 0x2c) = lbl_803E2FF0 * -*(f32 *)(obj + 0x2c);
    }
    if (*(f32 *)(obj + 0x14) > *(f32 *)(state + 0x50)) {
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x50);
        *(f32 *)(obj + 0x2c) = lbl_803E2FF0 * -*(f32 *)(obj + 0x2c);
    }
    if (lbl_803E2FF4 == *(f32 *)(obj + 0x98)) {
        ObjMsg_SendToObjects(0, 3, (void *)obj, 0xe0000, obj);
        Obj_FreeObject(obj);
        return 0;
    } else {
        *(u8 *)(obj + 0x36) = (u8)(255 - (s32)(lbl_803E2FF8 * *(f32 *)(obj + 0x98)));
    }
    return 0;
}
#pragma pop

/*
 * --INFO--
 *
 * Function: fn_801653D8
 * EN v1.0 Address: 0x801653D8
 * EN v1.0 Size: 436b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
int fn_801653D8(int obj, int stateWord) {
    f32 scale;
    int player;
    int state;
    f32 x;
    f32 y;
    f32 z;
    int countdown;

    state = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
    player = (int)Obj_GetPlayerObject();
    *(u8 *)(stateWord + 0x34d) = 1;
    if (*(s8 *)(stateWord + 0x27a) != 0) {
        *(u16 *)(state + 0x8e) = 0x3c;
        *(f32 *)(state + 0x60) = lbl_803E2FFC;
        ObjHits_DisableObject(obj);
    }
    if (*(u8 *)(state + 0x90) == 6) {
        goto use_player_reflect_position;
    }
    if (player == 0) {
        goto use_object_position;
    }
    if (*(f32 *)(player + 0x18) < *(f32 *)(state + 0x48)) {
        goto use_object_position;
    }
    if (*(f32 *)(player + 0x18) > *(f32 *)(state + 0x4c)) {
        if (*(f32 *)(player + 0x1c) < *(f32 *)(state + 0x5c)) {
            goto use_object_position;
        }
    }
    if (*(f32 *)(player + 0x1c) > *(f32 *)(state + 0x58)) {
        if (*(f32 *)(player + 0x20) < *(f32 *)(state + 0x54)) {
            goto use_object_position;
        }
    }
    if (*(f32 *)(player + 0x20) > *(f32 *)(state + 0x50)) {
        goto use_object_position;
    }
    goto use_player_reflect_position;
use_object_position:
    {
        x = *(f32 *)(obj + 0xc);
        y = *(f32 *)(obj + 0x10);
        z = *(f32 *)(obj + 0x14);
        scale = lbl_803E2FDC;
        goto update_action;
    }
use_player_reflect_position:
    {
        x = *(f32 *)(obj + 0xc) - lbl_803E3000 * (*(f32 *)(player + 0xc) - *(f32 *)(obj + 0xc));
        y = *(f32 *)(obj + 0x10) - lbl_803E3000 * (*(f32 *)(player + 0x10) - *(f32 *)(obj + 0x10));
        z = *(f32 *)(obj + 0x14) - lbl_803E3000 * (*(f32 *)(player + 0x14) - *(f32 *)(obj + 0x14));
        scale = lbl_803E2FF4;
    }
update_action:
    fn_80166A50(x, y, z, scale, obj);
    if (*(u8 *)(state + 0x90) == 6) {
        if (((*(u8 *)(state + 0x92) >> 2) & 1) == 0) {
            fn_80166444(obj, state);
        } else {
            fn_80165B3C(obj, state);
        }
    } else {
        fn_80165C8C(obj, state);
    }
    countdown = *(u16 *)(state + 0x8e);
    if (countdown > (int)(u32)framesThisStep) {
        *(u16 *)(state + 0x8e) = countdown - (u32)framesThisStep;
        return 0;
    }
    return 2;
}
#pragma pop
