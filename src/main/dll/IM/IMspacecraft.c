#include "ghidra_import.h"
#include "main/dll/IM/IMspacecraft.h"

#define SFXsp_lf_mutter1 262
#define SFXsp_lf_mutter4 265

/* SDK / engine externs */
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 *a, f32 *b);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_PlayFromObjectLimited(int obj, int sfxId, int p3);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern int fn_8001CC9C(int obj, int a, int b, int c, int d);
extern void fn_8001CB3C(void *p);
extern void lightDistAttenFn_8001dc38(void *p, f32 a, f32 b);
extern f32 Curve_AdvanceAlongPath(void *state, f32 t);
extern s16 getAngle(f32 dx, f32 dz);

extern void ObjHitbox_SetSphereRadius(int obj, int r);
extern void ObjHits_SetHitVolumeSlot(int obj, u8 slot, int a, int b);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern int ObjHits_GetPriorityHit(int obj, int *outHitObj, int *outB, u32 *outC);
extern int *ObjGroup_GetObjects(int groupId, int *outCount);
extern void ObjGroup_RemoveObject(int obj, int groupId);
extern void ObjGroup_AddObject(int obj, int groupId);
extern int *objFindTexture(int obj, int a, int b);
extern void Obj_TransformLocalVectorByWorldMatrix(int obj, f32 *in, f32 *out);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern void Obj_FreeObject(int obj);

extern void spawnExplosion(int obj, int p2, int p3, int p4, int p5, int p6, int p7, int p8, f32 size);
extern void CameraShake_Start(int obj, f32 a, f32 b, f32 c);
extern void doRumble(f32 v);

extern void objRenderFn_8003b8f4(f32 v);
extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern int getEnvfxAct(int obj, int player, int id, int p);
extern void MMP_levelcontrol_update(int obj);
extern void fn_801A5D88(int obj, int unused);

extern int *gCameraInterface;
extern int *gObjectTriggerInterface;
extern int *gRomCurveInterface;

extern f32 timeDelta;
extern u8 framesThisStep;
extern int lbl_802C22F8[4];
extern s16 lbl_803DBED0;
extern s32 lbl_803DBED4;
extern s32 lbl_803DBED8;
extern s16 lbl_803DDB20;

extern f32 lbl_803E4430;
extern f32 lbl_803E4440;
extern f32 lbl_803E4444;
extern f32 lbl_803E4448;
extern f32 lbl_803E444C;
extern f32 lbl_803E4450;
extern f32 lbl_803E4454;
extern f32 lbl_803E4458;
extern int lbl_803E4460;
extern int lbl_803E4464;
extern f32 lbl_803E4468;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;
extern f32 lbl_803E449C;
extern f32 lbl_803E44A0;
extern f32 lbl_803E44A4;
extern f32 lbl_803E44A8;
extern f32 lbl_803E44AC;
extern f32 lbl_803E44B0;
extern f32 lbl_803E44B4;
extern f32 lbl_803E44B8;
extern f32 lbl_803E44C0;
extern f32 lbl_803E44C4;

extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;

/* Trivial 4b 0-arg blr leaves. */
void SpiritDoorLock_hitDetect(void) {}
void SpiritDoorLock_release(void) {}
void SpiritDoorLock_initialise(void) {}
void RollingBarrel_hitDetect(void) {}
void RollingBarrel_release(void) {}
void MMP_levelcontrol_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int SpiritDoorLock_getExtraSize(void) { return 0x14; }
int SpiritDoorLock_getObjectTypeId(void) { return 0x0; }
int RollingBarrel_getExtraSize(void) { return 0x118; }
int RollingBarrel_getObjectTypeId(void) { return 0x0; }
int MMP_levelcontrol_getExtraSize(void) { return 0x0; }
int MMP_levelcontrol_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
void RollingBarrel_initialise(void) { lbl_803DDB20 = 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off
void SpiritDoorLock_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4440); }
void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E44C4); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void RollingBarrel_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    u8 *inner = *(u8 **)(obj + 0xb8);
    if (visible != 0 && inner[0x114] < 1) {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4474);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void SpiritDoorLock_free(int obj) {
    void *inner = *(void **)(obj + 0xb8);
    if (*(void **)inner != NULL) {
        fn_8001CB3C(inner);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void MMP_levelcontrol_free(int obj) {
    lbl_803DDB28 = lbl_803E44C0;
    lbl_803DDB2C = 0;
    Music_Trigger(0xd5, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void RollingBarrel_free(int obj) {
    char *inner = *(char **)(obj + 0xb8);
    int count;
    int *arr = ObjGroup_GetObjects(0x2f, &count);
    int i;
    for (i = 0; i < count; i++) {
        if ((u32)obj == (u32)arr[i]) {
            ObjGroup_RemoveObject(obj, 0x2f);
            break;
        }
    }
    if (*(u8 *)(inner + 0x114) == 1) {
        lbl_803DDB20 -= 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void RollingBarrel_init(int obj, int *params)
{
    int *state = *(int **)((char *)obj + 0xb8);
    int tmp[2];

    tmp[0] = lbl_803E4460;
    tmp[1] = lbl_803E4464;
    params[5] = -1;
    *(s16 *)((char *)obj + 6) = (s16)(*(s16 *)((char *)obj + 6) & ~0x4000);
    *(s16 *)((char *)obj + 4) = 0x4000;

    *(f32 *)((char *)obj + 12) = *(f32 *)((char *)params + 8);
    *(f32 *)((char *)obj + 24) = *(f32 *)((char *)params + 8);
    *(f32 *)((char *)obj + 16) = *(f32 *)((char *)params + 12);
    *(f32 *)((char *)obj + 28) = *(f32 *)((char *)params + 12);
    *(f32 *)((char *)obj + 20) = *(f32 *)((char *)params + 16);
    *(f32 *)((char *)obj + 32) = *(f32 *)((char *)params + 16);

    *(f32 *)((char *)state + 0x10c) = (f32) * (s16 *)((char *)params + 0x1a) / lbl_803E447C;
    *(f32 *)((char *)state + 0x108) = (f32) * (s16 *)((char *)params + 0x1c) / lbl_803E447C;
    *(u8 *)((char *)state + 0x114) = 0;
    *(u8 *)((char *)state + 0x115) = 1;
    *(f32 *)((char *)state + 0x110) = lbl_803E4468;

    ((void (*)(int *, int, int *, int, f32))((void **)*gRomCurveInterface)[35])(state, obj, tmp, -1, lbl_803E44B8);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void SpiritDoorLock_init(int obj, int *params, int mode)
{
    int *state = *(int **)((char *)obj + 0xb8);
    f32 mult;

    *(s16 *)obj = (s16)((s8) * (s8 *)((char *)params + 0x18) << 8);
    state[3] = *(s16 *)((char *)params + 0x1a);
    state[2] = 0;

    mult = (f32)*(s8 *)((char *)params + 0x19) * lbl_803E4448;
    if (mult < lbl_803E4430) {
        mult = lbl_803E4440;
    }
    *(f32 *)((char *)obj + 8) = (*(f32 **)((char *)obj + 0x50))[1] * mult;
    state[1] = 0;

    ObjHits_DisableObject(obj);
    *(u8 *)((char *)state + 0x10) &= ~0x80;

    if (mode == 0) {
        *(u8 *)((char *)obj + 0x36) = 0;
        state[0] = fn_8001CC9C(obj, 255, 0, 77, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void SpiritDoorLock_update(int obj)
{
    int *state;
    int *descriptor;
    int player;
    int local_68;
    f32 local_58[3];
    f32 local_5c[3];

    ((int *)local_58)[0] = lbl_802C22F8[0];
    ((int *)local_58)[1] = lbl_802C22F8[1];
    ((int *)local_58)[2] = lbl_802C22F8[2];

    state = *(int **)((char *)obj + 0xb8);
    descriptor = *(int **)((char *)obj + 0x4c);

    player = Obj_GetPlayerObject();

    if (GameBit_Get(0xab9) == 0) {
        if (Vec_xzDistance((f32 *)((char *)obj + 0x18), (f32 *)((char *)player + 0x18)) < lbl_803E4444) {
            if (state[2] != 0) {
                ((void (*)(int, int, int))((void **)*gObjectTriggerInterface)[18])(0, obj, -1);
            }
            GameBit_Set(0xab9, 1);
        }
    }

    if (state[2] == 0) {
        if (GameBit_Get(*(s16 *)((char *)descriptor + 0x1e)) == 0) {
            state[2] = GameBit_Get(*(s16 *)((char *)descriptor + 0x20));
            if (state[2] != 0) {
                *(f32 *)((char *)obj + 8) =
                    (*(f32 **)((char *)obj + 0x50))[1] *
                    (f32)(int)*(s8 *)((char *)descriptor + 0x19) *
                    lbl_803E4448;
                if (state[0] == 0) {
                    state[0] = fn_8001CC9C(obj, 0xff, 0, 0x4d, 0);
                }
            }
        } else {
            if (*(s8 *)((char *)obj + 0x36) == -1) {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            if (*(u8 *)((char *)obj + 0x36) == 0) {
                if (state[0] != 0) {
                    fn_8001CB3C(state);
                }
            } else {
                *(u8 *)((char *)obj + 0x36) -= 1;
                if (state[0] != 0) {
                    u32 b = *(u8 *)((char *)obj + 0x36) >> 2;
                    lightDistAttenFn_8001dc38((void *)state[0], (f32)(int)b, (f32)(int)(b + 10));
                }
                *(f32 *)((char *)obj + 8) *= lbl_803E444C;
                *(s16 *)((char *)obj + 4) =
                    (s16)(s32)((f32)(int)*(s16 *)((char *)obj + 4) - lbl_803E4450 * timeDelta);
            }
        }
    } else {
        int cam_state;
        int *list_ptr;
        int *piTex;
        int i;
        s16 angle;
        s16 stride;
        f32 max_dist;
        cam_state = ((int (*)(void))((void **)*gCameraInterface)[4])();
        if (cam_state != 0x51) {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x423);
        }
        list_ptr = ObjGroup_GetObjects(0x4e, &local_68);
        stride = (s16)(0x10000 / state[3]);
        angle = (s16)state[1];
        local_58[1] = lbl_803E4454;
        max_dist = lbl_803E4458;
        for (i = 0; i < local_68; i++) {
            if (Vec_distance((f32 *)((char *)obj + 0x18), (f32 *)((char *)list_ptr[i] + 0x18)) <= max_dist) {
                *(s16 *)((char *)obj + 4) = angle;
                Obj_TransformLocalVectorByWorldMatrix(obj, local_58, local_5c);
                PSVECAdd((f32 *)((char *)obj + 0xc), local_5c, (f32 *)((char *)list_ptr[i] + 0xc));
                *(s16 *)list_ptr[i] = *(s16 *)obj;
                *(s16 *)((char *)list_ptr[i] + 4) = (s16)(angle + 0x8000);
                *(f32 *)((char *)list_ptr[i] + 8) = *(f32 *)((char *)obj + 8);
                angle = (s16)(angle + stride);
            }
        }
        state[1] += (int)lbl_803DBED0;
        *(s16 *)((char *)obj + 4) = 0;
        if (local_68 == 0) {
            state[2] = 0;
            GameBit_Set(*(s16 *)((char *)descriptor + 0x1e), 1);
            ObjHits_DisableObject(obj);
        }
        piTex = objFindTexture(obj, 0, 0);
        if (piTex != NULL) {
            *(s16 *)((char *)piTex + 0xa) = (s16)(*(s16 *)((char *)piTex + 0xa) + lbl_803DBED4 * (s32)framesThisStep);
            *(s16 *)((char *)piTex + 0x8) = (s16)(*(s16 *)((char *)piTex + 0x8) + lbl_803DBED4 * (s32)framesThisStep);
            if ((s32) * (s16 *)((char *)piTex + 0xa) > (s32)(lbl_803DBED8 << 8)) {
                *(s16 *)((char *)piTex + 0xa) = (s16)(*(s16 *)((char *)piTex + 0xa) - (lbl_803DBED8 << 8));
            }
            if ((s32) * (s16 *)((char *)piTex + 0x8) > (s32)(lbl_803DBED8 << 8)) {
                *(s16 *)((char *)piTex + 0x8) = (s16)(*(s16 *)((char *)piTex + 0x8) - (lbl_803DBED8 << 8));
            }
        }
        if (*(u8 *)((char *)obj + 0x36) < 0xff) {
            *(u8 *)((char *)obj + 0x36) += 1;
        }
    }
}
#pragma scheduling reset

#pragma scheduling off
void RollingBarrel_update(int obj)
{
    int *state;
    int *descriptor;
    f32 floor_y;
    f32 dist_sq;
    int blocked;
    int hitInfo;
    int hitB;
    u32 hitC;
    int hitResult;
    u32 r;
    u8 bVar1;

    state = *(int **)((char *)obj + 0xb8);
    hitInfo = 0;
    descriptor = *(int **)((char *)obj + 0x4c);
    blocked = 0;
    dist_sq = lbl_803E4468;
    bVar1 = *(u8 *)((char *)state + 0x114);

    if (bVar1 == 2) {
        *(f32 *)((char *)state + 0x110) += timeDelta;
        if (*(f32 *)((char *)state + 0x110) >= lbl_803E44B0) {
            *(u8 *)((char *)state + 0x116) = 0;
            *(u8 *)((char *)state + 0x114) = 3;
            *(f32 *)((char *)state + 0x110) -= lbl_803E44B0;
            ObjGroup_AddObject(obj, 0x2f);
            lbl_803DDB20 -= 1;
        }
    } else if (bVar1 < 2) {
        if (bVar1 == 0) {
            if (*(s16 *)descriptor == 0x72a) {
                f32 vmax = lbl_803E446C;
                while (blocked == 0 && dist_sq < vmax * timeDelta) {
                    blocked = (int)Curve_AdvanceAlongPath(state, *(f32 *)((char *)state + 0x108));
                    if (blocked == 0 && *(int *)((char *)state + 0x10) != 0) {
                        ((void (*)(int *))((void **)*gRomCurveInterface)[36])(state);
                    }
                    {
                        f32 dx = *(f32 *)((char *)state + 0x68) - *(f32 *)((char *)obj + 0x80);
                        f32 dz = *(f32 *)((char *)state + 0x70) - *(f32 *)((char *)obj + 0x88);
                        dist_sq = dx * dx + dz * dz;
                    }
                }
            } else {
                blocked = (int)Curve_AdvanceAlongPath(state, *(f32 *)((char *)state + 0x108));
                if (blocked == 0 && *(int *)((char *)state + 0x10) != 0) {
                    ((void (*)(int *))((void **)*gRomCurveInterface)[36])(state);
                }
            }

            *(u8 *)((char *)state + 0x116) = 10;
            ObjHitbox_SetSphereRadius(obj, *(u8 *)(*(int *)((char *)obj + 0x50) + 0x62));

            if (*(s16 *)descriptor == 0x72a) {
                floor_y = lbl_803E4478 + *(f32 *)((char *)state + 0x6c);
            } else {
                floor_y = *(f32 *)((char *)state + 0x6c);
            }

            *(f32 *)((char *)state + 0x10c) = lbl_803E4498 * timeDelta + *(f32 *)((char *)state + 0x10c);
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)state + 0x10c) * timeDelta + *(f32 *)((char *)obj + 0x10);

            if (*(f32 *)((char *)obj + 0x10) < floor_y) {
                if (*(s16 *)descriptor == 0x72a && *(f32 *)((char *)obj + 0x10) < lbl_803E449C) {
                    blocked = 1;
                }
                if (blocked == 0 && *(f32 *)((char *)state + 0x10c) * *(f32 *)((char *)state + 0x10c) > lbl_803E446C) {
                    Sfx_PlayFromObjectLimited(obj, 0x41e, 6);
                }
                *(f32 *)((char *)state + 0x10c) *= lbl_803E44A0;
                *(f32 *)((char *)obj + 0x10) = lbl_803E44A4 * floor_y - *(f32 *)((char *)obj + 0x10);
            }
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)state + 0x68);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)state + 0x70);
            *(s16 *)obj = (s16)getAngle(*(f32 *)((char *)state + 0x74), *(f32 *)((char *)state + 0x7c));

            if (*(u8 *)((char *)state + 0x115) != 0) {
                *(s16 *)((char *)obj + 4) =
                    (s16)(s32)(lbl_803E44A8 * timeDelta + (f32)(int)*(s16 *)((char *)obj + 4));
                if (*(s16 *)((char *)obj + 4) > 0x5000) {
                    *(u8 *)((char *)state + 0x115) = 0;
                }
            } else {
                *(s16 *)((char *)obj + 4) =
                    (s16)(s32) - (lbl_803E44A8 * timeDelta - (f32)(int)*(s16 *)((char *)obj + 4));
                if (*(s16 *)((char *)obj + 4) < 0x3a00) {
                    *(u8 *)((char *)state + 0x115) = 1;
                }
            }

            *(s16 *)((char *)obj + 2) =
                (s16)(s32)(lbl_803E44AC * timeDelta * *(f32 *)((char *)state + 0x108) +
                           (f32)(int)*(s16 *)((char *)obj + 2));
            hitResult = ObjHits_GetPriorityHit(obj, &hitInfo, &hitB, &hitC);

            if (blocked != 0 || hitInfo == Obj_GetPlayerObject() || (u32)(hitResult - 0xe) <= 1u ||
                hitResult == 0x13) {
                if (blocked == 0) {
                    *(u8 *)((char *)state + 0x116) = 0;
                } else {
                    *(u8 *)((char *)state + 0x116) = 5;
                }
                r = randomGetRange(0, 2);
                fn_801A5D88(obj, (int)r);
            }
        } else {
            *(f32 *)((char *)state + 0x110) += timeDelta;
            if (*(f32 *)((char *)state + 0x110) >= lbl_803E44B0) {
                *(u8 *)((char *)state + 0x114) = 2;
                *(f32 *)((char *)state + 0x110) -= lbl_803E44B0;
            }
        }
    } else if (bVar1 < 4) {
        *(f32 *)((char *)state + 0x110) += timeDelta;
        if (*(f32 *)((char *)state + 0x110) >= lbl_803E44B4) {
            Obj_FreeObject(obj);
            return;
        }
    }

    if (*(u8 *)((char *)state + 0x116) != 0) {
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, *(u8 *)((char *)state + 0x116), 1, 0);
    } else {
        ObjHits_DisableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, *(u8 *)((char *)state + 0x116), 0, 0);
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MMP_LevelControl_SeqFn(int obj, int p2, u8 *seq)
{
    int player;
    int i;

    player = Obj_GetPlayerObject();
    seq[0x56] = 0;
    for (i = 0; i < seq[0x8b]; i++) {
        u8 v = seq[0x81 + i];
        switch (v) {
        case 1:
            getEnvfxAct(obj, player, 315, 0);
            break;
        case 2:
            getEnvfxAct(obj, player, 312, 0);
            break;
        }
    }
    MMP_levelcontrol_update(obj);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801A5D88(int obj, int unused) {
    int state = *(int*)(obj + 0xb8);
    u32 r;
    u32 r2;
    int player;
    f32 dist;
    f32 falloff;
    lbl_803DDB20 += 1;
    Sfx_PlayFromObject(obj, SFXsp_lf_mutter1);
    if (lbl_803DDB20 > 1) {
        f32 size;
        r = randomGetRange(0, 1) & 0xff;
        r2 = randomGetRange(0x32, 0x3c);
        size = (f32)(int)r2;
        spawnExplosion(obj, 1, 1, 0, (int)r, 0, 0, 0, size);
    } else {
        f32 size;
        r = randomGetRange(0, 1) & 0xff;
        r2 = randomGetRange(0x32, 0x3c);
        size = (f32)(int)r2;
        spawnExplosion(obj, 1, 1, 0, (int)r, 0, 1, 0, size);
    }
    *(u8*)(state + 0x114) = 1;
    *(f32*)(state + 0x110) = lbl_803E4468;
    *(s16*)(obj + 6) = (s16)(*(s16*)(obj + 6) | 0x4000);
    ObjHitbox_SetSphereRadius(obj,
        (s32)(lbl_803E446C * (f32)(u32) * (u8*)(*(int*)(obj + 0x50) + 0x62)));
    player = (int)Obj_GetPlayerObject();
    if ((*(u16*)(player + 0xb0) & 0x1000) == 0) {
        dist = Vec_distance((f32*)(obj + 0x18), (f32*)(player + 0x18));
        if (dist <= lbl_803E4470) {
            falloff = lbl_803E4474 - dist / lbl_803E4470;
            CameraShake_Start(obj, lbl_803E4478 * falloff, lbl_803E447C * falloff, lbl_803E4480);
            doRumble(lbl_803E4484 * falloff);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
