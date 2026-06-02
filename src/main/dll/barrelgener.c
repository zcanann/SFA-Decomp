#include "main/dll/dll_80220608_shared.h"

#define SFXpda_fper_camoff 808
#define SFXpda_compassbeep 809

#pragma peephole on
#pragma scheduling on
int barrelgener_getLinkId(int obj)
{
    obj = *(int *)(obj + 0x4c);
    return *(s8 *)(obj + 0x19);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void barrelgener_queueObjectRelease(int obj, int queuedObj, int releaseFrame)
{
    int state = *(int *)(obj + 0xb8);

    *(int *)state = queuedObj;
    *(u8 *)(state + 4) = 0;
    storeZeroToFloatParam((void *)(state + 8));
    s16toFloat((void *)(state + 8), (s16)(releaseFrame - lbl_803DC398));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int barrelgener_getExtraSize(void) { return 0x10; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int barrelgener_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void barrelgener_free(int obj) { ObjGroup_RemoveObject(obj, 0x3a); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void barrelgener_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6C20);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void barrelgener_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void barrelgener_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_AddObject(obj, 0x3a);
    *(u8 *)(state + 4) = 0;
    *(void **)state = NULL;
    storeZeroToFloatParam((void *)(state + 8));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void barrelgener_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void barrelgener_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void barrelgener_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();

    if ((u32)GameBit_Get(0xadb) == 0) {
        if (Vec_distance(obj + 24, player + 24) < lbl_803E6C24) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
            GameBit_Set(0xadb, 1);
        }
    }
    if (fn_80080150(state + 8) != 0) {
        if (*(f32 *)(state + 8) <= lbl_803E6C28 && *(u8 *)(state + 4) == 0) {
            *(u8 *)(state + 4) = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6C2C, 0);
            Sfx_PlayFromObject(obj, SFXpda_fper_camoff);
            *(u8 *)(state + 0xc) = 0;
        }
        if (timerCountDown((void *)(state + 8)) != 0) {
            if (Obj_IsObjectAlive(*(int *)(state + 0)) != 0) {
                int o = *(int *)(state + 0);
                f32 c2c;
                *(f32 *)(o + 12) = *(f32 *)(obj + 12);
                *(f32 *)(o + 16) = *(f32 *)(obj + 16);
                *(f32 *)(o + 20) = *(f32 *)(obj + 20);
                *(f32 *)(o + 128) = *(f32 *)(o + 12);
                *(f32 *)(o + 132) = *(f32 *)(o + 16);
                *(f32 *)(o + 136) = *(f32 *)(o + 20);
                *(f32 *)(o + 24) = *(f32 *)(o + 12);
                *(f32 *)(o + 28) = *(f32 *)(o + 16);
                *(f32 *)(o + 32) = *(f32 *)(o + 20);
                c2c = lbl_803E6C2C;
                *(f32 *)(o + 44) = c2c;
                *(f32 *)(o + 40) = c2c;
                *(f32 *)(o + 36) = c2c;
                ObjGroup_AddObject(o, 25);
                *(int *)(state + 0) = 0;
            }
        }
    }
    if (*(u8 *)(state + 4) != 0) {
        if (*(f32 *)(obj + 0x98) > lbl_803E6C30) {
            if (*(u8 *)(state + 0xc) == 0) {
                Sfx_PlayFromObject(obj, SFXpda_compassbeep);
                *(u8 *)(state + 0xc) = 1;
            }
        }
        *(u8 *)(state + 4) = !ObjAnim_AdvanceCurrentMove(lbl_803E6C34, timeDelta, obj, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void Obj_SteerVelocityTowardVector(int out, f32 *v1, f32 *v2, f32 a, f32 b, f32 c)
{
    f32 mtx[12];
    f32 n1[3];
    f32 n2[3];
    f32 cross[3];
    f32 mag1, mag2, t, ang;

    mag1 = PSVECMag(v1);
    if (mag1 > lbl_803E6C38) {
        t = lbl_803E6C6C / mag1;
        n1[0] = v1[0] * t;
        n1[1] = v1[1] * t;
        n1[2] = v1[2] * t;
        PSVECNormalize(n1, n1);
    } else {
        n1[0] = lbl_803E6C38;
        n1[1] = lbl_803E6C38;
        n1[2] = lbl_803E6C38;
    }
    mag2 = PSVECMag(v2);
    if (mag2 > lbl_803E6C38) {
        t = lbl_803E6C6C / mag2;
        n2[0] = v2[0] * t;
        n2[1] = v2[1] * t;
        n2[2] = v2[2] * t;
    } else {
        n2[0] = lbl_803E6C38;
        n2[1] = lbl_803E6C38;
        n2[2] = lbl_803E6C38;
    }
    PSVECCrossProduct(n1, n2, cross);
    if (PSVECMag(cross) > lbl_803E6C38) {
        ang = fn_80291FF4(PSVECDotProduct(n1, n2));
        if (ang > c) {
            PSMTXRotAxisRad(mtx, cross, c * (ang > lbl_803E6C38 ? lbl_803E6C6C : lbl_803E6C70));
            PSMTXMultVecSR2(mtx, n1, n2);
        }
    }
    t = mag2 * lbl_803E6C74;
    if (t > mag1 + b)
        t = mag1 + b;
    else if (t < mag1 - b)
        t = mag1 - b;
    if (t > a)
        t = a;
    *(f32 *)(out + 0x24) = n2[0] * t;
    *(f32 *)(out + 0x28) = n2[1] * t;
    *(f32 *)(out + 0x2c) = n2[2] * t;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int Obj_UpdateRomCurveFollowVelocity(int p1, int p2, f32 a, f32 b, f32 c, int flag)
{
    f32 d[3];
    f32 dist, ang, scale;
    int result;

    result = 0;
    scale = c;
    d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
    d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b) {
        if (curveFn_80010320(p2, a) != 0 || *(int *)(p2 + 0x10) != 0) {
            if ((u8)(*(int (**)(int))(*gRomCurveInterface + 0x90))(p2) != 0)
                result = -1;
            else
                result = (s8)*(u8 *)(*(int *)(p2 + 0x9c) + 0x18);
        }
        scale = lbl_803E6C78 * a;
    }
    d[0] = *(f32 *)(p2 + 0x68) - *(f32 *)(p1 + 0xc);
    d[1] = *(f32 *)(p2 + 0x6c) - *(f32 *)(p1 + 0x10);
    d[2] = *(f32 *)(p2 + 0x70) - *(f32 *)(p1 + 0x14);
    if (flag == 0) {
        int state2 = *(int *)(p1 + 0xb8);
        d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
        d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
        ang = lbl_803E6C60 * (f32)(-(s16)getAngle(d[0], d[2])) / lbl_803E6C64;
        *(f32 *)(state2 + 0x290) = scale * -fn_80293E80(ang);
        *(f32 *)(state2 + 0x28c) = scale * -sin(ang);
    } else {
        Obj_SteerVelocityTowardVector(p1, (f32 *)(p1 + 0x24), d, scale, scale / lbl_803E6C7C, lbl_803E6C80);
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int Obj_UpdateRomCurveFollowVelocityIndexed(int p1, int p2, f32 a, f32 b, f32 c, int flag, int *p6)
{
    f32 d[3];
    f32 dist, ang, scale;
    int result;

    result = 0;
    scale = c;
    d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
    d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b) {
        if (curveFn_80010320(p2, a) != 0 || *(int *)(p2 + 0x10) != 0) {
            if ((u8)(*(int (**)(int, int))(*gRomCurveInterface + 0x9c))(p2, *p6) != 0)
                result = -1;
            else
                result = (s8)*(u8 *)(*(int *)(p2 + 0x9c) + 0x18);
            *p6 = 0;
        }
        scale = lbl_803E6C78 * a;
    }
    d[0] = *(f32 *)(p2 + 0x68) - *(f32 *)(p1 + 0xc);
    d[1] = *(f32 *)(p2 + 0x6c) - *(f32 *)(p1 + 0x10);
    d[2] = *(f32 *)(p2 + 0x70) - *(f32 *)(p1 + 0x14);
    if (flag == 0) {
        int state2 = *(int *)(p1 + 0xb8);
        d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
        d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
        ang = lbl_803E6C60 * (f32)(-(s16)getAngle(d[0], d[2])) / lbl_803E6C64;
        *(f32 *)(state2 + 0x290) = scale * -fn_80293E80(ang);
        *(f32 *)(state2 + 0x28c) = scale * -sin(ang);
    } else {
        Obj_SteerVelocityTowardVector(p1, (f32 *)(p1 + 0x24), d, scale, scale / lbl_803E6C7C, lbl_803E6C80);
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void Obj_SpawnHitLightAndFade(int obj, f32 *p2)
{
    struct {
        f32 _pad[3];
        f32 vec[3];
    } s;

    s.vec[0] = p2[0] + playerMapOffsetX;
    s.vec[1] = p2[1];
    s.vec[2] = p2[2] + playerMapOffsetZ;
    objLightFn_8009a1dc(obj, lbl_803E6C68, &s, 1, 0);
    Obj_SetModelColorFadeRecursive(obj, 0x5a, 0xc8, 0, 0, 1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_80221978(int obj, void **entries, int count, void **light, f32 intensity)
{
    int i;
    int spawned;
    void **p;
    f32 pos[3];

    spawned = 0;
    if (lbl_803E6C38 == intensity) {
        spawned = 0;
        for (i = 0, p = entries; i < count; p++, i++) {
            if (*p != 0) {
                mm_free_(*p);
                *p = 0;
            }
        }
        if (*light != 0) {
            fn_8001CB3C((int)light);
        }
        return 0;
    }

    for (i = 0, p = entries; i < count; p++, i++) {
        if (*p != 0) {
            renderFn_8008f904(*p);
            *(u16 *)((char *)*p + 0x20) += framesThisStep;
            if ((f32)(u32)*(u16 *)((char *)*p + 0x20) > lbl_803DC3A8) {
                mm_free_(*p);
                *p = 0;
            }
        } else if (spawned == 0) {
            pos[0] = *(f32 *)(obj + 0xc);
            pos[1] = *(f32 *)(obj + 0x10);
            pos[2] = *(f32 *)(obj + 0x14);
            pos[0] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[1] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[2] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            *p = fn_8008FB20((f32 *)(obj + 0xc), pos, lbl_803DC3A0, lbl_803DC3A4,
                             (int)lbl_803DC3A8, (u8)lbl_803DC3AC, 0);
            spawned = 1;
        }
    }

    if (*light == 0) {
        *light = (void *)fn_8001CC9C(obj, 0x80, 0x80, 0xff, 0);
        if (*light != 0) {
            lightVecFn_8001dd88(*light, lbl_803E6C38, intensity * lbl_803E6C40, lbl_803E6C38);
            lightDistAttenFn_8001dc38(*light, intensity, lbl_803E6C44 + intensity);
        }
    }
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void Obj_SmoothTurnAnglesTowardVelocity(int a, int b, int c, f32 d, f32 e)
{
    f32 rate;
    f32 delta;
    f32 clamped;
    f32 dist;
    int tmp;

    rate = timeDelta / (f32)(u32)(u16)c;
    if (rate > lbl_803E6C6C) {
        rate = lbl_803E6C6C;
    }

    delta = (f32)(int)((u16)getAngle(-*(f32 *)(b + 0), -*(f32 *)(b + 8)) - (u16)*(s16 *)(a + 0));
    if (delta > lbl_803E6C64) {
        delta = lbl_803E6C84 + delta;
    }
    if (delta < lbl_803E6C8C) {
        delta = lbl_803E6C88 + delta;
    }
    delta *= rate;
    if (delta < lbl_803E6C90) {
        clamped = lbl_803E6C90;
    } else if (delta > lbl_803E6C94) {
        clamped = lbl_803E6C94;
    } else {
        clamped = delta;
    }
    *(s16 *)(a + 0) = *(s16 *)(a + 0) + (int)clamped;

    if (d != lbl_803E6C38) {
        *(s16 *)(a + 4) = (int)(lbl_803E6C98 * (f32)*(s16 *)(a + 4));
        *(s16 *)(a + 4) = (int)(oneOverTimeDelta * (lbl_803E6C5C * (clamped * d)) + (f32)*(s16 *)(a + 4));
        tmp = *(s16 *)(a + 4);
        if (tmp < -0x2000) {
            tmp = -0x2000;
        } else if (tmp > 0x2000) {
            tmp = 0x2000;
        }
        *(s16 *)(a + 4) = (s16)tmp;
    }

    if (lbl_803E6C38 != e) {
        dist = sqrtf(*(f32 *)(b + 0) * *(f32 *)(b + 0) + *(f32 *)(b + 8) * *(f32 *)(b + 8));
        delta = (f32)(int)((u16)getAngle(*(f32 *)(b + 4) * e, dist) - (u16)*(s16 *)(a + 2));
        if (delta > lbl_803E6C64) {
            delta = lbl_803E6C84 + delta;
        }
        if (delta < lbl_803E6C8C) {
            delta = lbl_803E6C88 + delta;
        }
        *(s16 *)(a + 2) = *(s16 *)(a + 2) + (int)(delta * rate);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_80221C18(int obj, f32 dt, int p3, int p4)
{
    f32 vel[3];
    f32 step[3];
    f32 pos[3];
    int gridA[2];
    int gridB[2];
    int gridOut[3];
    int i;

    if ((u32)obj != (u32)Obj_GetPlayerObject()) {
        PSVECSubtract((void *)(obj + 0xc), (void *)(obj + 0x80), vel);
    } else {
        vel[0] = *(f32 *)(obj + 0x24);
        vel[1] = *(f32 *)(obj + 0x28);
        vel[2] = *(f32 *)(obj + 0x2c);
    }
    PSVECScale(vel, vel, oneOverTimeDelta);
    pos[0] = *(f32 *)(obj + 0xc);
    pos[1] = lbl_803E6C58 + *(f32 *)(obj + 0x10);
    pos[2] = *(f32 *)(obj + 0x14);
    for (i = 0; i < 5; i++) {
        PSVECScale(vel, step, PSVECDistance(pos, (void *)p3) / dt);
        PSVECAdd(obj + 0xc, (int)step, (int)pos);
    }
    *(f32 *)(p4 + 0) = pos[0];
    *(f32 *)(p4 + 4) = pos[1];
    *(f32 *)(p4 + 8) = pos[2];
    voxmaps_worldToGrid((void *)p3, gridA);
    voxmaps_worldToGrid(pos, gridB);
    return voxmaps_traceLine(gridA, gridB, gridOut, 0, 0) != 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int voxmaps_traceWorldLine(void *p1, void *p2)
{
    int grid1[2];
    int grid2[2];
    int out[2];

    voxmaps_worldToGrid(p1, grid1);
    voxmaps_worldToGrid(p2, grid2);
    return voxmaps_traceLine(grid1, grid2, out, 0, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void voxmaps_traceScaledVectorEnd(int p1, void *p2, f32 *p3, f32 scale)
{
    f32 endPos[3];
    f32 scaled[3];
    int gridA[2];
    int gridB[2];
    int gridOut[2];
    int e0;
    int e1;

    PSVECNormalize(p3, p3);
    PSVECScale(p3, scaled, scale);
    PSVECAdd((int)scaled, (int)p2, (int)endPos);
    voxmaps_worldToGrid(p2, gridA);
    voxmaps_worldToGrid(endPos, gridB);
    if (voxmaps_traceLine(gridA, gridB, gridOut, 0, 0) == 0)
        voxmaps_gridToWorld(endPos, gridOut);
    e0 = *(int *)&endPos[0];
    e1 = *(int *)&endPos[1];
    *(int *)(p1 + 0) = e0;
    *(int *)(p1 + 4) = e1;
    *(int *)(p1 + 8) = *(int *)&endPos[2];
}
#pragma scheduling reset
#pragma peephole reset
