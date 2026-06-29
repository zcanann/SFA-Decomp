/*
 * objfx - object particle / light effect spawners (part of the
 * fx_800944A0 DLL, sharing its tables and float pool).
 *
 * Each routine builds a PartfxParams / PartfxFlags block and hands it to
 * the global particle interface (gPartfxInterface->spawnObject) or the
 * bone-attached effect interface (gBoneParticleEffectInterface), keyed by
 * a small caller-supplied selector that indexes the effect-id tables at
 * gObjFxCrystalSparkleTbl / lbl_802C20EC / etc. Coverage: crystal sparkle
 * (WM_newcrystalFn_800969b0), generic hit/impact bursts, directional /
 * arced / box scatter bursts, the A-button glow, projectile trails, item
 * pickup sparkles, and dynamic lights (objParticleFn / objLightFn driving
 * modelLightStruct_*). fn_8009A8C8 / spawnExplosion / DIMexplosionFn add a
 * distance-attenuated camera shake + rumble and spawn the shared explosion
 * object (type 0x24, id 0x253). The numerous 0x3xx/0x7xx literals are
 * particle-effect resource ids; the float lbl_803DFxxx symbols are tuning
 * constants in the DLL's shared .sdata2 pool.
 */
#include "main/dll/fx_800944A0_shared.h"

extern f32 gObjFxCrystalAmpTbl[];
extern s16 gObjFxCrystalSpinSpeed[4];
extern u8 gObjFxLightColorTbl[];
extern f32 lbl_803DF388;
extern f32 lbl_803DF38C;
extern f32 lbl_803DF39C;
extern f32 fcos16(u16 angle);

void WM_newcrystalFn_800969b0(void* obj, s16* state, u8 flags, f32 period, f32 xMul, f32 yMul, f32 xOff, f32 yOff)
{
    PartfxParams params;
    int i;
    int j;
    int spawnFlags;
    f32 phase;

    for (i = 0; i < 4; i++)
    {
        state[0x12 + i] = (65535.0f / period + (f32)(i * randomGetRange(120, 127)));
        phase = state[0x12 + i];
        state[0xe + i] = (phase * timeDelta + state[0xe + i]);
        phase = fcos16(state[0xe + i]);
        *(f32*)((char*)state + 0xc + i * 4) = gObjFxCrystalAmpTbl[i] * ((1.0f + phase) * 0.5f);

        state[0x16 + i] = (timeDelta * gObjFxCrystalSpinSpeed[i] + state[0x16 + i]);
        *(u16*)state = state[0x16 + i];
        *(f32*)((char*)state + 8) = *(f32*)((char*)state + 0xc + i * 4);

        for (j = 0; j < 0xffff; j += 0x7fff)
        {
            params.vec[0] = *(f32*)((char*)state + 8) * xMul + xOff;
            params.vec[1] = *(f32*)((char*)state + 8) * yMul + yOff;
            params.vec[2] = 0.0f;
            *(u16*)state += 0x7fff;
            vecRotateZXY(state, params.vec);
            params.vec[0] += ((GameObject*)obj)->anim.localPosX;
            params.vec[1] += ((GameObject*)obj)->anim.localPosY;
            params.vec[2] += ((GameObject*)obj)->anim.localPosZ;
            params.f8 = 1.0f;
            spawnFlags = 0x200001;
            if (flags != 0)
            {
                spawnFlags |= 0x20000000;
            }
            (*gPartfxInterface)->spawnObject(obj, 0x7ec, &params, spawnFlags, -1, NULL);
        }
    }
}

void objfx_spawnRandomBurst(void* obj, u8 type, u8 count, void* origin, u8 flagByte, f32 mult)
{
    PartfxParams params;
    ParticlePairTbl partbl = *(ParticlePairTbl*)gObjFxRandomBurstTbl;
    u16 rvec[3];
    int i;
    f32 r;
    u8 frames;

    if (framesThisStep > 3)
    {
        frames = 3;
    }
    else
    {
        frames = framesThisStep;
    }
    for (i = 0; i < frames * count; i++)
    {
        r = randomGetRange(0, 1000) / 1000.0f;
        rvec[0] = randomGetRange(0, 0xffff);
        rvec[1] = randomGetRange(0, 0xffff);
        rvec[2] = randomGetRange(0, 0xffff);
        params.vec[0] = mult * (1.0f - r * (r * r));
        params.vec[1] = 0.0f;
        params.vec[2] = 0.0f;
        vecRotateZXY(rvec, params.vec);
        if (origin != NULL)
        {
            params.vec[0] += ((GameObject*)origin)->anim.localPosX;
            params.vec[1] += ((GameObject*)origin)->anim.localPosY;
            params.vec[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.f6 = partbl.e[type].a;
        params.pad[1] = partbl.e[type].b;
        params.pad[2] = flagByte;
        params.f8 = 1.0f;
        if (type >= 9 && type <= 0xb)
        {
            if (type == 0xb || type == 0xa)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7e3, &params, 2, -1, NULL);
            }
            if (type == 0xb || type == 9)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7e4, &params, 2, -1, NULL);
            }
        }
        else
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7e2, &params, 2, -1, NULL);
        }
    }
}

void objfx_spawnHitEmitterAtPos(f32* pos, u8 a, u8 b, u8 c, u8 d)
{
    int args[4];
    ParticleEmit s1;
    int* res;
    s1.scale = lbl_803DF354;
    s1.h1c = 0;
    s1.h1a = 0;
    s1.h18 = 0;
    s1.x = pos[0];
    s1.y = pos[1];
    s1.z = pos[2];
    res = Resource_Acquire(0x5a, 1);
    args[0] = a;
    args[1] = b;
    args[2] = c;
    args[3] = d;
    (*(void (*)(int, int, void*, int, int, void*))(*(int*)(*(int*)res + 4)))(0, 1, &s1, 0x401, -1, args);
}

void hitDetectFn_80097070(void* obj, u8 a, u8 b, u8 count, void* p7, f32 fval)
{
    PartfxParams params;
    Tbl11 table = *(Tbl11*)lbl_802C2114;
    u16 ps[3];
    int i;
    *(int*)ps = lbl_803DF340;
    ps[2] = lbl_803DF344;
    if (a == 0 || b == 0)
    {
        return;
    }
    params.f8 = fval;
    params.f6 = table.v[b];
    if (p7 != NULL)
    {
        params.vec[0] = ((GameObject*)p7)->anim.localPosX;
        params.vec[1] = ((GameObject*)p7)->anim.localPosY;
        params.vec[2] = ((GameObject*)p7)->anim.localPosZ;
    }
    else
    {
        params.vec[0] = lbl_803DF35C;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
    }
    for (i = 0; i < count; i++)
    {
        (*gPartfxInterface)->spawnObject(obj, ps[a], &params, 2, -1, NULL);
    }
}

void objfx_spawnMaskedHitEffect(void* obj, u8 a, u8 b, u8 mask, void* p7, f32 fval)
{
    PartfxParams params;
    Tbl11 table1 = *(Tbl11*)lbl_802C20EC;
    Tbl7 table2 = *(Tbl7*)lbl_802C2104;
    if (a == 0 || b == 0)
    {
        return;
    }
    if ((mask & (u16)(int)gExpgfxFrameTimerA) == 0)
    {
        return;
    }
    params.f8 = fval;
    params.f6 = table1.v[b];
    if (p7 != NULL)
    {
        params.vec[0] = ((GameObject*)p7)->anim.localPosX;
        params.vec[1] = ((GameObject*)p7)->anim.localPosY;
        params.vec[2] = ((GameObject*)p7)->anim.localPosZ;
    }
    else
    {
        params.vec[0] = lbl_803DF35C;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
    }
    (*gPartfxInterface)->spawnObject(obj, table2.v[a], &params, 2, -1, NULL);
}

void objfx_spawnDirectionalBurst(void* obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance,
                                 f32 mult, void* origin, int flags)
{
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA*)((char*)gObjFxCrystalSparkleTbl + 0xd0);
    ParticleTbl8 tB = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0xe4);
    ParticleTbl8 tC = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0xf4);
    ParticleTbl8 tD = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0x104);
    u16 rvec[3];
    int i;
    f32 f30;

    params.f8 = f8val;
    params.f6 = tA.v[kind];
    params.pad[1] = 0x3c;
    for (i = 0; i < 4; i++)
    {
        if (randomGetRange(0, 0x63) >= chance)
        {
            continue;
        }
        f30 = randomGetRange(0, 1000) / lbl_803DF368;
        switch (mode)
        {
        case 1:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 2:
            rvec[0] = 0;
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = 0;
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 3:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = 0;
            rvec[2] = 0;
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 4:
            rvec[0] = 0;
            rvec[1] = 0;
            rvec[2] = randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 5:
            rvec[0] = randomGetRange(0x7fff, 0xffff);
            rvec[1] = 0;
            rvec[2] = randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 6:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.vec[0] = f30 * mult;
            break;
        case 7:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * (f30 * (f30 * f30))));
            break;
        }
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
        vecRotateZXY(rvec, params.vec);
        if (origin != NULL)
        {
            params.vec[0] += ((GameObject*)origin)->anim.localPosX;
            params.vec[1] += ((GameObject*)origin)->anim.localPosY;
            params.vec[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad[2] = tC.v[idx];
        params.pad[0] = tD.v[idx];
        (*gPartfxInterface)->spawnObject(obj, tB.v[idx], &params, flags | 2, -1, NULL);
    }
}

void objfx_spawnArcedBurst(void* obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance,
                           f32 angBase, f32 lo, f32 hi, void* origin, int flags)
{
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA*)((char*)gObjFxCrystalSparkleTbl + 0x8c);
    ParticleTbl8 tB = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0xa0);
    ParticleTbl8 tC = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0xb0);
    ParticleTbl8 tD = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0xc0);
    u16 rvec[3];
    int i;
    f32 fdelta;
    f32 f30;
    f32 f29;

    params.f8 = f8val;
    params.f6 = tA.v[kind];
    params.pad[1] = 0x3c;
    for (i = 0; i < 4; i++)
    {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance)
        {
            continue;
        }
        rvec[0] = randomGetRange(0, 0xffff);
        rvec[1] = 0;
        rvec[2] = 0;
        f30 = randomGetRange(1, 1000) / lbl_803DF368;
        f29 = randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
        switch (mode)
        {
        case 1:
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 2:
            f29 = f29 * (f29 * f29);
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 3:
            f29 = *(f32*)&lbl_803DF354 - f29 * (f29 * f29);
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 4:
            val = (u16)(int)(lbl_803DF350 * f29);
            a = gObjFxPi * (f32)(u32)
            val / lbl_803DF370;
            f29 = lbl_803DF358 * (lbl_803DF354 + mathCosf(a));
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 5:
            val = (u16)(int)(lbl_803DF350 * f29);
            a = gObjFxPi * (f32)(u32)
            val / lbl_803DF370;
            f29 = lbl_803DF358 * (lbl_803DF354 + mathSinf(a));
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 6:
            params.vec[0] = f30 * f30;
            break;
        case 7:
            params.vec[0] = lbl_803DF354 - f30 * (f30 * (f30 * (f30 * f30)));
            break;
        }
        fdelta = angBase - lo;
        params.vec[0] = params.vec[0] * (f29 * fdelta + lo);
        vecRotateZXY(rvec, params.vec);
        {
            f32 t = f29 - lbl_803DF358;
            params.vec[1] = t * hi;
        }
        if (origin != NULL)
        {
            params.vec[0] += ((GameObject*)origin)->anim.localPosX;
            params.vec[1] += ((GameObject*)origin)->anim.localPosY;
            params.vec[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad[2] = tC.v[idx];
        params.pad[0] = tD.v[idx];
        (*gPartfxInterface)->spawnObject(obj, tB.v[idx], &params, flags | 2, -1, NULL);
    }
}

void objfx_spawnBoxBurst(void* obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance,
                         f32 mulX, f32 mulY, f32 mulZ, void* origin, int flags)
{
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA*)((char*)gObjFxCrystalSparkleTbl + 0x48);
    ParticleTbl8 tB = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0x5c);
    ParticleTbl8 tC = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0x6c);
    ParticleTbl8 tD = *(ParticleTbl8*)((char*)gObjFxCrystalSparkleTbl + 0x7c);
    int i;

    params.f8 = f8val;
    params.f6 = tA.v[kind];
    params.pad[1] = 0x3c;
    for (i = 0; i < 4; i++)
    {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance)
        {
            continue;
        }
        params.vec[0] = randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[1] = randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[2] = randomGetRange(0, 1000) / lbl_803DF368;
        switch (mode)
        {
        case 1:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] -= lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 2:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] = params.vec[1] * (params.vec[1] * params.vec[1]) - lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 3:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] =
                (lbl_803DF354 - params.vec[1] * (params.vec[1] * params.vec[1])) - lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 4:
            params.vec[0] -= lbl_803DF358;
            val = (u16)(int)(lbl_803DF350 * params.vec[1]);
            a = gObjFxPi * (f32)(u32)
            val / lbl_803DF370;
            params.vec[1] = lbl_803DF358 * mathCosf(a);
            params.vec[2] -= lbl_803DF358;
            break;
        case 5:
            params.vec[0] -= lbl_803DF358;
            val = (u16)(int)(lbl_803DF350 * params.vec[1]);
            a = gObjFxPi * (f32)(u32)
            val / lbl_803DF370;
            params.vec[1] = lbl_803DF358 * mathSinf(a);
            params.vec[2] -= lbl_803DF358;
            break;
        case 6:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] -= lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 7:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] -= lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        }
        params.vec[0] = params.vec[0] * mulX;
        params.vec[1] = params.vec[1] * mulY;
        params.vec[2] = params.vec[2] * mulZ;
        if (origin != NULL)
        {
            params.vec[0] += ((GameObject*)origin)->anim.localPosX;
            params.vec[1] += ((GameObject*)origin)->anim.localPosY;
            params.vec[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad[2] = tC.v[idx];
        params.pad[0] = tD.v[idx];
        (*gPartfxInterface)->spawnObject(obj, tB.v[idx], &params, flags | 2, -1, NULL);
    }
}

void objShowButtonGlow(void* obj, u8 mode, f32 intensity)
{
    PartfxParams params;
    int i;

    params.f8 = intensity;
    if (mode == 0)
    {
        return;
    }
    switch (mode)
    {
    case 1:
        params.f6 = 0xc8c;
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.f6 = 1;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 2:
        params.f6 = 0xc8d;
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.f6 = 0;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 3:
        params.f6 = 0xc8e;
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.f6 = 2;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 4:
        params.f6 = 0;
        for (i = 0; i < 0x14; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7f2, &params, 1, -1, NULL);
        }
        break;
    }
}

void objfx_spawnFrameTimedHitPulse(void* obj, u8 a, u8 b, f32 c, f32 d)
{
    Tbl5 t1 = *(Tbl5*)lbl_802C1FF8;
    Tbl5 t2 = *(Tbl5*)lbl_802C200C;
    f32 vec[3];
    int frame;
    if (a == 0)
    {
        return;
    }
    if (b == 0 || b >= 5)
    {
        return;
    }
    {
        if (gExpgfxFrameTimerB != lbl_803DF35C)
        {
            frame = 0;
        }
        else
        {
            frame = t2.v[b] & 0xff;
        }
        vec[0] = *(f32*)&lbl_803DF35C;
        vec[1] = d;
        vec[2] = *(f32*)&lbl_803DF35C;
        switch (a)
        {
        case 1:
            fn_80098B18(obj, c, (u8)t1.v[b], frame, 0, vec);
            break;
        }
    }
}

void objfx_spawnLightPulse(void* obj, u8 type, int a3, u8 mode, void* light, f32 fa, f32 fb)
{
    extern void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 w, f32 *ox, f32 *oy, f32 *oz);
    extern void Camera_NdcToScreen(f32 x, f32 y, f32 z, int *sx, int *sy, int *sz);
    PartfxParams params;
    f32 lvec[6];
    f32 proj[3];
    int screen[3];
    int i;
    int depth;
    u8 n;

    if (framesThisStep > 3)
    {
        n = 3;
    }
    else
    {
        n = framesThisStep;
    }
    params.f8 = fa;
    if (fb <= lbl_803DF380)
    {
        fb = lbl_803DF380;
    }
    params.vec[0] = fb;
    if (type != 0)
    {
        switch (type)
        {
        case 1:
            params.f6 = 0x159;
            params.pad[2] = 1;
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7be, &params, 2, -1, light);
            }
            break;
        case 2:
            params.f6 = 0x159;
            params.pad[2] = 0;
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7be, &params, 2, -1, light);
            }
            break;
        case 3:
            params.f6 = 0x8e;
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c0, &params, 2, -1, light);
            }
            break;
        case 4:
            {
                int flags = 2;
                if ((((GameObject*)obj)->anim.flags & 0x40080) != 0)
                {
                    flags |= 0x20000000;
                }
                params.f6 = 0xc0e;
                params.pad[2] = 0;
                for (i = 0; i < n; i++)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x7eb, &params, flags, -1, light);
                }
                break;
            }
        }
    }

    if (mode != 0)
    {
        if (light != NULL)
        {
            lvec[3] = ((GameObject*)light)->anim.localPosX;
            lvec[4] = ((GameObject*)light)->anim.localPosY;
            lvec[5] = ((GameObject*)light)->anim.localPosZ;
            vecRotateZXY(obj, &lvec[3]);
            Camera_ProjectWorldPointWithOffset(
                ((GameObject*)obj)->anim.worldPosX + lvec[3] - playerMapOffsetX,
                ((GameObject*)obj)->anim.worldPosY + lvec[4],
                ((GameObject*)obj)->anim.worldPosZ + lvec[5] - playerMapOffsetZ, lbl_803DF384,
                &proj[2], &proj[1], &proj[0]);
        }
        else
        {
            Camera_ProjectWorldPointWithOffset(
                ((GameObject*)obj)->anim.worldPosX - playerMapOffsetX,
                ((GameObject*)obj)->anim.worldPosY,
                ((GameObject*)obj)->anim.worldPosZ - playerMapOffsetZ, lbl_803DF384,
                &proj[2], &proj[1], &proj[0]);
        }
        Camera_NdcToScreen(proj[2], proj[1], proj[0], &screen[2], &screen[1], &screen[0]);
        depth = depthReadRequestPoll(screen[2], screen[1], obj);
        if (screen[0] > depth)
        {
            switch (mode)
            {
            case 1:
                mode = 4;
                break;
            case 2:
                mode = 5;
                break;
            case 3:
                mode = 6;
                break;
            }
        }
        switch (mode)
        {
        case 1:
            if (type == 1)
            {
                params.f6 = 0xc75;
            }
            else
            {
                params.f6 = 0xc74;
            }
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 2:
            params.f6 = 0x605;
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 3:
            if (type == 1)
            {
                params.f6 = 0xc75;
            }
            else
            {
                params.f6 = 0xc74;
            }
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c1, &params, 2, -1, light);
            }
            break;
        case 4:
            if (type == 1)
            {
                params.f6 = 0xc75;
            }
            else
            {
                params.f6 = 0xc74;
            }
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 5:
            params.f6 = 0x605;
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 6:
            if (type == 1)
            {
                params.f6 = 0xc75;
            }
            else
            {
                params.f6 = 0xc74;
            }
            for (i = 0; i < n; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c5, &params, 2, -1, light);
            }
            break;
        }
    }
}

void objfx_spawnFlaggedTrailBurst(void* obj, u8 mode, int p5, int p6, int p7, f32 fval)
{
    PartfxFlags params;
    int i;
    u8 count;

    if (framesThisStep > 3)
    {
        count = 3;
    }
    else
    {
        count = framesThisStep;
    }
    params.f6 = p5;
    params.f4 = p6;
    params.f8 = fval;
    if (mode == 0)
    {
        return;
    }
    switch (mode)
    {
    case 1:
        params.a = 0;
        params.b = 0;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, (void*)p7);
        }
        break;
    case 2:
        params.a = 1;
        params.b = 0;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, (void*)p7);
        }
        break;
    case 3:
        params.a = 0;
        params.b = 1;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, (void*)p7);
        }
        break;
    case 4:
        params.a = 1;
        params.b = 1;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, (void*)p7);
        }
        break;
    }
}

void projectileParticleFxFn_80099660(void* obj, int mode)
{
    PartfxParams ps;
    f32 tailScale;
    f32 scale;
    int i;

    switch (mode)
    {
    case 0:
        i = 10;
        scale = lbl_803DF358;
        for (; i < 20; i += 2)
        {
            ps.f6 = i;
            ps.f8 = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, &ps, 1, -1, NULL);
        }
        tailScale = lbl_803DF390;
        break;
    case 1:
        i = 10;
        scale = lbl_803DF354;
        for (; i < 20; i += 2)
        {
            ps.f6 = i;
            ps.f8 = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, &ps, 1, -1, NULL);
        }
        for (i = 0; i < 20; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, NULL, 1, -1, NULL);
        }
        tailScale = lbl_803DF354;
        break;
    case 2:
        i = 10;
        scale = lbl_803DF354;
        for (; i < 20; i += 2)
        {
            ps.f6 = i;
            ps.f8 = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, &ps, 1, -1, NULL);
        }
        for (i = 0; i < 20; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, NULL, 1, -1, NULL);
        }
        tailScale = lbl_803DF354;
        break;
    case 3:
        i = 10;
        scale = lbl_803DF358;
        for (; i < 20; i += 2)
        {
            ps.f6 = i;
            ps.f8 = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, &ps, 1, -1, NULL);
        }
        tailScale = lbl_803DF390;
        break;
    case 4:
        i = 10;
        scale = lbl_803DF354;
        for (; i < 20; i += 2)
        {
            ps.f6 = i;
            ps.f8 = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, &ps, 1, -1, NULL);
        }
        for (i = 0; i < 20; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, NULL, 1, -1, NULL);
        }
        tailScale = lbl_803DF354;
        break;
    case 6:
        i = 10;
        scale = lbl_803DF358;
        for (; i < 20; i += 2)
        {
            ps.f6 = i;
            ps.f8 = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, &ps, 1, -1, NULL);
        }
        tailScale = lbl_803DF390;
        break;
    default:
        return;
    }
    (*gPartfxInterface)->spawnObject(obj, 0x79f, NULL, 1, -1, &tailScale);
}

void itemPickupDoParticleFx(void* obj, int mode, u8 count, f32 fval)
{
    PartfxParams params;
    int i;

    params.f8 = fval;
    if (mode == 0)
    {
        return;
    }
    switch (mode)
    {
    case 1:
        params.f6 = 0x79;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 2:
        params.f6 = 0xc13;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 3:
        params.f6 = 0x71;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 4:
        params.f6 = 0xdb;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 5:
        params.f6 = 0x77;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 6:
        params.f6 = 0x7b;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 7:
        params.f6 = 0xda;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 8:
        params.f6 = 0xdd;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    case 10:
        params.f6 = 0xde;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    case 9:
        params.f6 = 0xdf;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    default:
        params.f6 = 0x5c;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    }
}

void objParticleFn_80099d84(void* obj, f32 scale, int type, f32 extraScale, void* light)
{
    PartfxParams params;
    f32 zoff = lbl_803DF394;
    ColorTbl colors = *(ColorTbl*)gObjFxCrystalSparkleTbl;
    u8* cbuf;
    u8* cbuf1;
    u8* cbuf2;

    params.f8 = scale;
    params.pad[0] = 0;
    params.pad[2] = 0;
    params.pad[1] = 0;
    params.f6 = 0xc0a;
    if ((u8)type)
    {
    switch (type & 0xff)
    {
    case 1:
        params.vec[0] = scale * randomGetRange(-10, 10);
        params.vec[1] = scale * randomGetRange(-10, 10);
        params.vec[2] = scale * randomGetRange(-10, 10);
        (*gPartfxInterface)->spawnObject(obj, 0x32f, &params, 2, -1, &extraScale);
        break;
    case 2:
        params.vec[0] = scale * randomGetRange(-10, 10);
        params.vec[1] = scale * randomGetRange(-10, 10);
        params.vec[2] = scale * randomGetRange(-10, 10);
        (*gPartfxInterface)->spawnObject(obj, 0x330, &params, 2, -1, &extraScale);
        break;
    case 3:
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x32f, &extraScale, 0x19, NULL);
        break;
    case 4:
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x330, &extraScale, 0x19, NULL);
        break;
    case 5:
        params.f6 = 0xc0a;
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cd, &extraScale, 0x32, &params);
        break;
    case 6:
        params.f6 = 0xc0d;
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7ce, &extraScale, 0x50, &params);
        break;
    case 7:
        params.f6 = 0x605;
        params.pad[2] = 1;
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cf, &extraScale, 0x19, &params);
        zoff = lbl_803DF35C;
        break;
    case 8:
        params.f6 = 0x605;
        params.pad[2] = 0;
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cf, &extraScale, 0x19, &params);
        zoff = lbl_803DF35C;
        break;
    }
    }

    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, 2);
        modelLightStruct_setPosition(light, ((GameObject*)obj)->anim.worldPosX,
                                     ((GameObject*)obj)->anim.worldPosY + zoff,
                                     ((GameObject*)obj)->anim.worldPosZ);
        cbuf = (u8*)&colors;
        cbuf1 = (u8*)&colors + 1;
        cbuf2 = (u8*)&colors + 2;
        modelLightStruct_setDiffuseColor(light, cbuf[(u8)type * 3], cbuf1[(u8)type * 3],
                                         cbuf2[(u8)type * 3], 0xff);
        modelLightStruct_setSpecularColor(light, cbuf[(u8)type * 3], cbuf1[(u8)type * 3],
                                          cbuf2[(u8)type * 3], 0xff);
        modelLightStruct_setDistanceAttenuation(light, lbl_803DF34C, lbl_803DF398);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, 1, lbl_803DF35C);
        modelLightStruct_setEnabled(light, 0, lbl_803DF354);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}

void objLightFn_8009a1dc(void* obj, f32 scale, void* origin, u8 type, void* light)
{
    u8 args[16];
    u8 i;

    if (type != 0)
    {
    switch (type)
    {
    case 1:
        args[0] = 1;
        for (i = 10; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, args);
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 4; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 2:
        args[0] = 2;
        for (i = 13; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, args);
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 6; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 3:
        args[0] = 3;
        for (i = 30; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, args);
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 8; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 4:
        for (i = 7; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x328, origin, 0x200001, -1, NULL);
        }
        break;
    case 5:
        args[0] = 4;
        for (i = 10; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 4; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 6:
        args[0] = 5;
        for (i = 10; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 4; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 7:
        args[0] = 6;
        for (i = 10; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 4; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 8:
        args[0] = 7;
        for (i = 10; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 4; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    case 9:
        args[0] = 8;
        for (i = 10; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, args);
        }
        for (i = 4; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, args);
        }
        break;
    }
    }

    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, 2);
        modelLightStruct_setPosition(light, ((GameObject*)origin)->anim.localPosX,
                                     lbl_803DF384 + ((GameObject*)origin)->anim.localPosY,
                                     ((GameObject*)origin)->anim.localPosZ);
        modelLightStruct_setDiffuseColor(light, gObjFxLightColorTbl[type * 3], gObjFxLightColorTbl[type * 3 + 1],
                                         gObjFxLightColorTbl[type * 3 + 2], 0xff);
        modelLightStruct_setSpecularColor(light, gObjFxLightColorTbl[type * 3], gObjFxLightColorTbl[type * 3 + 1],
                                          gObjFxLightColorTbl[type * 3 + 2], 0xff);
        modelLightStruct_setDistanceAttenuation(light, lbl_803DF394, lbl_803DF39C);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, 1, lbl_803DF35C);
        modelLightStruct_setEnabled(light, 0, lbl_803DF358);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}

void fn_8009A8C8(u8* obj, f32 thresh)
{
    u8* player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    if (((GameObject*)player)->objectFlags & 0x1000)
    {
        return;
    }
    {
        f32 d = Camera_DistanceToCurrentViewPosition(((GameObject*)obj)->anim.worldPosX,
                                                     ((GameObject*)obj)->anim.worldPosY,
                                                     ((GameObject*)obj)->anim.worldPosZ);
        if (d <= thresh)
        {
            f32 t = lbl_803DF354 - d / thresh;
            CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
            doRumble(lbl_803DF3A8 * t);
        }
    }
}

void DIMexplosionFn_8009a96c(u8* src, f32 vx, f32 vy, f32 vz, f32 fval, u8 a, u8 flag4,
                             u8 flag8, u8 flag10, u8 doShake, u8 flag20, u8 f1cinit)
{
    u8* obj;
    if (Obj_IsLoadingLocked() != 0)
    {
        obj = Obj_AllocObjectSetup(0x24, 0x253);
        *(u8*)(obj + 4) = 2;
        *(u8*)(obj + 5) = 1;
        ((GameObject*)obj)->anim.rootMotionScale = vx;
        ((GameObject*)obj)->anim.localPosX = vy;
        ((GameObject*)obj)->anim.localPosY = vz;
        *(s8*)(obj + 0x19) = a;
        *(s16*)(obj + 0x1a) = (s16)(lbl_803DF3AC * fval);
        *(s16*)(obj + 0x1c) = f1cinit;
        if (flag4 != 0)
        {
            *(s16*)(obj + 0x1c) |= 4;
        }
        if (flag8 != 0)
        {
            *(s16*)(obj + 0x1c) |= 8;
        }
        if (flag10 != 0)
        {
            *(s16*)(obj + 0x1c) |= 0x10;
        }
        if (flag20 != 0)
        {
            *(s16*)(obj + 0x1c) |= 0x20;
        }
        if (doShake != 0)
        {
            u8* player = Obj_GetPlayerObject();
            if (player != NULL && (((GameObject*)player)->objectFlags & 0x1000) == 0)
            {
                f32 d = Camera_DistanceToCurrentViewPosition(((ObjAnimComponent*)src)->worldPosX,
                                                             ((ObjAnimComponent*)src)->worldPosY,
                                                             ((ObjAnimComponent*)src)->worldPosZ);
                if (d <= lbl_803DF3B0)
                {
                    f32 t = lbl_803DF354 - d / lbl_803DF3B0;
                    CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
                    doRumble(lbl_803DF3A8 * t);
                }
            }
        }
        Obj_SetupObject(obj, 5, ((ObjAnimComponent*)src)->mapEventSlot, -1, 0);
    }
}

void spawnExplosion(u8* src, f32 fval, u8 a, u8 flag4, u8 flag8, u8 flag10, u8 doShake,
                    u8 flag20, u8 f1cinit)
{
    u8* obj;
    if (Obj_IsLoadingLocked() != 0)
    {
        obj = Obj_AllocObjectSetup(0x24, 0x253);
        *(u8*)(obj + 4) = 2;
        *(u8*)(obj + 5) = 1;
        ((GameObject*)obj)->anim.rootMotionScale = ((ObjAnimComponent*)src)->worldPosX;
        ((GameObject*)obj)->anim.localPosX = ((ObjAnimComponent*)src)->worldPosY;
        ((GameObject*)obj)->anim.localPosY = ((ObjAnimComponent*)src)->worldPosZ;
        *(s8*)(obj + 0x19) = a;
        *(s16*)(obj + 0x1a) = (s16)(lbl_803DF3AC * fval);
        *(s16*)(obj + 0x1c) = f1cinit;
        if (flag4 != 0)
        {
            *(s16*)(obj + 0x1c) |= 4;
        }
        if (flag8 != 0)
        {
            *(s16*)(obj + 0x1c) |= 8;
        }
        if (flag10 != 0)
        {
            *(s16*)(obj + 0x1c) |= 0x10;
        }
        if (flag20 != 0)
        {
            *(s16*)(obj + 0x1c) |= 0x20;
        }
        if (doShake != 0)
        {
            u8* player = Obj_GetPlayerObject();
            if (player != NULL && (((GameObject*)player)->objectFlags & 0x1000) == 0)
            {
                f32 d = Camera_DistanceToCurrentViewPosition(((ObjAnimComponent*)src)->worldPosX,
                                                             ((ObjAnimComponent*)src)->worldPosY,
                                                             ((ObjAnimComponent*)src)->worldPosZ);
                if (d <= lbl_803DF3B0)
                {
                    f32 t = lbl_803DF354 - d / lbl_803DF3B0;
                    CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
                    doRumble(lbl_803DF3A8 * t);
                }
            }
        }
        Obj_SetupObject(obj, 5, ((ObjAnimComponent*)src)->mapEventSlot, -1, 0);
    }
}

void fn_80098B18(void* obj, f32 scale, int type, int count, int mode, f32* vec)
{
    PartfxParams params;
    int j;
    int i;
    int effB;
    int t;
    u8 n;

    if (framesThisStep > 3)
    {
        n = 3;
    }
    else
    {
        n = framesThisStep;
    }

    params.f8 = scale;
    if (vec != NULL)
    {
        params.vec[0] = vec[0];
        params.vec[1] = vec[1];
        params.vec[2] = vec[2];
    }
    else
    {
        f32 z = lbl_803DF35C;
        params.vec[0] = z;
        params.vec[1] = z;
        params.vec[2] = z;
    }

    t = (u8)type;
    switch (t)
    {
    case 3:
        params.f8 = params.f8 * lbl_803DF388;
        effB = 1968;
        break;
    case 9:
    case 10:
        mode = 0;
        count = 0;
        break;
    case 12:
    case 13:
    case 14:
        mode = 0;
        if ((u8)count != 0)
        {
            count = 8;
        }
        break;
    default:
        effB = 1967;
        break;
    }

    if ((u8)count != 0)
    {
        switch ((u8)count)
        {
        case 1:
            params.f6 = -20536;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            break;
        case 2:
            params.f6 = 10000;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            break;
        case 3:
            params.f6 = 500;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            break;
        case 4:
            params.f6 = -1;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 5:
            params.f6 = 32767;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 6:
            params.f6 = 10000;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 7:
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 8:
            if (params.f8 < lbl_803DF358)
            {
                params.f8 = *(f32*)&lbl_803DF358;
            }
            params.pad[2] = 90;
            for (i = 0; i < n * 2; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1981, &params, 1, -1, NULL);
            }
            break;
        }
    }

    if ((u8)mode != 0)
    {
        switch ((u8)mode)
        {
        case 1:
            params.f6 = 127;
            (*gPartfxInterface)->spawnObject(obj, effB, &params, 1, -1, NULL);
            break;
        case 2:
            params.f6 = 192;
            (*gPartfxInterface)->spawnObject(obj, effB, &params, 1, -1, NULL);
            break;
        case 3:
            params.f6 = 255;
            (*gPartfxInterface)->spawnObject(obj, effB, &params, 1, -1, NULL);
            break;
        }
    }

    params.f8 = scale;
    if ((u8)type != 0)
    {
        switch (t)
        {
        case 1:
            params.f6 = 3085;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1960, &params, 1, -1, NULL);
            }
            break;
        case 2:
            params.f6 = 3082;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1961, &params, 1, -1, NULL);
            }
            break;
        case 3:
            params.f6 = 3082;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1962, &params, 1, -1, NULL);
            }
            break;
        case 4:
            params.f6 = 3086;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 5:
            params.f6 = 132;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 6:
            params.f6 = 3087;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 7:
            params.f6 = 100;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 8:
            params.f6 = 3198;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 9:
            if (params.f8 < lbl_803DF358)
            {
                params.f8 = *(f32*)&lbl_803DF358;
            }
            for (j = 0; j < n * 2; j++)
            {
                params.f6 = 0;
                (*gPartfxInterface)->spawnObject(obj, 1973, &params, 1, -1, NULL);
                params.f6 = 1;
                (*gPartfxInterface)->spawnObject(obj, 1973, &params, 1, -1, NULL);
            }
            break;
        case 10:
            if (params.f8 < lbl_803DF358)
            {
                params.f8 = *(f32*)&lbl_803DF358;
            }
            for (j = 0; j < n * 2; j++)
            {
                params.f6 = 0;
                (*gPartfxInterface)->spawnObject(obj, 1974, &params, 1, -1, NULL);
                params.f6 = 1;
                (*gPartfxInterface)->spawnObject(obj, 1974, &params, 1, -1, NULL);
            }
            break;
        case 11:
            params.f6 = 100;
            for (j = 0; j < n; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 12:
            if (params.f8 < lbl_803DF38C)
            {
                params.f8 = *(f32*)&lbl_803DF38C;
            }
            params.pad[2] = 50;
            for (j = 0; j < n * 2; j++)
            {
                params.f6 = 0;
                (*gPartfxInterface)->spawnObject(obj, 1979, &params, 1, -1, NULL);
                params.f6 = 1;
                (*gPartfxInterface)->spawnObject(obj, 1979, &params, 1, -1, NULL);
            }
            break;
        case 13:
            if (params.f8 < lbl_803DF358)
            {
                params.f8 = *(f32*)&lbl_803DF358;
            }
            params.pad[2] = 90;
            for (j = 0; j < n * 2; j++)
            {
                params.f6 = 0;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
                params.f6 = 1;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
            }
            break;
        case 14:
            if (params.f8 < lbl_803DF358)
            {
                params.f8 = *(f32*)&lbl_803DF358;
            }
            params.pad[2] = 240;
            for (j = 0; j < n * 2; j++)
            {
                params.f6 = 0;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
                params.f6 = 1;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
            }
            break;
        }
    }
}
