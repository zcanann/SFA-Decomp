/* DLL 0xE1 - wisp baddie / swarmbaddie / hagabon objects [8014F620-8014F9E8) */
#include "main/dll/rom_curve_interface.h"
#include "main/dll/swarmbaddiestate_struct.h"
#include "main/dll/hagabonstate_struct.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/dll_00E1_wispbaddie.h"

extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined8 ObjGroup_RemoveObject();

extern f32 lbl_803DC074;

void hagabon_release(void);

void hagabon_initialise(void);

void swarmbaddie_hitDetect(void);

void swarmbaddie_release(void);

void swarmbaddie_initialise(void);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void mm_free(void* p);
extern f32 lbl_803E26D0;
extern f32 lbl_803E26D4;
extern f32 lbl_803E26D8;
extern f32 lbl_803E26DC;
extern f32 lbl_803E26E0;
extern f32 lbl_803E26E4;
extern f32 lbl_803E26E8;
extern f32 lbl_803E26EC;
extern f32 lbl_803E26F0;
extern f32 lbl_803E26F4;
extern f32 lbl_803E26F8;
extern f32 lbl_803E26FC;
extern int lbl_803DBC80;
extern void* mmAlloc(int size, int heap, int flags);
extern void* memset(void* dst, int val, u32 n);
extern int lbl_803DDA68;
extern f32 timeDelta;
extern GameObject* Obj_GetPlayerObject(void);
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 t);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);
extern void* mmAlloc(int size, int tag, int flags);
extern void* memset(void* dst, int value, uint size);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800305c4();
extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfxId);
extern void doRumble(f32 duration);
extern void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude);
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern undefined4 FUN_80151844();
extern void fn_801513AC(int obj, int state);
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 DAT_8031e980;
extern undefined4 DAT_8031feac;
extern undefined4 DAT_8031fead;
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;
extern f32 lbl_803E33E0;
extern f32 lbl_803E33E4;
extern f32 lbl_803E33E8;
extern f32 lbl_803E33EC;
extern f32 lbl_803E2708;
extern f32 lbl_803E270C;
extern f32 lbl_803E2710;
extern f32 lbl_803E2714;
extern f32 lbl_803E2718;
extern f32 lbl_803E271C;
extern f32 lbl_803E2720;
extern f32 lbl_803E2740;
extern f32 lbl_803E2744;
extern f32 lbl_803E2748;
extern f32 lbl_803E274C;
extern f32 lbl_803E2750;
extern f32 lbl_803E2754;
extern f32 lbl_803E2760;
extern f32 lbl_803E2764;
extern void* PTR_DAT_8031fdc4;
extern void wispbaddie_init(int obj, int setup, int initialised);
extern void fn_8014CF7C(int a, int b, f32 e, f32 f, int c, int d);
extern f32 lbl_803E2728;
extern f32 lbl_803E272C;
extern f32 lbl_803E2730;
extern f32 lbl_803E2734;
extern f32 lbl_803E2738;
extern f32 lbl_803E273C;
extern char lbl_8031F16C[];
extern u8 lbl_8031DD30[];

void wispbaddie_hitDetect(void)
{
}

void hagabon_hitDetect(int obj);

void swarmbaddie_free(int obj);

void wispbaddie_free(int obj)
{
    void** state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}

void hagabon_free(int obj);

void swarmbaddie_init(int obj, int data, int skip_alloc);

void hagabon_init(int obj, int data, int skip_alloc);

void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

int hagabon_getExtraSize(void);
int hagabon_getObjectTypeId(void);
int swarmbaddie_getExtraSize(void);
int swarmbaddie_getObjectTypeId(void);
int wispbaddie_getExtraSize(void) { return 0x2c; }
int wispbaddie_getObjectTypeId(void) { return 0x9; }

void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wispbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void fn_8014EE8C(int obj, SwarmBaddieState* state);

void fn_8014F620(int obj, WispBaddieState* state)
{
    RomCurveWalker* curve;
    int done;
    f32 step;
    f32 wave;

    curve = state->curve;
    state->pathWavePhase += (s16)(lbl_803E26D0 * timeDelta);
    state->hoverWavePhase += (s16)(lbl_803E26D4 * timeDelta);

    wave = lbl_803E26D8 + mathSinf((lbl_803E26DC * (f32)state->pathWavePhase) / lbl_803E26E0);
    done = Curve_AdvanceAlongPath(curve, state->hitRadius * wave);
    if (((done != 0) || (curve->atSegmentEnd != lbl_803DDA68)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E26E4,
                                          &lbl_803DBC80, -1) != 0))
    {
        state->flags = state->flags & ~1;
    }
    lbl_803DDA68 = curve->atSegmentEnd;

    if ((state->flags & 2) != 0)
    {
        ((GameObject*)obj)->anim.velocityX =
            lbl_803E26E8 * (state->playerObj->anim.localPosX - ((GameObject*)obj)->anim.localPosX) +
            ((GameObject*)obj)->anim.velocityX;

        wave = mathSinf((lbl_803E26DC * (f32)state->hoverWavePhase) / lbl_803E26E0);
        ((GameObject*)obj)->anim.velocityY =
            ((lbl_803E26F0 * wave + (lbl_803E26EC + state->playerObj->anim.localPosY)) -
                ((GameObject*)obj)->anim.localPosY) * lbl_803E26E8 +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ =
            lbl_803E26E8 * (state->playerObj->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) +
            ((GameObject*)obj)->anim.velocityZ;
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E26E8 * (*(f32*)((char*)curve + 0x68) - ((GameObject*)obj)->anim.localPosX)
            +
            ((GameObject*)obj)->anim.velocityX;

        wave = mathSinf((lbl_803E26DC * (f32)state->hoverWavePhase) / lbl_803E26E0);
        ((GameObject*)obj)->anim.velocityY =
            ((lbl_803E26F0 * wave + *(f32*)((char*)curve + 0x6c)) - ((GameObject*)obj)->anim.localPosY) *
            lbl_803E26E8 +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E26E8 * (*(f32*)((char*)curve + 0x70) - ((GameObject*)obj)->anim.localPosZ)
            +
            ((GameObject*)obj)->anim.velocityZ;
    }

    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (step = lbl_803E26F4);
    ((GameObject*)obj)->anim.velocityY *= step;
    ((GameObject*)obj)->anim.velocityZ *= step;

    if (((GameObject*)obj)->anim.velocityX > *(f32*)&lbl_803E26F8)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E26F8;
    }
    if (((GameObject*)obj)->anim.velocityY > *(f32*)&lbl_803E26F8)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E26F8;
    }
    if (((GameObject*)obj)->anim.velocityZ > *(f32*)&lbl_803E26F8)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E26F8;
    }
    if (((GameObject*)obj)->anim.velocityX < *(f32*)&lbl_803E26FC)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E26FC;
    }
    if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E26FC)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E26FC;
    }
    if (((GameObject*)obj)->anim.velocityZ < *(f32*)&lbl_803E26FC)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E26FC;
    }

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
}

void swarmbaddie_update(int obj);

void hagabon_update(int obj);

ObjectDescriptor gHagabonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)hagabon_initialise,
    (ObjectDescriptorCallback)hagabon_release,
    0,
    (ObjectDescriptorCallback)hagabon_init,
    (ObjectDescriptorCallback)hagabon_update,
    (ObjectDescriptorCallback)hagabon_hitDetect,
    (ObjectDescriptorCallback)hagabon_render,
    (ObjectDescriptorCallback)hagabon_free,
    (ObjectDescriptorCallback)hagabon_getObjectTypeId,
    hagabon_getExtraSize,
};

ObjectDescriptor gSwarmBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)swarmbaddie_initialise,
    (ObjectDescriptorCallback)swarmbaddie_release,
    0,
    (ObjectDescriptorCallback)swarmbaddie_init,
    (ObjectDescriptorCallback)swarmbaddie_update,
    (ObjectDescriptorCallback)swarmbaddie_hitDetect,
    (ObjectDescriptorCallback)swarmbaddie_render,
    (ObjectDescriptorCallback)swarmbaddie_free,
    (ObjectDescriptorCallback)swarmbaddie_getObjectTypeId,
    swarmbaddie_getExtraSize,
};

/* segment pragma-stack balance (re-split): */

#define SEQOBJ_ANIM_BLEND_ACTIVE_FLAG 0x40
#define SEQOBJ_ANIM_EVENT_HOLD_FLAG 0x40000000

void wispbaddie_update(int obj)
{
    WispBaddieState* state;
    RomCurveWalker* curve;
    int hit;
    f32 dx;
    f32 hitZ;
    f32 dy;
    f32 dz;
    f32 hitX;
    f32 hitY;
    f32 d[3];
    int particleParam;
    u8 f;
    void* dAlias = (void*)d;

    state = ((GameObject*)obj)->extra;
    curve = state->curve;
    hit = ObjHits_GetPriorityHitWithPosition(obj, &dx, &hitX, &hitY, &hitZ, &dy, &dz);
    if (hit != 0)
    {
        state->hitRadius = lbl_803E2708;
        f = state->flags;
        if ((f & 2) != 0)
        {
            state->flags = (u8)(f & ~2);
            state->flags = (u8)(state->flags | 4);
        }
        Sfx_PlayAtPositionFromObject(obj, hitZ, dy, dz, 0x23c);
    }

    particleParam = 4;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 1, -1,
                                     &particleParam);
    particleParam = 3;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                     &particleParam);

    if (state->hitRadius < state->maxHitRadius)
    {
        state->hitRadius += lbl_803E270C;
        ObjHits_DisableObject(obj);
    }
    else
    {
        state->hitRadius = state->maxHitRadius;
        particleParam = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                         &particleParam);
        particleParam = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                         &particleParam);
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
    }

    particleParam = 1;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                     &particleParam);
    state->playerObj = Obj_GetPlayerObject();
    if (state->playerObj != NULL)
    {
        d[0] = state->playerObj->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d[1] = state->playerObj->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d[2] = state->playerObj->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }
    if (curve != 0)
    {
        d[0] = *(f32*)((u8*)curve + 0x68) - ((GameObject*)obj)->anim.worldPosX;
        d[1] = *(f32*)((u8*)curve + 0x6c) - ((GameObject*)obj)->anim.worldPosY;
        d[2] = *(f32*)((u8*)curve + 0x70) - ((GameObject*)obj)->anim.worldPosZ;
        state->curveDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }

    f = state->flags;
    if ((f & 2) != 0)
    {
        if (state->curveDistance > lbl_803E2710)
        {
            state->flags = (u8)(f & ~2);
            state->flags = (u8)(state->flags | 4);
        }
        state->cryTimer -= timeDelta;
        if (state->cryTimer < lbl_803E2714)
        {
            Sfx_PlayFromObject(obj, 0x23d);
            state->cryTimer = (f32)(int)randomGetRange(0x3c, 0x78);
        }
        state->particleId = 0x338;
    }
    f = state->flags;
    if ((f & 4) != 0)
    {
        if (state->curveDistance < lbl_803E2718)
        {
            state->flags = (u8)(f & ~4);
        }
        state->particleId = 0x337;
    }
    if ((state->flags & 6) == 0)
    {
        if ((state->hitRadius >= state->maxHitRadius) && (state->playerObj != 0) &&
            (state->playerDistance < state->triggerDistance))
        {
            state->flags = (u8)(state->flags | 2);
        }
        state->particleId = 0x337;
    }
    fn_8014F620(obj, state);
}

void wispbaddie_init(int obj, int setup, int initialised)
{
    WispBaddieState* state;
    f32 value;

    state = ((GameObject*)obj)->extra;
    value = (f32) * (s16*)(setup + 0x1a) / lbl_803E271C;
    state->maxHitRadius = value;
    state->hitRadius = value;
    state->triggerDistance = lbl_803E2720 * (f32) * (s8*)(setup + 0x19);
    state->particleId = 0x337;

    if (initialised == 0)
    {
        state->curve = (RomCurveWalker*)mmAlloc(0x108, 0x1a, 0);
        if ((void*)state->curve != NULL)
        {
            memset((void*)state->curve, 0, 0x108);
        }
        if ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, state->triggerDistance,
                                             &lbl_803DBC80, -1) == 0)
        {
            state->flags = (u8)(state->flags | 1);
        }
        Sfx_PlayFromObject(obj, 0x23b);
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

void FUN_8014fef8(undefined4 param_1, int param_2, undefined4 param_3, int param_4)
{
    if (param_4 == 0x10)
    {
        *(uint*)(param_2 + 0x2e8) = *(uint*)(param_2 + 0x2e8) | 0x20;
        return;
    }
    *(uint*)(param_2 + 0x2e8) = *(uint*)(param_2 + 0x2e8) | 8;
    return;
}

void FUN_8014ff20(void)
{
    return;
}

#pragma scheduling on
#pragma peephole on
void FUN_8014ff24(short* param_1, undefined4 param_2)
{
    FUN_8014d3d0(param_1, param_2, 0xf, 0);
    return;
}

void FUN_8014ffa8(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, uint param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte bVar1;
    float fVar2;
    float fVar3;
    int iVar4;
    short* psVar5;
    uint uVar6;
    int iVar7;
    undefined* puVar8;
    float* pfVar9;
    double dVar10;
    double dVar11;
    undefined8 uVar12;

    uVar12 = FUN_80286840();
    fVar3 = lbl_803E33D8;
    psVar5 = (short*)((ulonglong)uVar12 >> 0x20);
    iVar7 = (int)uVar12;
    puVar8 = (&PTR_DAT_8031fdc4)[(uint) * (byte*)(iVar7 + 0x33b) * 10];
    if (((*(uint*)(iVar7 + 0x2dc) & 0x4000) != 0) ||
        ((dVar10 = (double)*(float*)(iVar7 + 0x328), dVar10 != (double)lbl_803E33D8 &&
            (*(short*)(iVar7 + 0x338) != 0))))
        goto LAB_80150818;
    bVar1 = *(byte*)(iVar7 + 0x2f1);
    uVar6 = bVar1 & 0x1f;
    if ((bVar1 & 0x10) != 0)
    {
        uVar6 = bVar1 & 0x17;
    }
    if (0x18 < uVar6)
    {
        uVar6 = 0;
    }
    fVar2 = lbl_803E33E0;
    if ((bVar1 & 0x20) != 0)
    {
        uVar6 = 0;
        fVar2 = lbl_803E33DC;
    }
    dVar11 = (double)fVar2;
    if (((param_11 & 0xff) != 0) &&
        ((((bVar1 != 0 ||
                (dVar10 = (double)*(float*)(iVar7 + 0x324), dVar10 != (double)lbl_803E33D8)) &&
            ((*(uint*)(iVar7 + 0x2dc) & 0x40) == 0)) && ((bVar1 & 0x20) == 0))))
    {
        param_2 = (double)*(float*)(iVar7 + 0x324);
        dVar10 = (double)lbl_803E33D8;
        if (param_2 == dVar10)
        {
            iVar4 = (uint) * (byte*)(iVar7 + 0x33b) * 2;
            uVar6 = randomGetRange((uint)(byte)(&DAT_8031feac)[iVar4], (uint)(byte)(&DAT_8031fead)[iVar4]);
            *(float*)(iVar7 + 0x324) =
                *(float*)(iVar7 + 0x334) +
                (f32)(s32)(uVar6);
            *(float*)(iVar7 + 0x334) = lbl_803E33D8;
            goto LAB_80150818;
        }
        *(float*)(iVar7 + 0x324) = (float)(param_2 - (double)lbl_803DC074);
        if (dVar10 < (double)*(float*)(iVar7 + 0x324)) goto LAB_80150818;
        *(float*)(iVar7 + 0x324) = fVar3;
    }
    if ((((((param_11 & 0xff) == 0) || (*(char*)(iVar7 + 0x2f1) == '\0')) ||
            (puVar8[uVar6 * 0xc + 8] == '\0')) && ((*(byte*)(iVar7 + 0x2f1) & 0x20) == 0)) ||
        ((*(byte*)(iVar7 + 0x33c) == uVar6 &&
            (dVar10 = (double)lbl_803E33D8, dVar10 != (double)*(float*)(iVar7 + 0x32c)))))
    {
        if (*(float*)(iVar7 + 0x32c) != lbl_803E33D8)
        {
            dVar10 = (double)*(float*)(*(int*)(iVar7 + 0x29c) + 0x14);
            FUN_8014d3d0(psVar5, iVar7, 0xf, 0);
            if (lbl_803E33E8 < *(float*)(iVar7 + 0x308))
            {
                *(float*)(iVar7 + 0x308) = *(float*)(iVar7 + 0x308) - lbl_803E33EC;
            }
            if ((*(uint*)(iVar7 + 0x2dc) & 0x40000000) != 0)
            {
                iVar4 = (uint) * (byte*)(iVar7 + 0x33c) * 0xc;
                FUN_8014d4c8((double)*(float*)(puVar8 + iVar4), dVar10, dVar11, param_4, param_5, param_6,
                             param_7, param_8, (int)psVar5, iVar7, (uint)(byte)puVar8[iVar4 + 8], 0,
                             *(uint*)(puVar8 + iVar4 + 4) & 0xff, param_14, param_15, param_16);
                FUN_800305c4((double)*(float*)(&DAT_8031e980 +
                                 (uint)(byte)puVar8[(uint) * (byte*)(iVar7 + 0x33c) * 0xc + 8]
                             * 4), (int)psVar5
                )
                ;
            }
            *(float*)(iVar7 + 0x32c) = *(float*)(iVar7 + 0x32c) - lbl_803DC074;
            if (*(float*)(iVar7 + 0x32c) <= lbl_803E33D8)
            {
                *(float*)(iVar7 + 0x32c) = lbl_803E33D8;
                *(uint*)(iVar7 + 0x2dc) = *(uint*)(iVar7 + 0x2dc) & 0xffffffbf;
                *(uint*)(iVar7 + 0x2dc) = *(uint*)(iVar7 + 0x2dc) | 0x40000000;
                *(byte*)(iVar7 + 0x2f2) = *(byte*)(iVar7 + 0x2f2) & 0x7f;
                *(undefined*)(iVar7 + 0x33c) = 0;
            }
        }
    }
    else if (((*(uint*)(iVar7 + 0x2dc) & 0x800080) == 0) && ((*(byte*)(iVar7 + 0x2f1) & 0x20) == 0))
    {
        if ((*(uint*)(iVar7 + 0x2dc) & 0x40000000) != 0)
        {
            FUN_80151844(dVar10, param_2, dVar11, param_4, param_5, param_6, param_7, param_8, psVar5, iVar7);
        }
    }
    else
    {
        pfVar9 = (float*)(puVar8 + uVar6 * 0xc);
        fVar3 = lbl_803E33E4 * (float)(dVar11 * (double)*pfVar9);
        *(float*)(iVar7 + 0x330) = fVar3;
        *(float*)(iVar7 + 0x32c) = fVar3;
        *(uint*)(iVar7 + 0x2dc) = *(uint*)(iVar7 + 0x2dc) | 0x40;
        *(byte*)(iVar7 + 0x2f2) = *(byte*)(iVar7 + 0x2f2) | 0x80;
        *(undefined*)(iVar7 + 0x2f3) = 0;
        *(undefined*)(iVar7 + 0x2f4) = 0;
        FUN_8014d4c8((double)(float)(dVar11 * (double)*pfVar9), param_2, dVar11, param_4, param_5, param_6,
                     param_7, param_8, (int)psVar5, iVar7, (uint) * (byte*)(pfVar9 + 2), 0,
                     (uint)pfVar9[1] & 0xff, param_14, param_15, param_16);
        FUN_800305c4((double)*(float*)(&DAT_8031e980 + (uint) * (byte*)(pfVar9 + 2) * 4), (int)psVar5);
        *(char*)(iVar7 + 0x33c) = (char)uVar6;
    }
LAB_80150818:
    FUN_8028688c();
    return;
}

#pragma scheduling off
#pragma peephole off
void wispbaddie_release(void)
{
}

void wispbaddie_initialise(void)
{
}

ObjectDescriptor gWispBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wispbaddie_initialise,
    (ObjectDescriptorCallback)wispbaddie_release,
    0,
    (ObjectDescriptorCallback)wispbaddie_init,
    (ObjectDescriptorCallback)wispbaddie_update,
    (ObjectDescriptorCallback)wispbaddie_hitDetect,
    (ObjectDescriptorCallback)wispbaddie_render,
    (ObjectDescriptorCallback)wispbaddie_free,
    (ObjectDescriptorCallback)wispbaddie_getObjectTypeId,
    wispbaddie_getExtraSize,
};

void fn_8014FF20(void)
{
}

void fn_8014FEF8(int p1, int* p2, int p3, int code)
{
    if (code == 0x10)
    {
        *(u32*)((char*)p2 + 0x2e8) |= 0x20;
    }
    else
    {
        *(u32*)((char*)p2 + 0x2e8) |= 0x8;
    }
}

void fn_8014FF24(int a, int b)
{
    f32* p = *(f32**)((char*)b + 0x29c);
    fn_8014CF7C(a, b, p[3], p[5], 0xf, 0);
}

void fn_8014FF58(int unused, char* p)
{
    f32 v1c;
    *(f32*)(p + 0x2ac) = lbl_803E2728;
    *(u32*)(p + 0x2e4) = 1;
    *(u32*)(p + 0x2e4) |= 0x80;
    *(f32*)(p + 0x308) = lbl_803E272C;
    *(f32*)(p + 0x300) = lbl_803E2730;
    *(f32*)(p + 0x304) = lbl_803E2734;
    *(u8*)(p + 0x320) = 0;
    v1c = lbl_803E2738;
    *(f32*)(p + 0x314) = v1c;
    *(u8*)(p + 0x321) = 0;
    *(f32*)(p + 0x318) = lbl_803E273C;
    *(u8*)(p + 0x322) = 0;
    *(f32*)(p + 0x31c) = v1c;
}

u32 fn_8014FFB4(int obj, int state, u32 allowNewEvent)
{
    u8* base = lbl_8031DD30;
    u8* eventRows;
    u8 eventIndex;
    int ei;
    int flag20;
    u8 sequenceIndex;
    u32 stateFlags;
    u8 eventFlags;
    f32 blendScale;
    f32 blendTimer;
    int eventTableIndex;
    u8* row;
    u32 sf2;

    sequenceIndex = *(u8*)(state + 0x33b);
    eventRows = *(u8**)(base + sequenceIndex * 0x28 + 0x1444);
    stateFlags = ((BaddieState*)state)->controlFlags;
    if ((stateFlags & 0x4000) != 0)
    {
        return 0;
    }
    if (*(f32*)(state + 0x328) != lbl_803E2740 && *(u16*)(state + 0x338) != 0)
    {
        return 0;
    }
    eventFlags = *(u8*)(state + 0x2f1);
    ei = eventFlags & 0x1f;
    eventIndex = ei;
    if ((ei & 0x10) != 0)
    {
        eventIndex = ei & ~0x8;
    }
    if (eventIndex > 0x18)
    {
        eventIndex = 0;
    }
    flag20 = eventFlags & 0x20;
    if (flag20 != 0)
    {
        blendScale = lbl_803E2744;
        eventIndex = 0;
    }
    else
    {
        blendScale = lbl_803E2748;
    }
    if ((u8)allowNewEvent != 0)
    {
        if ((eventFlags != 0 || *(f32*)(state + 0x324) != lbl_803E2740) &&
            (stateFlags & 0x40) == 0 && flag20 == 0)
        {
            if (*(f32*)(state + 0x324) != lbl_803E2740)
            {
                *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
                if (*(f32*)(state + 0x324) <= lbl_803E2740)
                {
                    *(f32*)(state + 0x324) = lbl_803E2740;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                eventTableIndex = sequenceIndex * 2;
                *(f32*)(state + 0x324) = *(f32*)(state + 0x334) +
                    (f32)(int)
                randomGetRange(base[eventTableIndex + 0x152c],
                               base[eventTableIndex + 0x152d]);
                *(f32*)(state + 0x334) = lbl_803E2740;
                return 0;
            }
        }
    }
    if ((((u8)allowNewEvent != 0 && *(u8*)(state + 0x2f1) != 0 &&
                eventRows[eventIndex * 0xc + 8] != 0) ||
            (*(u8*)(state + 0x2f1) & 0x20) != 0) &&
        !(*(u8*)(state + 0x33c) == eventIndex && lbl_803E2740 != *(f32*)(state + 0x32c)))
    {
        sf2 = ((BaddieState*)state)->controlFlags;
        if ((sf2 & 0x800080) != 0 || (*(u8*)(state + 0x2f1) & 0x20) != 0)
        {
            row = eventRows + eventIndex * 0xc;
            blendTimer = lbl_803E274C * (blendScale * *(f32*)row);
            *(f32*)(state + 0x330) = blendTimer;
            *(f32*)(state + 0x32c) = blendTimer;
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags | 0x40;
            *(u8*)(state + 0x2f2) = *(u8*)(state + 0x2f2) | 0x80;
            *(u8*)(state + 0x2f3) = 0;
            *(u8*)(state + 0x2f4) = 0;
            Baddie_SetMove(obj, state, row[8], blendScale * *(f32*)row, 0, *(u32*)(row + 4) & 0xff);
            ObjAnim_SetMoveProgress(*(f32*)(base + row[8] * 4), (ObjAnimComponent*)obj);
            *(u8*)(state + 0x33c) = eventIndex;
            return 1;
        }
        if ((sf2 & 0x40000000) != 0)
        {
            fn_801513AC(obj, state);
        }
        return 0;
    }
    if (*(f32*)(state + 0x32c) != lbl_803E2740)
    {
        int pos = *(int*)(state + 0x29c);
        fn_8014CF7C(obj, state, *(f32*)(pos + 0xc), *(f32*)(pos + 0x14), 0xf, 0);
        if (*(f32*)(state + 0x308) > lbl_803E2750)
        {
            *(f32*)(state + 0x308) = *(f32*)(state + 0x308) - lbl_803E2754;
        }
        if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            eventTableIndex = *(u8*)(state + 0x33c) * 0xc;
            row = eventRows + eventTableIndex;
            Baddie_SetMove(obj, state, row[8],
                        *(f32*)(eventRows + *(u8*)(state + 0x33c) * 0xc), 0,
                        *(u32*)(row + 4) & 0xff);
            ObjAnim_SetMoveProgress(
                *(f32*)(base + eventRows[*(u8*)(state + 0x33c) * 0xc + 8] * 4),
                (ObjAnimComponent*)obj);
        }
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= lbl_803E2740)
        {
            *(f32*)(state + 0x32c) = lbl_803E2740;
            ((BaddieState*)state)->controlFlags =
                (((BaddieState*)state)->controlFlags & ~SEQOBJ_ANIM_BLEND_ACTIVE_FLAG) |
                SEQOBJ_ANIM_EVENT_HOLD_FLAG;
            *(u8*)(state + 0x2f2) = *(u8*)(state + 0x2f2) & 0x7f;
            *(u8*)(state + 0x33c) = 0;
            return 0;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

void fn_8015039C(int obj, int animState)
{
    extern f32 Vec_distance(f32 * a, f32 * b); /* #57 */
    GameObject* player;
    f32 distance;
    f32 rumbleFalloff;

    if ((*(u16*)(animState + 0x2f8) & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, 0x383);
        player = Obj_GetPlayerObject();
        if ((player->objectFlags & 0x1000) == 0)
        {
            distance = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &player->anim.worldPosX);
            if (distance <= lbl_803E2760)
            {
                rumbleFalloff = lbl_803E2748 - distance / lbl_803E2760;
                rumbleFalloff = lbl_803E2744 * rumbleFalloff;
                doRumble(rumbleFalloff);
            }
            CameraShake_ApplyRadial(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ, lbl_803E2760,
                                    lbl_803E2764);
        }
    }
    if ((*(u16*)(animState + 0x2f8) & 0x40) != 0)
    {
        Sfx_PlayFromObject(obj, 0x19);
    }
    if ((*(u16*)(animState + 0x2f8) & 0x1000) != 0)
    {
        Sfx_PlayFromObject(obj, 0x257);
    }
    if ((*(u16*)(animState + 0x2f8) & 1) != 0)
    {
        Sfx_PlayFromObject(obj, 0x12);
    }
    if ((*(u16*)(animState + 0x2f8) & 0x80) != 0)
    {
        Sfx_PlayFromObject(obj, 0x15);
    }
}

#pragma scheduling off
void fn_801504BC(int obj, int delta)
{
    u8* inner = ((GameObject*)obj)->extra;
    u8* ptr = *(u8**)(lbl_8031F16C + inner[0x33b] * 0x28 + 4);
    inner[0x33d] = (u8)(delta + (u32)ptr[8] + 1);
    inner[0x33e] = 1;
}
