/*
 * objfx - object particle / light effect spawners (part of the
 * fx_800944A0 DLL, sharing its tables and float pool).
 *
 * Each routine builds an ObjFxParticleParams / ObjFxParticleFlags block and
 * hands it to the global particle interface (gPartfxInterface->spawnObject) or the
 * bone-attached effect interface (gBoneParticleEffectInterface), keyed by
 * a small caller-supplied selector that indexes the effect-id tables at
 * gObjFxCrystalSparkleTbl / gObjFxHitEffectParamTbl / etc. Coverage: crystal sparkle
 * (objfx_spawnCrystalOrbitEffects), generic hit/impact bursts, directional /
 * arced / box scatter bursts, the A-button glow, projectile trails, item
 * pickup sparkles, and dynamic lights (objParticleFn / objLightFn driving
 * modelLightStruct_*). fn_8009A8C8 / spawnExplosion / DIMexplosionFn add a
 * distance-attenuated camera shake + rumble and spawn the shared explosion
 * object (type 0x24, id 0x253). The numerous 0x3xx/0x7xx literals are
 * particle-effect resource ids; the float lbl_803DFxxx symbols are tuning
 * constants in the DLL's shared .sdata2 pool.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_005A_staffcollisionfunc03.h"
#include "main/dll/objfx_api.h"
#include "main/dll/objfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/viewfinder.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/expgfx_resource_api.h"
#include "main/frame_timing.h"
#include "main/trig.h"
#include "main/object.h"
#include "main/model_light.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/pad_api.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "track/intersect_api.h"

u8 gExpgfxStaticData[48] = {
    192, 160, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0,
    66,  72,  0, 0, 66, 72, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0, 66, 72, 0, 0,
};

s16 gExpgfxStaticPoolSlotTypeIds[80] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0,
};

u8 gExpgfxStaticPoolFrameFlags[112] = {
    0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 64, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* Crystal burst amplitude scales + spawn direction table (referenced by objfx.c). */
ObjFxCrystalBurstTable gObjFxCrystalAmpTbl = {
    {0.5f, 0.55f, 0.65f, 0.7f},
    {
        {-1000, 0, 1000},
        {1000, 0, 1000},
        {1000, 0, -1000},
        {-1000, 0, -1000},
        {-1000, -1000, 0},
        {1000, -1000, 0},
        {1000, 1000, 0},
        {-1000, 1000, 0},
        {-1000, -1000, 0},
        {1000, -1000, 0},
        {1000, 1000, 0},
        {-1000, 1000, 0},
    },
};

/* Light RGB triplets per fx type (referenced by objfx.c). */
u8 gObjFxLightColorTbl[36] = {
    0x00, 0x00, 0x00, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0x40, 0xFF, 0x40, 0x7F,
    0x7F, 0x7F, 0x7F, 0x40, 0xFF, 0x40, 0xFF, 0xFF, 0x00, 0xFF, 0x7F, 0x40,
    0xFF, 0xFF, 0x40, 0x00, 0x7F, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

ObjectDescriptor14 expgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_14_SLOTS,
    (ObjectDescriptorCallback)expgfx_initialise,
    (ObjectDescriptorCallback)expgfx_release,
    0,
    (ObjectDescriptorCallback)expgfx_onMapSetup,
    (ObjectDescriptorCallback)expgfx_addremove,
    (ObjectDescriptorCallback)expgfx_updateFrameState,
    (ObjectDescriptorCallback)expgfx_resetAllPools,
    (ObjectDescriptorCallback)expgfx_free,
    (ObjectDescriptorCallback)expgfx_free2,
    (ObjectDescriptorCallback)expgfx_func09,
    (ObjectDescriptorCallback)expgfx_func0A_nop,
    (ObjectDescriptorCallback)expgfx_func0B_nop,
    (ObjectDescriptorCallback)expgfx_ownerFree3,
    (ObjectDescriptorCallback)expgfx_updateSourceFrameFlags,
};

s16 gObjFxCrystalSpinSpeed[4] = {-1024, -512, 512, 1024};

const ObjFxColorTable gObjFxCrystalSparkleTbl = {
    {0x0000, 0x00FF, 0x7FFF, 0x7FC0, 0xFFFF, 0x7FFF, 0x7FC0, 0xFFFF,
     0xA000, 0xFFA0, 0x007F, 0x40FF, 0x0000, 0x0000, 0x0000}};
const ObjFxS32Table5 gObjFxPulseVariantTbl = {{0, 0, 0, 1, 2}};
const ObjFxSparkleEffectTable lbl_802C200C = {
    {{0, 2, 3, 3, 3}},
    {{0x0000, 0x00DF, 0x0160, 0x00DE, 0x0200, 0x00DD, 0x00E0, 0x00E4, 0x007B,
      0x0000, 0x07D3, 0x07D3, 0x07D4, 0x07D5, 0x07D6, 0x07DC, 0x07DC, 0x07DC,
      0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x0200, 0x0080, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00BF, 0x00BF},
     {0x0000, 0x00DF, 0x0160, 0x00DE, 0x0200, 0x00DD, 0x00E0, 0x00E4, 0x007B,
      0x0000, 0x07D3, 0x07D3, 0x07D4, 0x07D5, 0x07D6, 0x07DC, 0x07DC, 0x07DC,
      0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x0200, 0x0080, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00BF, 0x00BF},
     {0x0000, 0x00DF, 0x0160, 0x00DE, 0x0200, 0x00DD, 0x00E0, 0x00E4, 0x007B,
      0x0000, 0x07D3, 0x07D3, 0x07D4, 0x07D5, 0x07D6, 0x07DC, 0x07DC, 0x07DC,
      0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x0200, 0x0080, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00BF, 0x00BF}}};
const ObjFxU16Table11 gObjFxHitEffectParamTbl = {
    {0x0000, 0x0079, 0x007B, 0x00DB, 0x0C13, 0x0605, 0x0C75, 0x0C74, 0x0C76, 0x0C77, 0x0C78}};
const ObjFxU16Table7 gObjFxMaskedHitSpawnIdTbl = {
    {0x0000, 0x07D9, 0x07DA, 0x07DB, 0x07E8, 0x07E9, 0x07EA}};
const ObjFxU16Table11 gObjFxHitEffectParamTbl2 = {
    {0x0000, 0x0079, 0x007B, 0x00DB, 0x0C13, 0x0605, 0x0C75, 0x0C74, 0x0C76, 0x0C77, 0x0C78}};
const ObjFxRandomBurstTable gObjFxRandomBurstTbl = {
    {{0x000, 0}, {0x3A2, 1}, {0x3A3, 1}, {0x3A4, 1}, {0x3A5, 1}, {0x3A2, 2}, {0x3A3, 2},
     {0x3A4, 2}, {0x3A5, 2}, {0x630, 0}, {0xC10, 0}, {0x630, 0}, {0x62F, 0}}};

#define OBJFX_OBJFLAG_PARENT_SLACK 0x1000

/* Shared explosion object spawned by spawnExplosion / DIMexplosionFn_8009a96c
 * (type 0x24, id 0x253; buffer cast to ExplosionSetup). */
#define OBJFX_CHILD_OBJ_EXPLOSION 0x253

/*
 * Setup buffer the explosion spawners (DIMexplosionFn_8009a96c / spawnExplosion)
 * fill from Obj_AllocObjectSetup (0x24 bytes, def id 0x253). Embeds the common
 * ObjPlacement head (the spawn position is stored into the head's posX/posY/posZ
 * slots via a GameObject anim view); 0x19/0x1a/0x1c carry this class's own slots.
 * The class byte at 0x18 is left unwritten. Field names beyond the head are
 * generic (provenance is the raw store offsets). Only unk19 is accessed through
 * this struct; the 0x1a scaled value (an f32->s16 truncation) and the 0x1c s16
 * flag word (seeded from a flag arg then OR'd with 0x4/0x8/0x10/0x20) stay raw
 * pointer stores because routing them through struct members reorders the DLL's
 * shared float-conversion pool (byte-affecting). The struct still documents the
 * full recovered layout.
 */
typedef struct ExplosionSetup
{
    ObjPlacement head;     /* 0x00: common placement head (position via GameObject anim view) */
    u8 pad18;              /* 0x18: class byte (unwritten here) */
    s8 unk19;              /* 0x19 */
    u8 pad1A[0x1C - 0x1A]; /* 0x1A: scaled s16 value, written raw (see note) */
    s16 flags;             /* 0x1C: flag word, written raw (see note) */
    u8 pad1E[0x24 - 0x1E];
} ExplosionSetup;

STATIC_ASSERT(offsetof(ExplosionSetup, unk19) == 0x19);
STATIC_ASSERT(offsetof(ExplosionSetup, flags) == 0x1C);
STATIC_ASSERT(sizeof(ExplosionSetup) == 0x24);

void objfx_spawnCrystalOrbitEffects(GameObject* obj, s16* work, f32 period, f32 xMul, f32 yMul, f32 xOff,
                                    f32 yOff, u8 flags)
{
    ObjFxParticleParams params;
    int crystalIdx;
    int angleStep;
    int spawnFlags;
    f32 wave;

    for (crystalIdx = 0; crystalIdx < 4; crystalIdx++)
    {
        work[0x12 + crystalIdx] = (65535.0f / period + (f32)(crystalIdx * randomGetRange(120, 127)));
        wave = work[0x12 + crystalIdx];
        work[0xe + crystalIdx] = (wave * timeDelta + work[0xe + crystalIdx]);
        wave = fcos16((u16)work[0xe + crystalIdx]);
        wave = (1.0f + wave) / 2.0f;
        {
            f32 amp = gObjFxCrystalAmpTbl.amps[crystalIdx];
            *(f32*)((char*)work + 0xc + crystalIdx * 4) = amp * wave;
        }

        work[0x16 + crystalIdx] = (timeDelta * gObjFxCrystalSpinSpeed[crystalIdx] + work[0x16 + crystalIdx]);
        *(u16*)work = work[0x16 + crystalIdx];
        *(f32*)((char*)work + 8) = *(f32*)((char*)work + 0xc + crystalIdx * 4);

        for (angleStep = 0; angleStep < 0xffff; angleStep += 0x7fff)
        {
            params.position[0] = *(f32*)((char*)work + 8) * xMul + xOff;
            params.position[1] = *(f32*)((char*)work + 8) * yMul + yOff;
            params.position[2] = 0.0f;
            *(u16*)work += 0x7fff;
            vecRotateZXY(work, params.position);
            params.position[0] += (obj)->anim.localPosX;
            params.position[1] += (obj)->anim.localPosY;
            params.position[2] += (obj)->anim.localPosZ;
            params.scale = 1.0f;
            spawnFlags = 0x200001;
            if (flags != 0)
            {
                spawnFlags |= 0x20000000;
            }
            (*gPartfxInterface)->spawnObject(obj, 0x7ec, &params, spawnFlags, -1, NULL);
        }
    }
}

void objfx_spawnRandomBurst(void* obj, u8 type, u8 count, void* origin, f32 mult, u8 flagByte)
{
    ObjFxParticleParams params;
    ObjFxRandomBurstTable burstTbl = gObjFxRandomBurstTbl;
    u16 randAngles[3];
    int i;
    f32 unitRand;
    u8 frameCount;

    if (framesThisStep > 3)
    {
        frameCount = 3;
    }
    else
    {
        frameCount = framesThisStep;
    }
    for (i = 0; i < frameCount * count; i++)
    {
        unitRand = randomGetRange(0, 1000) / 1000.0f;
        randAngles[0] = randomGetRange(0, 0xffff);
        randAngles[1] = randomGetRange(0, 0xffff);
        randAngles[2] = randomGetRange(0, 0xffff);
        params.position[0] = mult * (1.0f - unitRand * (unitRand * unitRand));
        params.position[1] = 0.0f;
        params.position[2] = 0.0f;
        vecRotateZXY((s16*)randAngles, params.position);
        if (origin != NULL)
        {
            params.position[0] += ((GameObject*)origin)->anim.localPosX;
            params.position[1] += ((GameObject*)origin)->anim.localPosY;
            params.position[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.effectParam = burstTbl.entries[type].effectParam;
        params.pad00[1] = burstTbl.entries[type].extraParam;
        params.pad00[2] = flagByte;
        params.scale = 1.0f;
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
    StaffCollisionColorArgs emitterArgs;
    ObjFxParticleEmitter emitter;
    StaffCollisionInterface** partfxIface;
    emitter.scale = lbl_803DF354;
    emitter.rotZ = 0;
    emitter.rotY = 0;
    emitter.rotX = 0;
    emitter.x = pos[0];
    emitter.y = pos[1];
    emitter.z = pos[2];
    partfxIface = Resource_Acquire(0x5a, 1);
    emitterArgs.count = a;
    emitterArgs.red = b;
    emitterArgs.green = c;
    emitterArgs.blue = d;
    (*partfxIface)->spawn(NULL, 1, (PartFxSpawnParams*)&emitter, 0x401, -1, &emitterArgs);
}

void objfx_spawnHitEffectBurst(void* obj, f32 scale, int idSel, int paramSel, int count, GameObject* origin)
{
    ObjFxParticleParams params;
    ObjFxU16Table11 table = gObjFxHitEffectParamTbl2;
    u16 effectIds[3];
    int i;
    *(int*)effectIds = lbl_803DF340;
    effectIds[2] = lbl_803DF344;
    if ((u8)idSel == 0 || (u8)paramSel == 0)
    {
        return;
    }
    params.scale = scale;
    params.effectParam = table.values[(u8)paramSel];
    if (origin != NULL)
    {
        params.position[0] = origin->anim.localPosX;
        params.position[1] = origin->anim.localPosY;
        params.position[2] = origin->anim.localPosZ;
    }
    else
    {
        params.position[0] = lbl_803DF35C;
        params.position[1] = lbl_803DF35C;
        params.position[2] = lbl_803DF35C;
    }
    for (i = 0; i < (u8)count; i++)
    {
        (*gPartfxInterface)->spawnObject(obj, effectIds[(u8)idSel], &params, 2, -1, NULL);
    }
}

void objfx_spawnMaskedHitEffect(void* obj, f32 scale, u8 type, u8 mode, u8 mask, void* origin)
{
    ObjFxParticleParams params;
    ObjFxU16Table11 effectParamTbl = gObjFxHitEffectParamTbl;
    ObjFxU16Table7 spawnIdTbl = gObjFxMaskedHitSpawnIdTbl;
    if (type == 0 || mode == 0)
    {
        return;
    }
    if ((mask & (u16)(int)gExpgfxFrameTimerA) == 0)
    {
        return;
    }
    params.scale = scale;
    params.effectParam = effectParamTbl.values[mode];
    if (origin != NULL)
    {
        params.position[0] = ((GameObject*)origin)->anim.localPosX;
        params.position[1] = ((GameObject*)origin)->anim.localPosY;
        params.position[2] = ((GameObject*)origin)->anim.localPosZ;
    }
    else
    {
        params.position[0] = lbl_803DF35C;
        params.position[1] = lbl_803DF35C;
        params.position[2] = lbl_803DF35C;
    }
    (*gPartfxInterface)->spawnObject(obj, spawnIdTbl.values[type], &params, 2, -1, NULL);
}

void objfx_spawnDirectionalBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mult, void* origin,
                                 int flags)
{
    ObjFxParticleParams params;
    ObjFxU16Table9 effectParams = *(ObjFxU16Table9*)((char*)&gObjFxCrystalSparkleTbl + 0xd0);
    ObjFxU16Table8 spawnIds = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0xe4);
    ObjFxU16Table8 paramC = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0xf4);
    ObjFxU16Table8 paramD = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x104);
    u16 rvec[3];
    int i;
    f32 radialT;

    params.scale = scale;
    params.effectParam = effectParams.values[kind];
    params.pad00[1] = 0x3c;
    for (i = 0; i < 4; i++)
    {
        if (randomGetRange(0, 0x63) >= chance)
        {
            continue;
        }
        radialT = randomGetRange(0, 1000) / 1000.0f;
        switch (mode)
        {
        case 1:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (lbl_803DF354 - radialT * (radialT * radialT));
            break;
        case 2:
            rvec[0] = 0;
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = 0;
            params.position[0] = mult * (lbl_803DF354 - radialT * (radialT * radialT));
            break;
        case 3:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = 0;
            rvec[2] = 0;
            params.position[0] = mult * (lbl_803DF354 - radialT * (radialT * radialT));
            break;
        case 4:
            rvec[0] = 0;
            rvec[1] = 0;
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (lbl_803DF354 - radialT * (radialT * radialT));
            break;
        case 5:
            rvec[0] = randomGetRange(0x7fff, 0xffff);
            rvec[1] = 0;
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (lbl_803DF354 - radialT * (radialT * radialT));
            break;
        case 6:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = radialT * mult;
            break;
        case 7:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (lbl_803DF354 - radialT * (radialT * (radialT * (radialT * radialT))));
            break;
        }
        params.position[1] = lbl_803DF35C;
        params.position[2] = lbl_803DF35C;
        vecRotateZXY((s16*)rvec, params.position);
        if (origin != NULL)
        {
            params.position[0] += ((GameObject*)origin)->anim.localPosX;
            params.position[1] += ((GameObject*)origin)->anim.localPosY;
            params.position[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad00[2] = paramC.values[idx];
        params.pad00[0] = paramD.values[idx];
        (*gPartfxInterface)->spawnObject(obj, spawnIds.values[idx], &params, flags | 2, -1, NULL);
    }
}

#define OBJ_FX_PI 3.1415927f

void objfx_spawnArcedBurst(void* obj, int idx, f32 scale, int kind, int mode, int chance, f32 angBase, f32 lo, f32 hi,
                           void* origin, int flags)
{
    ObjFxParticleParams params;
    ObjFxU16Table9 effectParams = *(ObjFxU16Table9*)((char*)&gObjFxCrystalSparkleTbl + 0x8c);
    ObjFxU16Table8 spawnIds = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0xa0);
    ObjFxU16Table8 paramC = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0xb0);
    ObjFxU16Table8 paramD = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0xc0);
    u16 rvec[3];
    int i;
    f32 range;
    f32 radialT;
    f32 angularT;

    params.scale = scale;
    params.effectParam = effectParams.values[(u8)kind];
    params.pad00[1] = 0x3c;
    for (i = 0; i < 4; i++)
    {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= (u8)chance)
        {
            continue;
        }
        rvec[0] = randomGetRange(0, 0xffff);
        rvec[1] = 0;
        rvec[2] = 0;
        radialT = randomGetRange(1, 1000) / 1000.0f;
        angularT = randomGetRange(0, 1000) / 1000.0f;
        params.position[1] = lbl_803DF35C;
        params.position[2] = lbl_803DF35C;
        switch ((u8)mode)
        {
        case 1:
            params.position[0] = lbl_803DF354 - radialT * radialT;
            break;
        case 2:
            angularT = angularT * (angularT * angularT);
            params.position[0] = lbl_803DF354 - radialT * radialT;
            break;
        case 3:
            angularT = *(f32*)&lbl_803DF354 - angularT * (angularT * angularT);
            params.position[0] = lbl_803DF354 - radialT * radialT;
            break;
        case 4:
            val = (u16)(int)(lbl_803DF350 * angularT);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            angularT = lbl_803DF358 * (lbl_803DF354 + mathCosf(a));
            params.position[0] = lbl_803DF354 - radialT * radialT;
            break;
        case 5:
            val = (u16)(int)(lbl_803DF350 * angularT);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            angularT = lbl_803DF358 * (lbl_803DF354 + mathSinf(a));
            params.position[0] = lbl_803DF354 - radialT * radialT;
            break;
        case 6:
            params.position[0] = radialT * radialT;
            break;
        case 7:
            params.position[0] = lbl_803DF354 - radialT * (radialT * (radialT * (radialT * radialT)));
            break;
        }
        range = angBase - lo;
        params.position[0] = params.position[0] * (angularT * range + lo);
        vecRotateZXY((s16*)rvec, params.position);
        {
            f32 t = angularT - lbl_803DF358;
            params.position[1] = t * hi;
        }
        if (origin != NULL)
        {
            params.position[0] += ((GameObject*)origin)->anim.localPosX;
            params.position[1] += ((GameObject*)origin)->anim.localPosY;
            params.position[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad00[2] = paramC.values[(u8)idx];
        params.pad00[0] = paramD.values[(u8)idx];
        (*gPartfxInterface)->spawnObject(obj, spawnIds.values[(u8)idx], &params, flags | 2, -1, NULL);
    }
}

void objfx_spawnBoxBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mulX, f32 mulY, f32 mulZ,
                         void* origin, int flags)
{
    ObjFxParticleParams params;
    ObjFxU16Table9 effectParams = *(ObjFxU16Table9*)((char*)&gObjFxCrystalSparkleTbl + 0x48);
    ObjFxU16Table8 spawnIds = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x5c);
    ObjFxU16Table8 paramC = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x6c);
    ObjFxU16Table8 paramD = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x7c);
    int i;

    params.scale = scale;
    params.effectParam = effectParams.values[kind];
    params.pad00[1] = 0x3c;
    for (i = 0; i < 4; i++)
    {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance)
        {
            continue;
        }
        params.position[0] = randomGetRange(0, 1000) / 1000.0f;
        params.position[1] = randomGetRange(0, 1000) / 1000.0f;
        params.position[2] = randomGetRange(0, 1000) / 1000.0f;
        switch (mode)
        {
        case 1:
            params.position[0] -= lbl_803DF358;
            params.position[1] -= lbl_803DF358;
            params.position[2] -= lbl_803DF358;
            break;
        case 2:
            params.position[0] -= lbl_803DF358;
            params.position[1] = params.position[1] * (params.position[1] * params.position[1]) - lbl_803DF358;
            params.position[2] -= lbl_803DF358;
            break;
        case 3:
            params.position[0] -= lbl_803DF358;
            params.position[1] = (lbl_803DF354 - params.position[1] * (params.position[1] * params.position[1])) - lbl_803DF358;
            params.position[2] -= lbl_803DF358;
            break;
        case 4:
            params.position[0] -= lbl_803DF358;
            val = (u16)(int)(lbl_803DF350 * params.position[1]);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            params.position[1] = lbl_803DF358 * mathCosf(a);
            params.position[2] -= lbl_803DF358;
            break;
        case 5:
            params.position[0] -= lbl_803DF358;
            val = (u16)(int)(lbl_803DF350 * params.position[1]);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            params.position[1] = lbl_803DF358 * mathSinf(a);
            params.position[2] -= lbl_803DF358;
            break;
        case 6:
            params.position[0] -= lbl_803DF358;
            params.position[1] -= lbl_803DF358;
            params.position[2] -= lbl_803DF358;
            break;
        case 7:
            params.position[0] -= lbl_803DF358;
            params.position[1] -= lbl_803DF358;
            params.position[2] -= lbl_803DF358;
            break;
        }
        params.position[0] = params.position[0] * mulX;
        params.position[1] = params.position[1] * mulY;
        params.position[2] = params.position[2] * mulZ;
        if (origin != NULL)
        {
            params.position[0] += ((GameObject*)origin)->anim.localPosX;
            params.position[1] += ((GameObject*)origin)->anim.localPosY;
            params.position[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad00[2] = paramC.values[idx];
        params.pad00[0] = paramD.values[idx];
        (*gPartfxInterface)->spawnObject(obj, spawnIds.values[idx], &params, flags | 2, -1, NULL);
    }
}

void objShowButtonGlow(void* obj, f32 intensity, u8 glowKind)
{
    ObjFxParticleParams params;
    int i;

    params.scale = intensity;
    if (glowKind == 0)
    {
        return;
    }
    switch (glowKind)
    {
    case 1:
        params.effectParam = 0xc8c;
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.effectParam = 1;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 2:
        params.effectParam = 0xc8d;
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.effectParam = 0;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 3:
        params.effectParam = 0xc8e;
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.effectParam = 2;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 4:
        params.effectParam = 0;
        for (i = 0; i < 0x14; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7f2, &params, 1, -1, NULL);
        }
        break;
    }
}

void objfx_spawnFrameTimedHitPulse(GameObject* obj, f32 scale, u8 type, u8 variant, f32 yOffset)
{
    ObjFxS32Table5 variantTbl = gObjFxPulseVariantTbl;
    ObjFxS32Table5 countTbl = lbl_802C200C.counts;
    f32 offset[3];
    int frame;
    if (type == 0)
    {
        return;
    }
    if (variant == 0 || variant >= 5)
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
            frame = countTbl.values[variant] & 0xff;
        }
        offset[0] = *(f32*)&lbl_803DF35C;
        offset[1] = yOffset;
        offset[2] = *(f32*)&lbl_803DF35C;
        switch (type)
        {
        case 1:
            fn_80098B18(obj, scale, (u8)variantTbl.values[variant], frame, 0, offset);
            break;
        }
    }
}

void objfx_spawnLightPulse(GameObject* obj, f32 scale, int type, int a3, int mode, f32 sizeParam, void* light)
{
    ObjFxParticleParams params;
    f32 lightOffset[6];
    f32 ndc[3];
    s32 screenPos[3];
    int i;
    int depth;
    u8 frameCount;

    if (framesThisStep > 3)
    {
        frameCount = 3;
    }
    else
    {
        frameCount = framesThisStep;
    }
    params.scale = scale;
    if (sizeParam <= 0.001f)
    {
        sizeParam = 0.001f;
    }
    params.position[0] = sizeParam;
    if ((u8)type != 0)
    {
        switch ((u8)type)
        {
        case 1:
            params.effectParam = 0x159;
            params.pad00[2] = 1;
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7be, &params, 2, -1, light);
            }
            break;
        case 2:
            params.effectParam = 0x159;
            params.pad00[2] = 0;
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7be, &params, 2, -1, light);
            }
            break;
        case 3:
            params.effectParam = 0x8e;
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c0, &params, 2, -1, light);
            }
            break;
        case 4:
        {
            int flags = 2;
            if (((obj)->anim.flags & 0x40080) != 0)
            {
                flags |= 0x20000000;
            }
            params.effectParam = 0xc0e;
            params.pad00[2] = 0;
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7eb, &params, flags, -1, light);
            }
            break;
        }
        }
    }

    if ((u8)mode != 0)
    {
        if (light != NULL)
        {
            lightOffset[3] = ((GameObject*)light)->anim.localPosX;
            lightOffset[4] = ((GameObject*)light)->anim.localPosY;
            lightOffset[5] = ((GameObject*)light)->anim.localPosZ;
            vecRotateZXY((s16*)obj, &lightOffset[3]);
            Camera_ProjectWorldPointWithOffset(
                (obj)->anim.worldPosX + lightOffset[3] - playerMapOffsetX, (obj)->anim.worldPosY + lightOffset[4],
                (obj)->anim.worldPosZ + lightOffset[5] - playerMapOffsetZ, 10.0f, &ndc[2], &ndc[1], &ndc[0]);
        }
        else
        {
            Camera_ProjectWorldPointWithOffset((obj)->anim.worldPosX - playerMapOffsetX, (obj)->anim.worldPosY,
                                               (obj)->anim.worldPosZ - playerMapOffsetZ, 10.0f, &ndc[2],
                                               &ndc[1], &ndc[0]);
        }
        Camera_NdcToScreen(ndc[2], ndc[1], ndc[0], &screenPos[2], &screenPos[1], &screenPos[0]);
        depth = depthReadRequestPoll(screenPos[2], screenPos[1], obj);
        if (screenPos[0] > depth)
        {
            switch ((u8)mode)
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
        switch ((u8)mode)
        {
        case 1:
            if ((u8)type == 1)
            {
                params.effectParam = 0xc75;
            }
            else
            {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 2:
            params.effectParam = 0x605;
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 3:
            if ((u8)type == 1)
            {
                params.effectParam = 0xc75;
            }
            else
            {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c1, &params, 2, -1, light);
            }
            break;
        case 4:
            if ((u8)type == 1)
            {
                params.effectParam = 0xc75;
            }
            else
            {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 5:
            params.effectParam = 0x605;
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 6:
            if ((u8)type == 1)
            {
                params.effectParam = 0xc75;
            }
            else
            {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x7c5, &params, 2, -1, light);
            }
            break;
        }
    }
}

void objfx_spawnFlaggedTrailBurst(void* obj, f32 fval, u8 mode, int f6val, int f4val, void* origin)
{
    ObjFxParticleFlags params;
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
    params.effectParam = f6val;
    params.f4 = f4val;
    params.scale = fval;
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
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    case 2:
        params.a = 1;
        params.b = 0;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    case 3:
        params.a = 0;
        params.b = 1;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    case 4:
        params.a = 1;
        params.b = 1;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    }
}

void fn_80098B18(void* obj, f32 scale, int type, int count, int mode, f32* vec)
{
    ObjFxParticleParams params;
    int j;
    int i;
    int pulseEffectId;
    int typeByte;
    u8 frameCount;

    if (framesThisStep > 3)
    {
        frameCount = 3;
    }
    else
    {
        frameCount = framesThisStep;
    }

    params.scale = scale;
    if (vec != NULL)
    {
        params.position[0] = vec[0];
        params.position[1] = vec[1];
        params.position[2] = vec[2];
    }
    else
    {
        f32 z = lbl_803DF35C;
        params.position[0] = z;
        params.position[1] = z;
        params.position[2] = z;
    }

    typeByte = (u8)type;
    switch (typeByte)
    {
    case 3:
        params.scale *= 2.25f;
        pulseEffectId = 1968;
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
        pulseEffectId = 1967;
        break;
    }

    if ((u8)count != 0)
    {
        switch ((u8)count)
        {
        case 1:
            params.effectParam = -20536;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            break;
        case 2:
            params.effectParam = 10000;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            break;
        case 3:
            params.effectParam = 500;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            break;
        case 4:
            params.effectParam = -1;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 5:
            params.effectParam = 32767;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 6:
            params.effectParam = 10000;
            (*gPartfxInterface)->spawnObject(obj, 1965, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 7:
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 1966, &params, 1, -1, NULL);
            break;
        case 8:
            if (params.scale < lbl_803DF358)
            {
                params.scale = *(f32*)&lbl_803DF358;
            }
            params.pad00[2] = 90;
            for (i = 0; i < frameCount * 2; i++)
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
            params.effectParam = 127;
            (*gPartfxInterface)->spawnObject(obj, pulseEffectId, &params, 1, -1, NULL);
            break;
        case 2:
            params.effectParam = 192;
            (*gPartfxInterface)->spawnObject(obj, pulseEffectId, &params, 1, -1, NULL);
            break;
        case 3:
            params.effectParam = 255;
            (*gPartfxInterface)->spawnObject(obj, pulseEffectId, &params, 1, -1, NULL);
            break;
        }
    }

    params.scale = scale;
    if ((u8)type != 0)
    {
        switch (typeByte)
        {
        case 1:
            params.effectParam = 3085;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1960, &params, 1, -1, NULL);
            }
            break;
        case 2:
            params.effectParam = 3082;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1961, &params, 1, -1, NULL);
            }
            break;
        case 3:
            params.effectParam = 3082;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1962, &params, 1, -1, NULL);
            }
            break;
        case 4:
            params.effectParam = 3086;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 5:
            params.effectParam = 132;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 6:
            params.effectParam = 3087;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 7:
            params.effectParam = 100;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 8:
            params.effectParam = 3198;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 9:
            if (params.scale < lbl_803DF358)
            {
                params.scale = *(f32*)&lbl_803DF358;
            }
            for (j = 0; j < frameCount * 2; j++)
            {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1973, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1973, &params, 1, -1, NULL);
            }
            break;
        case 10:
            if (params.scale < lbl_803DF358)
            {
                params.scale = *(f32*)&lbl_803DF358;
            }
            for (j = 0; j < frameCount * 2; j++)
            {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1974, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1974, &params, 1, -1, NULL);
            }
            break;
        case 11:
            params.effectParam = 100;
            for (j = 0; j < frameCount; j++)
            {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 12:
            if (params.scale < 0.25f)
            {
                params.scale = 0.25f;
            }
            params.pad00[2] = 50;
            for (j = 0; j < frameCount * 2; j++)
            {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1979, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1979, &params, 1, -1, NULL);
            }
            break;
        case 13:
            if (params.scale < lbl_803DF358)
            {
                params.scale = *(f32*)&lbl_803DF358;
            }
            params.pad00[2] = 90;
            for (j = 0; j < frameCount * 2; j++)
            {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
            }
            break;
        case 14:
            if (params.scale < lbl_803DF358)
            {
                params.scale = *(f32*)&lbl_803DF358;
            }
            params.pad00[2] = 240;
            for (j = 0; j < frameCount * 2; j++)
            {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
            }
            break;
        }
    }
}
void projectileParticleFxFn_80099660(void* obj, f32 scaleArg, int mode)
{
    ObjFxParticleParams params;
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
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, &params, 1, -1, NULL);
        }
        tailScale = 0.3f;
        break;
    case 1:
        i = 10;
        scale = lbl_803DF354;
        for (; i < 20; i += 2)
        {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, &params, 1, -1, NULL);
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
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, &params, 1, -1, NULL);
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
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, &params, 1, -1, NULL);
        }
        tailScale = 0.3f;
        break;
    case 4:
        i = 10;
        scale = lbl_803DF354;
        for (; i < 20; i += 2)
        {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, &params, 1, -1, NULL);
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
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, &params, 1, -1, NULL);
        }
        tailScale = 0.3f;
        break;
    default:
        return;
    }
    (*gPartfxInterface)->spawnObject(obj, 0x79f, NULL, 1, -1, &tailScale);
}

void itemPickupDoParticleFx(void* obj, f32 scale, int mode, u8 count)
{
    ObjFxParticleParams params;
    int i;

    params.scale = scale;
    if (mode == 0)
    {
        return;
    }
    switch (mode)
    {
    case 1:
        params.effectParam = 0x79;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 2:
        params.effectParam = 0xc13;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 3:
        params.effectParam = 0x71;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 4:
        params.effectParam = 0xdb;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 5:
        params.effectParam = 0x77;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 6:
        params.effectParam = 0x7b;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 7:
        params.effectParam = 0xda;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 8:
        params.effectParam = 0xdd;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    case 10:
        params.effectParam = 0xde;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    case 9:
        params.effectParam = 0xdf;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    default:
        params.effectParam = 0x5c;
        for (i = 0; i < count; i++)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    }
}

void objParticleFn_80099d84(GameObject* obj, f32 scale, int type, f32 extraScale, ModelLightStruct* light)
{
    ObjFxParticleParams params;
    f32 lightYOffset = 40.0f;
    ObjFxColorTable colorTbl = gObjFxCrystalSparkleTbl;
    u8* rPtr;
    u8* gPtr;
    u8* bPtr;

    params.scale = scale;
    params.pad00[0] = 0;
    params.pad00[2] = 0;
    params.pad00[1] = 0;
    params.effectParam = 0xc0a;
    if ((u8)type)
    {
        switch (type & 0xff)
        {
        case 1:
            params.position[0] = scale * randomGetRange(-10, 10);
            params.position[1] = scale * randomGetRange(-10, 10);
            params.position[2] = scale * randomGetRange(-10, 10);
            (*gPartfxInterface)->spawnObject(obj, 0x32f, &params, 2, -1, &extraScale);
            break;
        case 2:
            params.position[0] = scale * randomGetRange(-10, 10);
            params.position[1] = scale * randomGetRange(-10, 10);
            params.position[2] = scale * randomGetRange(-10, 10);
            (*gPartfxInterface)->spawnObject(obj, 0x330, &params, 2, -1, &extraScale);
            break;
        case 3:
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x32f, &extraScale, 0x19, NULL);
            break;
        case 4:
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x330, &extraScale, 0x19, NULL);
            break;
        case 5:
            params.effectParam = 0xc0a;
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cd, &extraScale, 0x32, &params);
            break;
        case 6:
            params.effectParam = 0xc0d;
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7ce, &extraScale, 0x50, &params);
            break;
        case 7:
            params.effectParam = 0x605;
            params.pad00[2] = 1;
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cf, &extraScale, 0x19, &params);
            lightYOffset = lbl_803DF35C;
            break;
        case 8:
            params.effectParam = 0x605;
            params.pad00[2] = 0;
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cf, &extraScale, 0x19, &params);
            lightYOffset = lbl_803DF35C;
            break;
        }
    }

    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(light, ((GameObject*)obj)->anim.worldPosX,
                                     ((GameObject*)obj)->anim.worldPosY + lightYOffset, ((GameObject*)obj)->anim.worldPosZ);
        rPtr = (u8*)&colorTbl;
        gPtr = (u8*)&colorTbl + 1;
        bPtr = (u8*)&colorTbl + 2;
        modelLightStruct_setDiffuseColor(light, rPtr[(u8)type * 3], gPtr[(u8)type * 3], bPtr[(u8)type * 3], 0xff);
        modelLightStruct_setSpecularColor(light, rPtr[(u8)type * 3], gPtr[(u8)type * 3], bPtr[(u8)type * 3], 0xff);
        modelLightStruct_setDistanceAttenuation(light, lbl_803DF34C, 75.0f);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, 1, lbl_803DF35C);
        modelLightStruct_setEnabled(light, 0, lbl_803DF354);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}

void objLightFn_8009a1dc(void* obj, f32 scale, void* origin, u8 type, void* light)
{
    u8 spawnArgs[16];
    u8 remaining;

    if (type != 0)
    {
        switch (type)
        {
        case 1:
            spawnArgs[0] = 1;
            for (remaining = 10; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, spawnArgs);
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 2:
            spawnArgs[0] = 2;
            for (remaining = 13; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, spawnArgs);
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 6; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 3:
            spawnArgs[0] = 3;
            for (remaining = 30; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, spawnArgs);
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 8; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 4:
            for (remaining = 7; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x328, origin, 0x200001, -1, NULL);
            }
            break;
        case 5:
            spawnArgs[0] = 4;
            for (remaining = 10; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 6:
            spawnArgs[0] = 5;
            for (remaining = 10; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 7:
            spawnArgs[0] = 6;
            for (remaining = 10; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 8:
            spawnArgs[0] = 7;
            for (remaining = 10; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 9:
            spawnArgs[0] = 8;
            for (remaining = 10; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        }
    }

    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(light, ((GameObject*)origin)->anim.localPosX,
                                     10.0f + ((GameObject*)origin)->anim.localPosY,
                                     ((GameObject*)origin)->anim.localPosZ);
        modelLightStruct_setDiffuseColor(light, gObjFxLightColorTbl[type * 3], gObjFxLightColorTbl[type * 3 + 1],
                                         gObjFxLightColorTbl[type * 3 + 2], 0xff);
        modelLightStruct_setSpecularColor(light, gObjFxLightColorTbl[type * 3], gObjFxLightColorTbl[type * 3 + 1],
                                          gObjFxLightColorTbl[type * 3 + 2], 0xff);
        modelLightStruct_setDistanceAttenuation(light, 40.0f, 55.0f);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, 1, lbl_803DF35C);
        modelLightStruct_setEnabled(light, 0, lbl_803DF358);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}

void fn_8009A8C8(GameObject* obj, f32 shakeRange)
{
    GameObject* player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    if (((GameObject*)player)->objectFlags & OBJFX_OBJFLAG_PARENT_SLACK)
    {
        return;
    }
    {
        f32 dist = Camera_DistanceToCurrentViewPosition(
            obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ);
        if (dist <= shakeRange)
        {
            f32 falloff = lbl_803DF354 - dist / shakeRange;
            CameraShake_Start(5.0f * falloff, 10.0f * falloff, 4.0f);
            doRumble(22.0f * falloff);
        }
    }
}

void DIMexplosionFn_8009a96c(u8* src, f32 x, f32 y, f32 z, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake,
                             u8 flag20, u8 f1cinit)
{
    ExplosionSetup* setup;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = (ExplosionSetup*)Obj_AllocObjectSetup(0x24, OBJFX_CHILD_OBJ_EXPLOSION);
        setup->head.color[0] = 2;
        setup->head.color[1] = 1;
        ((GameObject*)setup)->anim.rootMotionScale = x;
        ((GameObject*)setup)->anim.localPosX = y;
        ((GameObject*)setup)->anim.localPosY = z;
        ((ExplosionSetup*)setup)->unk19 = kind;
        *(s16*)((char*)setup + 0x1a) = (s16)(256.0f * scale);
        *(s16*)((char*)setup + 0x1c) = f1cinit;
        if (flag4 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 4;
        }
        if (flag8 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 8;
        }
        if (flag10 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 0x10;
        }
        if (flag20 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 0x20;
        }
        if (doShake != 0)
        {
            GameObject* player = Obj_GetPlayerObject();
            if (player != NULL && (((GameObject*)player)->objectFlags & OBJFX_OBJFLAG_PARENT_SLACK) == 0)
            {
                f32 d = Camera_DistanceToCurrentViewPosition(((ObjAnimComponent*)src)->worldPosX,
                                                             ((ObjAnimComponent*)src)->worldPosY,
                                                             ((ObjAnimComponent*)src)->worldPosZ);
                if (d <= 300.0f)
                {
                    f32 t = lbl_803DF354 - d / 300.0f;
                    CameraShake_Start(5.0f * t, 10.0f * t, 4.0f);
                    doRumble(22.0f * t);
                }
            }
        }
        Obj_SetupObject(&setup->head, 5, ((ObjAnimComponent*)src)->mapEventSlot, -1, NULL);
    }
}

void spawnExplosion(GameObject* src, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake, u8 flag20,
                    u8 f1cinit)
{
    ExplosionSetup* setup;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = (ExplosionSetup*)Obj_AllocObjectSetup(0x24, OBJFX_CHILD_OBJ_EXPLOSION);
        setup->head.color[0] = 2;
        setup->head.color[1] = 1;
        ((GameObject*)setup)->anim.rootMotionScale = src->anim.worldPosX;
        ((GameObject*)setup)->anim.localPosX = src->anim.worldPosY;
        ((GameObject*)setup)->anim.localPosY = src->anim.worldPosZ;
        ((ExplosionSetup*)setup)->unk19 = kind;
        *(s16*)((char*)setup + 0x1a) = (s16)(256.0f * scale);
        *(s16*)((char*)setup + 0x1c) = f1cinit;
        if (flag4 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 4;
        }
        if (flag8 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 8;
        }
        if (flag10 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 0x10;
        }
        if (flag20 != 0)
        {
            *(s16*)((char*)setup + 0x1c) |= 0x20;
        }
        if (doShake != 0)
        {
            GameObject* player = Obj_GetPlayerObject();
            if (player != NULL && (((GameObject*)player)->objectFlags & OBJFX_OBJFLAG_PARENT_SLACK) == 0)
            {
                f32 d = Camera_DistanceToCurrentViewPosition(src->anim.worldPosX, src->anim.worldPosY,
                                                             src->anim.worldPosZ);
                if (d <= 300.0f)
                {
                    f32 t = lbl_803DF354 - d / 300.0f;
                    CameraShake_Start(5.0f * t, 10.0f * t, 4.0f);
                    doRumble(22.0f * t);
                }
            }
        }
        Obj_SetupObject(&setup->head, 5, src->anim.mapEventSlot, -1, NULL);
    }
}
