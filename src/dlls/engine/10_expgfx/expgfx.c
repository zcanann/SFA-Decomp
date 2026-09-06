#include "dlls/objects/458_DIMExplosio.h"
#include "main/dll/partfx_interface.h"
#include "dolphin/mtx.h"
#include "string.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_fog_api.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_geom_api.h"
#include "main/hud_visibility_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "sys/objects/lifecycle.h"
#include "main/camera.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/expgfx_internal.h"
#include "game/objects/object.h"
#include "main/dll/player_api.h"
#include "sys/objects.h"
#include "main/objfx.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_queue_api.h"
#include "main/mm.h"
#include "main/sky.h"
#include "main/tex_dolphin.h"
#include "main/texture.h"
#include "main/dll/objfx_api.h"
#include "dolphin/os/OSFastCast.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/render_mode_api.h"
#include "main/dll/objfx.h"
#include "main/trig_float_helpers.h"
#include "main/dll/viewfinder.h"
#include "track/intersect_api.h"
#include "main/lightmap.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/camera_shake_api.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/expgfx_resource_api.h"
#include "main/trig.h"
#include "main/model_light.h"
#include "game/objects/object_setup.h"
#include "main/pad_api.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/os/OSCache.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "dolphin/gx/GXGeometry.h"

typedef union ExpgfxWGPipe {
    u8 u8;
    u16 u16;
    u32 u32;
    s8 s8;
    s16 s16;
    s32 s32;
    f32 f32;
    f64 f64;
} ExpgfxWGPipe;

typedef struct ExpgfxRotateParams {
    s16 angleX;
    s16 angleY;
    s16 angleZ;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ExpgfxRotateParams;

typedef struct ExpgfxBillboardAngles {
    s16 pitch;
    s16 yaw;
} ExpgfxBillboardAngles;

#define GXWGFifo (*(volatile ExpgfxWGPipe*)0xCC008000)

#define EXPGFX_Y_VELOCITY_POSITIVE_LIMIT 15.0f
#define EXPGFX_Y_VELOCITY_FAST_STEP      -0.03f
#define EXPGFX_Y_VELOCITY_SLOW_STEP      -0.003f
#define EXPGFX_Y_VELOCITY_NEGATIVE_LIMIT -15.0f
#define EXPGFX_SLOT_MOTION_STEP          3.0f

#define EXPGFX_BOUNDS_INIT_MIN   3.4028235e38f
#define EXPGFX_BOUNDS_INIT_MAX   -3.4028235e38f
#define EXPGFX_U16_TO_UNIT_SCALE (1.0f / 65535.0f)

static inline ExpgfxTableEntry* Expgfx_GetTableEntry(int tableIndex) {
    return &EXPGFX_RUNTIME_DATA->expTab[tableIndex];
}

static inline u32 Expgfx_GetSlotTableIndex(const ExpgfxSlot* slot) {
    return ((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK;
}

static inline void Expgfx_SetSlotTableIndex(ExpgfxSlot* slot, u8 tableIndex) {
    slot->encodedTableIndex = (tableIndex << 1) | (slot->encodedTableIndex & 1);
}

static inline ExpgfxSlot* Expgfx_GetSlot(int poolIndex, int slotIndex) {
    return (ExpgfxSlot*)(gExpgfxSlotPoolBases[poolIndex] + slotIndex * EXPGFX_SLOT_SIZE);
}

static inline ExpgfxPlaneOffsets* Expgfx_GetPlaneOffsets(int setIndex) {
    return &gExpgfxStaticData[setIndex];
}

#define EXPGFX_POOL_ACTIVE_MASK_PTR(runtime, poolIndex)                                                                \
    ((u32*)((u8*)(runtime)->poolActiveMasks + (poolIndex) * sizeof(u32)))

/*
 * viewfinder - camera zoom control for the photo/viewfinder mode.
 *
 * Maintains the shared zoom scalar gExpgfxNearFadeDepth, derived by scaling a
 * base reference value by the inverse of the current
 * camera FOV. viewFinderSetZoomTo50 snaps it to a fixed preset.
 * The result is consumed elsewhere (dll_000A_expgfx)
 * as a view-projection W threshold gating effect rendering.
 *
 * Driven from the player viewfinder/camera-mode code (player.c,
 * dll_0044_cameramodeviewfinder.c).
 */

static const ObjFxU16Table3 objFxHitEffectIdTbl = {{0x0000, 0x07DD, 0x07DE}};

void viewFinderSetZoom(f32 zoom) {
    gExpgfxNearFadeDepth = -3000.0f / zoom;
}

void viewFinderSetZoomTo50(void) {
    gExpgfxNearFadeDepth = 50.0f;
}

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
 * modelLightStruct_*). objfx_shakeCameraByDistance / spawnExplosion / DIMexplosionFn add a
 * distance-attenuated camera shake + rumble and spawn the shared explosion
 * object (type 0x24, id 0x253). The numerous 0x3xx/0x7xx literals are
 * particle-effect resource ids; the float lbl_803DFxxx symbols are tuning
 * constants in the DLL's shared .sdata2 pool.
 */

ExpgfxPlaneOffsets gExpgfxStaticData[EXPGFX_STATIC_PLANE_OFFSET_SET_COUNT] = {
    {{-5.0f, 50.0f, 50.0f, 50.0f, 50.0f, 50.0f}},
    {{50.0f, 50.0f, 50.0f, 50.0f, 50.0f, 50.0f}},
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
ObjFxLightColor gObjFxLightColorTbl[12] = {
    {0x00, 0x00, 0x00}, {0x40, 0xFF, 0xFF}, {0xFF, 0xFF, 0x40}, {0xFF, 0x40, 0x7F},
    {0x7F, 0x7F, 0x7F}, {0x40, 0xFF, 0x40}, {0xFF, 0xFF, 0x00}, {0xFF, 0x7F, 0x40},
    {0xFF, 0xFF, 0x40}, {0x00, 0x7F, 0xFF}, {0x00, 0x00, 0x00}, {0x00, 0x00, 0x00},
};

ExpgfxDllInterface expgfx_funcs = {
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

const ObjFxColorTable gObjFxCrystalSparkleTbl = {{0x0000, 0x00FF, 0x7FFF, 0x7FC0, 0xFFFF, 0x7FFF, 0x7FC0, 0xFFFF,
                                                  0xA000, 0xFFA0, 0x007F, 0x40FF, 0x0000, 0x0000, 0x0000}};
const ObjFxS32Table5 gObjFxPulseVariantTbl = {{0, 0, 0, 1, 2}};
const ObjFxSparkleEffectTable gObjFxHitPulseTbl = {
    {{0, 2, 3, 3, 3}},
    {{0x0000, 0x00DF, 0x0160, 0x00DE, 0x0200, 0x00DD, 0x00E0, 0x00E4, 0x007B, 0x0000, 0x07D3, 0x07D3,
      0x07D4, 0x07D5, 0x07D6, 0x07DC, 0x07DC, 0x07DC, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
      0x0200, 0x0080, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00BF, 0x00BF},
     {0x0000, 0x00DF, 0x0160, 0x00DE, 0x0200, 0x00DD, 0x00E0, 0x00E4, 0x007B, 0x0000, 0x07D3, 0x07D3,
      0x07D4, 0x07D5, 0x07D6, 0x07DC, 0x07DC, 0x07DC, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
      0x0200, 0x0080, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00BF, 0x00BF},
     {0x0000, 0x00DF, 0x0160, 0x00DE, 0x0200, 0x00DD, 0x00E0, 0x00E4, 0x007B, 0x0000, 0x07D3, 0x07D3,
      0x07D4, 0x07D5, 0x07D6, 0x07DC, 0x07DC, 0x07DC, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
      0x0200, 0x0080, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00BF, 0x00BF}}};
const ObjFxU16Table11 gObjFxHitEffectParamTbl = {
    {0x0000, 0x0079, 0x007B, 0x00DB, 0x0C13, 0x0605, 0x0C75, 0x0C74, 0x0C76, 0x0C77, 0x0C78}};
const ObjFxU16Table7 gObjFxMaskedHitSpawnIdTbl = {{0x0000, 0x07D9, 0x07DA, 0x07DB, 0x07E8, 0x07E9, 0x07EA}};
const ObjFxU16Table11 gObjFxHitEffectParamTbl2 = {
    {0x0000, 0x0079, 0x007B, 0x00DB, 0x0C13, 0x0605, 0x0C75, 0x0C74, 0x0C76, 0x0C77, 0x0C78}};
const ObjFxRandomBurstTable gObjFxRandomBurstTbl = {{{0x000, 0},
                                                     {0x3A2, 1},
                                                     {0x3A3, 1},
                                                     {0x3A4, 1},
                                                     {0x3A5, 1},
                                                     {0x3A2, 2},
                                                     {0x3A3, 2},
                                                     {0x3A4, 2},
                                                     {0x3A5, 2},
                                                     {0x630, 0},
                                                     {0xC10, 0},
                                                     {0x630, 0},
                                                     {0x62F, 0}}};

#define OBJFX_OBJFLAG_PARENT_SLACK 0x1000

void objfx_spawnCrystalOrbitEffects(GameObject* obj, s16* work, f32 period, f32 xMul, f32 yMul, f32 xOff, f32 yOff,
                                    u8 flags) {
    ObjFxParticleParams params;
    int crystalIdx;
    int angleStep;
    int spawnFlags;
    f32 wave;

    for (crystalIdx = 0; crystalIdx < 4; crystalIdx++) {
        work[0x12 + crystalIdx] = (65535.0f / period + (f32)(crystalIdx * randomGetRange(120, 127)));
        wave = work[0x12 + crystalIdx];
        work[0xe + crystalIdx] = (wave * timeDelta + work[0xe + crystalIdx]);
        wave = fsin16((u16)work[0xe + crystalIdx]);
        wave = (1.0f + wave) / 2.0f;
        {
            f32 amp = gObjFxCrystalAmpTbl.amps[crystalIdx];
            *(f32*)((char*)work + 0xc + crystalIdx * 4) = amp * wave;
        }

        work[0x16 + crystalIdx] = (timeDelta * gObjFxCrystalSpinSpeed[crystalIdx] + work[0x16 + crystalIdx]);
        *(u16*)work = work[0x16 + crystalIdx];
        *(f32*)((char*)work + 8) = *(f32*)((char*)work + 0xc + crystalIdx * 4);

        for (angleStep = 0; angleStep < 0xffff; angleStep += 0x7fff) {
            params.position[0] = *(f32*)((char*)work + 8) * xMul + xOff;
            params.position[1] = *(f32*)((char*)work + 8) * yMul + yOff;
            params.position[2] = 0.0f;
            *(u16*)work += 0x7fff;
            vecRotateZXY(work, params.position);
            params.position[0] += obj->anim.localPosX;
            params.position[1] += obj->anim.localPosY;
            params.position[2] += obj->anim.localPosZ;
            params.scale = 1.0f;
            spawnFlags = 0x200001;
            if (flags != 0) {
                spawnFlags |= 0x20000000;
            }
            (*gPartfxInterface)->spawnObject(obj, 0x7ec, &params, spawnFlags, -1, NULL);
        }
    }
}

void objfx_spawnRandomBurst(void* obj, u8 type, u8 count, void* origin, f32 mult, u8 flagByte) {
    ObjFxParticleParams params;
    ObjFxRandomBurstTable burstTbl = gObjFxRandomBurstTbl;
    u16 randAngles[3];
    int i;
    f32 unitRand;
    u8 frameCount;

    if (framesThisStep > 3) {
        frameCount = 3;
    } else {
        frameCount = framesThisStep;
    }
    for (i = 0; i < frameCount * count; i++) {
        unitRand = randomGetRange(0, 1000) / 1000.0f;
        randAngles[0] = randomGetRange(0, 0xffff);
        randAngles[1] = randomGetRange(0, 0xffff);
        randAngles[2] = randomGetRange(0, 0xffff);
        params.position[0] = mult * (1.0f - unitRand * (unitRand * unitRand));
        params.position[1] = 0.0f;
        params.position[2] = 0.0f;
        vecRotateZXY((s16*)randAngles, params.position);
        if (origin != NULL) {
            params.position[0] += ((PartFxSpawnParams*)origin)->posX;
            params.position[1] += ((PartFxSpawnParams*)origin)->posY;
            params.position[2] += ((PartFxSpawnParams*)origin)->posZ;
        }
        params.effectParam = burstTbl.entries[type].effectParam;
        params.pad00[1] = burstTbl.entries[type].extraParam;
        params.pad00[2] = flagByte;
        params.scale = 1.0f;
        if (type >= 9 && type <= 0xb) {
            if (type == 0xb || type == 0xa) {
                (*gPartfxInterface)->spawnObject(obj, 0x7e3, &params, 2, -1, NULL);
            }
            if (type == 0xb || type == 9) {
                (*gPartfxInterface)->spawnObject(obj, 0x7e4, &params, 2, -1, NULL);
            }
        } else {
            (*gPartfxInterface)->spawnObject(obj, 0x7e2, &params, 2, -1, NULL);
        }
    }
}

void objfx_spawnHitEmitterAtPos(f32* pos, u8 a, u8 b, u8 c, u8 d) {
    StaffCollisionColorArgs emitterArgs;
    ObjFxParticleEmitter emitter;
    StaffCollisionInterface** partfxIface;
    emitter.scale = 1.0f;
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

void objfx_spawnHitEffectBurst(void* obj, f32 scale, u8 idSel, u8 paramSel, u8 count, GameObject* origin) {
    ObjFxParticleParams params;
    ObjFxU16Table11 table = gObjFxHitEffectParamTbl2;
    ObjFxU16Table3 effectIds = objFxHitEffectIdTbl;
    int i;
    if (idSel == 0 || paramSel == 0) {
        return;
    }
    params.scale = scale;
    params.effectParam = table.values[paramSel];
    if (origin != NULL) {
        params.position[0] = origin->anim.localPosX;
        params.position[1] = origin->anim.localPosY;
        params.position[2] = origin->anim.localPosZ;
    } else {
        params.position[0] = 0.0f;
        params.position[1] = 0.0f;
        params.position[2] = 0.0f;
    }
    for (i = 0; i < count; i++) {
        (*gPartfxInterface)->spawnObject(obj, effectIds.values[idSel], &params, 2, -1, NULL);
    }
}

void objfx_spawnMaskedHitEffect(void* obj, f32 scale, u8 type, u8 mode, u8 mask, void* origin) {
    ObjFxParticleParams params;
    ObjFxU16Table11 effectParamTbl = gObjFxHitEffectParamTbl;
    ObjFxU16Table7 spawnIdTbl = gObjFxMaskedHitSpawnIdTbl;
    if (type == 0 || mode == 0) {
        return;
    }
    if ((mask & (u16)(int)gExpgfxFrameTimerA) == 0) {
        return;
    }
    params.scale = scale;
    params.effectParam = effectParamTbl.values[mode];
    if (origin != NULL) {
        params.position[0] = ((GameObject*)origin)->anim.localPosX;
        params.position[1] = ((GameObject*)origin)->anim.localPosY;
        params.position[2] = ((GameObject*)origin)->anim.localPosZ;
    } else {
        params.position[0] = 0.0f;
        params.position[1] = 0.0f;
        params.position[2] = 0.0f;
    }
    (*gPartfxInterface)->spawnObject(obj, spawnIdTbl.values[type], &params, 2, -1, NULL);
}

void objfx_spawnDirectionalBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mult, void* origin,
                                 int flags) {
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
    for (i = 0; i < 4; i++) {
        if (randomGetRange(0, 0x63) >= chance) {
            continue;
        }
        radialT = randomGetRange(0, 1000) / 1000.0f;
        switch (mode) {
        case 1:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (1.0f - radialT * (radialT * radialT));
            break;
        case 2:
            rvec[0] = 0;
            rvec[1] = randomGetRange(0, 0xffff);
            rvec[2] = 0;
            params.position[0] = mult * (1.0f - radialT * (radialT * radialT));
            break;
        case 3:
            rvec[0] = randomGetRange(0, 0xffff);
            rvec[1] = 0;
            rvec[2] = 0;
            params.position[0] = mult * (1.0f - radialT * (radialT * radialT));
            break;
        case 4:
            rvec[0] = 0;
            rvec[1] = 0;
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (1.0f - radialT * (radialT * radialT));
            break;
        case 5:
            rvec[0] = randomGetRange(0x7fff, 0xffff);
            rvec[1] = 0;
            rvec[2] = randomGetRange(0, 0xffff);
            params.position[0] = mult * (1.0f - radialT * (radialT * radialT));
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
            params.position[0] = mult * (1.0f - radialT * (radialT * (radialT * (radialT * radialT))));
            break;
        }
        params.position[1] = 0.0f;
        params.position[2] = 0.0f;
        vecRotateZXY((s16*)rvec, params.position);
        if (origin != NULL) {
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

void objfx_spawnArcedBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, int chance, f32 angBase, f32 lo, f32 hi,
                           void* origin, int flags) {
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
    params.effectParam = effectParams.values[kind];
    params.pad00[1] = 0x3c;
    for (i = 0; i < 4; i++) {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= (u8)chance) {
            continue;
        }
        rvec[0] = randomGetRange(0, 0xffff);
        rvec[1] = 0;
        rvec[2] = 0;
        radialT = randomGetRange(1, 1000) / 1000.0f;
        angularT = randomGetRange(0, 1000) / 1000.0f;
        params.position[1] = 0.0f;
        params.position[2] = 0.0f;
        switch (mode) {
        case 1:
            params.position[0] = 1.0f - radialT * radialT;
            break;
        case 2:
            angularT *= (angularT * angularT);
            params.position[0] = 1.0f - radialT * radialT;
            break;
        case 3:
            angularT = 1.0f - angularT * (angularT * angularT);
            params.position[0] = 1.0f - radialT * radialT;
            break;
        case 4:
            val = (u16)(int)(65535.0f * angularT);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            angularT = 0.5f * (1.0f + mathCosf(a));
            params.position[0] = 1.0f - radialT * radialT;
            break;
        case 5:
            val = (u16)(int)(65535.0f * angularT);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            angularT = 0.5f * (1.0f + mathSinf(a));
            params.position[0] = 1.0f - radialT * radialT;
            break;
        case 6:
            params.position[0] = radialT * radialT;
            break;
        case 7:
            params.position[0] = 1.0f - radialT * (radialT * (radialT * (radialT * radialT)));
            break;
        }
        range = angBase - lo;
        params.position[0] *= (angularT * range + lo);
        vecRotateZXY((s16*)rvec, params.position);
        {
            f32 t = angularT - 0.5f;
            params.position[1] = t * hi;
        }
        if (origin != NULL) {
            params.position[0] += ((GameObject*)origin)->anim.localPosX;
            params.position[1] += ((GameObject*)origin)->anim.localPosY;
            params.position[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad00[2] = paramC.values[idx];
        params.pad00[0] = paramD.values[idx];
        (*gPartfxInterface)->spawnObject(obj, spawnIds.values[idx], &params, flags | 2, -1, NULL);
    }
}

void objfx_spawnBoxBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mulX, f32 mulY, f32 mulZ,
                         void* origin, int flags) {
    ObjFxParticleParams params;
    ObjFxU16Table9 effectParams = *(ObjFxU16Table9*)((char*)&gObjFxCrystalSparkleTbl + 0x48);
    ObjFxU16Table8 spawnIds = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x5c);
    ObjFxU16Table8 paramC = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x6c);
    ObjFxU16Table8 paramD = *(ObjFxU16Table8*)((char*)&gObjFxCrystalSparkleTbl + 0x7c);
    int i;

    params.scale = scale;
    params.effectParam = effectParams.values[kind];
    params.pad00[1] = 0x3c;
    for (i = 0; i < 4; i++) {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance) {
            continue;
        }
        params.position[0] = randomGetRange(0, 1000) / 1000.0f;
        params.position[1] = randomGetRange(0, 1000) / 1000.0f;
        params.position[2] = randomGetRange(0, 1000) / 1000.0f;
        switch (mode) {
        case 1:
            params.position[0] -= 0.5f;
            params.position[1] -= 0.5f;
            params.position[2] -= 0.5f;
            break;
        case 2:
            params.position[0] -= 0.5f;
            params.position[1] = params.position[1] * (params.position[1] * params.position[1]) - 0.5f;
            params.position[2] -= 0.5f;
            break;
        case 3:
            params.position[0] -= 0.5f;
            params.position[1] = (1.0f - params.position[1] * (params.position[1] * params.position[1])) - 0.5f;
            params.position[2] -= 0.5f;
            break;
        case 4:
            params.position[0] -= 0.5f;
            val = (u16)(int)(65535.0f * params.position[1]);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            params.position[1] = 0.5f * mathCosf(a);
            params.position[2] -= 0.5f;
            break;
        case 5:
            params.position[0] -= 0.5f;
            val = (u16)(int)(65535.0f * params.position[1]);
            a = OBJ_FX_PI * (f32)(u32)val / 32768.0f;
            params.position[1] = 0.5f * mathSinf(a);
            params.position[2] -= 0.5f;
            break;
        case 6:
            params.position[0] -= 0.5f;
            params.position[1] -= 0.5f;
            params.position[2] -= 0.5f;
            break;
        case 7:
            params.position[0] -= 0.5f;
            params.position[1] -= 0.5f;
            params.position[2] -= 0.5f;
            break;
        }
        params.position[0] *= mulX;
        params.position[1] *= mulY;
        params.position[2] *= mulZ;
        if (origin != NULL) {
            params.position[0] += ((GameObject*)origin)->anim.localPosX;
            params.position[1] += ((GameObject*)origin)->anim.localPosY;
            params.position[2] += ((GameObject*)origin)->anim.localPosZ;
        }
        params.pad00[2] = paramC.values[idx];
        params.pad00[0] = paramD.values[idx];
        (*gPartfxInterface)->spawnObject(obj, spawnIds.values[idx], &params, flags | 2, -1, NULL);
    }
}

void objShowButtonGlow(void* obj, f32 intensity, u8 glowKind) {
    ObjFxParticleParams params;
    int i;

    params.scale = intensity;
    if (glowKind == 0) {
        return;
    }
    switch (glowKind) {
    case 1:
        params.effectParam = 0xc8c;
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.effectParam = 1;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 2:
        params.effectParam = 0xc8d;
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.effectParam = 0;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 3:
        params.effectParam = 0xc8e;
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7c8, &params, 1, -1, NULL);
        }
        params.effectParam = 2;
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 0x7f3, &params, 1, -1, NULL);
        break;
    case 4:
        params.effectParam = 0;
        for (i = 0; i < 0x14; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7f2, &params, 1, -1, NULL);
        }
        break;
    }
}

void objfx_spawnFrameTimedHitPulse(GameObject* obj, f32 scale, u8 type, u8 variant, f32 yOffset) {
    ObjFxS32Table5 variantTbl = gObjFxPulseVariantTbl;
    ObjFxS32Table5 countTbl = gObjFxHitPulseTbl.counts;
    f32 offset[3];
    int frame;
    if (type == 0) {
        return;
    }
    if (variant == 0 || variant >= 5) {
        return;
    }
    {
        if (gExpgfxFrameTimerB != 0.0f) {
            frame = 0;
        } else {
            frame = countTbl.values[variant] & 0xff;
        }
        offset[0] = 0.0f;
        offset[1] = yOffset;
        offset[2] = 0.0f;
        switch (type) {
        case 1:
            objfx_spawnPulseBurst(obj, scale, (u8)variantTbl.values[variant], frame, 0, offset);
            break;
        }
    }
}

void objfx_spawnLightPulse(GameObject* obj, f32 scale, int type, int a3, int mode, f32 sizeParam, void* light) {
    ObjFxParticleParams params;
    f32 lightOffset[6];
    f32 ndc[3];
    s32 screenPos[3];
    int i;
    int depth;
    u8 frameCount;

    if (framesThisStep > 3) {
        frameCount = 3;
    } else {
        frameCount = framesThisStep;
    }
    params.scale = scale;
    if (sizeParam <= 0.001f) {
        sizeParam = 0.001f;
    }
    params.position[0] = sizeParam;
    if ((u8)type != 0) {
        switch ((u8)type) {
        case 1:
            params.effectParam = 0x159;
            params.pad00[2] = 1;
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7be, &params, 2, -1, light);
            }
            break;
        case 2:
            params.effectParam = 0x159;
            params.pad00[2] = 0;
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7be, &params, 2, -1, light);
            }
            break;
        case 3:
            params.effectParam = 0x8e;
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7c0, &params, 2, -1, light);
            }
            break;
        case 4: {
            int flags = 2;
            if ((obj->anim.flags & 0x40080) != 0) {
                flags |= 0x20000000;
            }
            params.effectParam = 0xc0e;
            params.pad00[2] = 0;
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7eb, &params, flags, -1, light);
            }
            break;
        }
        }
    }

    if ((u8)mode != 0) {
        if (light != NULL) {
            lightOffset[3] = ((GameObject*)light)->anim.localPosX;
            lightOffset[4] = ((GameObject*)light)->anim.localPosY;
            lightOffset[5] = ((GameObject*)light)->anim.localPosZ;
            vecRotateZXY((s16*)obj, &lightOffset[3]);
            Camera_ProjectWorldPointWithOffset(
                obj->anim.worldPosX + lightOffset[3] - playerMapOffsetX, obj->anim.worldPosY + lightOffset[4],
                obj->anim.worldPosZ + lightOffset[5] - playerMapOffsetZ, 10.0f, &ndc[2], &ndc[1], &ndc[0]);
        } else {
            Camera_ProjectWorldPointWithOffset(obj->anim.worldPosX - playerMapOffsetX, obj->anim.worldPosY,
                                               obj->anim.worldPosZ - playerMapOffsetZ, 10.0f, &ndc[2], &ndc[1],
                                               &ndc[0]);
        }
        Camera_ClipToScreen(ndc[2], ndc[1], ndc[0], &screenPos[2], &screenPos[1], &screenPos[0]);
        depth = depthReadRequestPoll(screenPos[2], screenPos[1], obj);
        if (screenPos[0] > depth) {
            switch ((u8)mode) {
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
        switch ((u8)mode) {
        case 1:
            if ((u8)type == 1) {
                params.effectParam = 0xc75;
            } else {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 2:
            params.effectParam = 0x605;
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 3:
            if ((u8)type == 1) {
                params.effectParam = 0xc75;
            } else {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7c1, &params, 2, -1, light);
            }
            break;
        case 4:
            if ((u8)type == 1) {
                params.effectParam = 0xc75;
            } else {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 5:
            params.effectParam = 0x605;
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 6:
            if ((u8)type == 1) {
                params.effectParam = 0xc75;
            } else {
                params.effectParam = 0xc74;
            }
            for (i = 0; i < frameCount; i++) {
                (*gPartfxInterface)->spawnObject(obj, 0x7c5, &params, 2, -1, light);
            }
            break;
        }
    }
}

void objfx_spawnFlaggedTrailBurst(void* obj, f32 fval, u8 mode, int f6val, int f4val, void* origin) {
    ObjFxParticleFlags params;
    int i;
    u8 count;

    if (framesThisStep > 3) {
        count = 3;
    } else {
        count = framesThisStep;
    }
    params.effectParam = f6val;
    params.f4 = f4val;
    params.scale = fval;
    if (mode == 0) {
        return;
    }
    switch (mode) {
    case 1:
        params.a = 0;
        params.b = 0;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    case 2:
        params.a = 1;
        params.b = 0;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    case 3:
        params.a = 0;
        params.b = 1;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    case 4:
        params.a = 1;
        params.b = 1;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b7, &params, 1, -1, origin);
        }
        break;
    }
}

void objfx_spawnPulseBurst(void* obj, f32 scale, int type, int count, int mode, f32* vec) {
    ObjFxParticleParams params;
    int j;
    int i;
    int pulseEffectId;
    int typeByte;
    u8 frameCount;

    if (framesThisStep > 3) {
        frameCount = 3;
    } else {
        frameCount = framesThisStep;
    }

    params.scale = scale;
    if (vec != NULL) {
        params.position[0] = vec[0];
        params.position[1] = vec[1];
        params.position[2] = vec[2];
    } else {
        f32 z = 0.0f;
        params.position[0] = z;
        params.position[1] = z;
        params.position[2] = z;
    }

    typeByte = (u8)type;
    switch (typeByte) {
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
        if ((u8)count != 0) {
            count = 8;
        }
        break;
    default:
        pulseEffectId = 1967;
        break;
    }

    if ((u8)count != 0) {
        switch ((u8)count) {
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
            if (params.scale < 0.5f) {
                params.scale = 0.5f;
            }
            params.pad00[2] = 90;
            for (i = 0; i < frameCount * 2; i++) {
                (*gPartfxInterface)->spawnObject(obj, 1981, &params, 1, -1, NULL);
            }
            break;
        }
    }

    if ((u8)mode != 0) {
        switch ((u8)mode) {
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
    if ((u8)type != 0) {
        switch (typeByte) {
        case 1:
            params.effectParam = 3085;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1960, &params, 1, -1, NULL);
            }
            break;
        case 2:
            params.effectParam = 3082;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1961, &params, 1, -1, NULL);
            }
            break;
        case 3:
            params.effectParam = 3082;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1962, &params, 1, -1, NULL);
            }
            break;
        case 4:
            params.effectParam = 3086;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 5:
            params.effectParam = 132;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 6:
            params.effectParam = 3087;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1963, &params, 1, -1, NULL);
            }
            break;
        case 7:
            params.effectParam = 100;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 8:
            params.effectParam = 3198;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 9:
            if (params.scale < 0.5f) {
                params.scale = 0.5f;
            }
            for (j = 0; j < frameCount * 2; j++) {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1973, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1973, &params, 1, -1, NULL);
            }
            break;
        case 10:
            if (params.scale < 0.5f) {
                params.scale = 0.5f;
            }
            for (j = 0; j < frameCount * 2; j++) {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1974, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1974, &params, 1, -1, NULL);
            }
            break;
        case 11:
            params.effectParam = 100;
            for (j = 0; j < frameCount; j++) {
                (*gPartfxInterface)->spawnObject(obj, 1964, &params, 1, -1, NULL);
            }
            break;
        case 12:
            if (params.scale < 0.25f) {
                params.scale = 0.25f;
            }
            params.pad00[2] = 50;
            for (j = 0; j < frameCount * 2; j++) {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1979, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1979, &params, 1, -1, NULL);
            }
            break;
        case 13:
            if (params.scale < 0.5f) {
                params.scale = 0.5f;
            }
            params.pad00[2] = 90;
            for (j = 0; j < frameCount * 2; j++) {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
            }
            break;
        case 14:
            if (params.scale < 0.5f) {
                params.scale = 0.5f;
            }
            params.pad00[2] = 240;
            for (j = 0; j < frameCount * 2; j++) {
                params.effectParam = 0;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
                params.effectParam = 1;
                (*gPartfxInterface)->spawnObject(obj, 1980, &params, 1, -1, NULL);
            }
            break;
        }
    }
}
void projectileDoParticleFx(void* obj, f32 scaleArg, int mode) {
    ObjFxParticleParams params;
    f32 tailScale;
    f32 scale;
    int i;

    switch (mode) {
    case 0:
        i = 10;
        scale = 0.5f;
        for (; i < 20; i += 2) {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, &params, 1, -1, NULL);
        }
        tailScale = 0.3f;
        break;
    case 1:
        i = 10;
        scale = 1.0f;
        for (; i < 20; i += 2) {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, &params, 1, -1, NULL);
        }
        for (i = 0; i < 20; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7a0, NULL, 1, -1, NULL);
        }
        tailScale = 1.0f;
        break;
    case 2:
        i = 10;
        scale = 1.0f;
        for (; i < 20; i += 2) {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, &params, 1, -1, NULL);
        }
        for (i = 0; i < 20; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7a1, NULL, 1, -1, NULL);
        }
        tailScale = 1.0f;
        break;
    case 3:
        i = 10;
        scale = 0.5f;
        for (; i < 20; i += 2) {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, &params, 1, -1, NULL);
        }
        tailScale = 0.3f;
        break;
    case 4:
        i = 10;
        scale = 1.0f;
        for (; i < 20; i += 2) {
            params.effectParam = i;
            params.scale = scale;
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, &params, 1, -1, NULL);
        }
        for (i = 0; i < 20; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7a6, NULL, 1, -1, NULL);
        }
        tailScale = 1.0f;
        break;
    case 6:
        i = 10;
        scale = 0.5f;
        for (; i < 20; i += 2) {
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

void itemPickupDoParticleFx(void* obj, f32 scale, int mode, u8 count) {
    ObjFxParticleParams params;
    int i;

    params.scale = scale;
    if (mode == 0) {
        return;
    }
    switch (mode) {
    case 1:
        params.effectParam = 0x79;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 2:
        params.effectParam = 0xc13;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 3:
        params.effectParam = 0x71;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 4:
        params.effectParam = 0xdb;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 5:
        params.effectParam = 0x77;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 6:
        params.effectParam = 0x7b;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 7:
        params.effectParam = 0xda;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    case 8:
        params.effectParam = 0xdd;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    case 10:
        params.effectParam = 0xde;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    case 9:
        params.effectParam = 0xdf;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7cc, &params, 1, -1, NULL);
        }
        break;
    default:
        params.effectParam = 0x5c;
        for (i = 0; i < count; i++) {
            (*gPartfxInterface)->spawnObject(obj, 0x7b1, &params, 1, -1, NULL);
        }
        break;
    }
}

void objDoParticleFx(GameObject* obj, f32 scale, int type, f32 extraScale, ModelLightStruct* light) {
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
    if ((u8)type) {
        switch (type & 0xff) {
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
            lightYOffset = 0.0f;
            break;
        case 8:
            params.effectParam = 0x605;
            params.pad00[2] = 0;
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7cf, &extraScale, 0x19, &params);
            lightYOffset = 0.0f;
            break;
        }
    }

    if (light != NULL) {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(light, obj->anim.worldPosX, obj->anim.worldPosY + lightYOffset,
                                     obj->anim.worldPosZ);
        rPtr = (u8*)&colorTbl;
        gPtr = (u8*)&colorTbl + 1;
        bPtr = (u8*)&colorTbl + 2;
        modelLightStruct_setDiffuseColor(light, rPtr[(u8)type * 3], gPtr[(u8)type * 3], bPtr[(u8)type * 3], 0xff);
        modelLightStruct_setSpecularColor(light, rPtr[(u8)type * 3], gPtr[(u8)type * 3], bPtr[(u8)type * 3], 0xff);
        modelLightStruct_setDistanceAttenuation(light, 50.0f, 75.0f);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, 1, 0.0f);
        modelLightStruct_setEnabled(light, 0, 1.0f);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}

void objDoHitParticleFx(void* obj, f32 scale, void* origin, u8 type, void* light) {
    u8 spawnArgs[16];
    u8 remaining;

    if (type != 0) {
        switch (type) {
        case 1:
            spawnArgs[0] = 1;
            for (remaining = 10; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, spawnArgs);
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 2:
            spawnArgs[0] = 2;
            for (remaining = 13; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, spawnArgs);
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 6; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 3:
            spawnArgs[0] = 3;
            for (remaining = 30; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x325, origin, 0x200001, -1, spawnArgs);
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 8; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 4:
            for (remaining = 7; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x328, origin, 0x200001, -1, NULL);
            }
            break;
        case 5:
            spawnArgs[0] = 4;
            for (remaining = 10; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 6:
            spawnArgs[0] = 5;
            for (remaining = 10; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 7:
            spawnArgs[0] = 6;
            for (remaining = 10; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 8:
            spawnArgs[0] = 7;
            for (remaining = 10; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        case 9:
            spawnArgs[0] = 8;
            for (remaining = 10; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x323, origin, 0x200001, -1, spawnArgs);
            }
            for (remaining = 4; remaining != 0; remaining--) {
                (*gPartfxInterface)->spawnObject(obj, 0x326, origin, 0x200001, -1, spawnArgs);
            }
            break;
        }
    }

    if (light != NULL) {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(light, ((GameObject*)origin)->anim.localPosX,
                                     10.0f + ((GameObject*)origin)->anim.localPosY,
                                     ((GameObject*)origin)->anim.localPosZ);
        modelLightStruct_setDiffuseColor(light, gObjFxLightColorTbl[type].r, gObjFxLightColorTbl[type].g,
                                         gObjFxLightColorTbl[type].b, 0xff);
        modelLightStruct_setSpecularColor(light, gObjFxLightColorTbl[type].r, gObjFxLightColorTbl[type].g,
                                          gObjFxLightColorTbl[type].b, 0xff);
        modelLightStruct_setDistanceAttenuation(light, 40.0f, 55.0f);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, 1, 0.0f);
        modelLightStruct_setEnabled(light, 0, 0.5f);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}

void objfx_shakeCameraByDistance(GameObject* obj, f32 shakeRange) {
    GameObject* player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    if (player->objectFlags & OBJFX_OBJFLAG_PARENT_SLACK) {
        return;
    }
    {
        f32 dist = Camera_DistanceToCurrentViewPosition(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ);
        if (dist <= shakeRange) {
            f32 falloff = 1.0f - dist / shakeRange;
            CameraShake_StartDampened(5.0f * falloff, 10.0f * falloff, 4.0f);
            doRumble(22.0f * falloff);
        }
    }
}

void spawnDimExplosion(u8* src, f32 x, f32 y, f32 z, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake,
                       u8 flag20, u8 f1cinit) {
    DimExplosionPlacement* setup;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        setup = (DimExplosionPlacement*)Obj_AllocObjectSetup(sizeof(DimExplosionPlacement), DIM_EXPLOSION_OBJECT_ID);
        setup->base.color[0] = 2;
        setup->base.color[1] = 1;
        setup->base.posX = x;
        setup->base.posY = y;
        setup->base.posZ = z;
        setup->sfxKind = kind;
        setup->scaleParam = (s16)(256.0f * scale);
        setup->configFlags = f1cinit;
        if (flag4 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_HAS_GRAVITY;
        }
        if (flag8 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_HAS_RAYS;
        }
        if (flag10 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_SPAWNS_DEBRIS;
        }
        if (flag20 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_HAS_LIGHT;
        }
        if (doShake != 0) {
            GameObject* player = Obj_GetPlayerObject();
            if (player != NULL && (player->objectFlags & OBJFX_OBJFLAG_PARENT_SLACK) == 0) {
                f32 d = Camera_DistanceToCurrentViewPosition(((ObjAnimComponent*)src)->worldPosX,
                                                             ((ObjAnimComponent*)src)->worldPosY,
                                                             ((ObjAnimComponent*)src)->worldPosZ);
                if (d <= 300.0f) {
                    f32 t = 1.0f - d / 300.0f;
                    CameraShake_StartDampened(5.0f * t, 10.0f * t, 4.0f);
                    doRumble(22.0f * t);
                }
            }
        }
        objSetupObject(&setup->base, 5, ((ObjAnimComponent*)src)->mapEventSlot, -1, NULL);
    }
}

void spawnExplosion(GameObject* src, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake, u8 flag20,
                    u8 f1cinit) {
    DimExplosionPlacement* setup;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        setup = (DimExplosionPlacement*)Obj_AllocObjectSetup(sizeof(DimExplosionPlacement), DIM_EXPLOSION_OBJECT_ID);
        setup->base.color[0] = 2;
        setup->base.color[1] = 1;
        setup->base.posX = src->anim.worldPosX;
        setup->base.posY = src->anim.worldPosY;
        setup->base.posZ = src->anim.worldPosZ;
        setup->sfxKind = kind;
        setup->scaleParam = (s16)(256.0f * scale);
        setup->configFlags = f1cinit;
        if (flag4 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_HAS_GRAVITY;
        }
        if (flag8 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_HAS_RAYS;
        }
        if (flag10 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_SPAWNS_DEBRIS;
        }
        if (flag20 != 0) {
            setup->configFlags |= DIM_EXPLOSION_CONFIG_HAS_LIGHT;
        }
        if (doShake != 0) {
            GameObject* player = Obj_GetPlayerObject();
            if (player != NULL && (player->objectFlags & OBJFX_OBJFLAG_PARENT_SLACK) == 0) {
                f32 d =
                    Camera_DistanceToCurrentViewPosition(src->anim.worldPosX, src->anim.worldPosY, src->anim.worldPosZ);
                if (d <= 300.0f) {
                    f32 t = 1.0f - d / 300.0f;
                    CameraShake_StartDampened(5.0f * t, 10.0f * t, 4.0f);
                    doRumble(22.0f * t);
                }
            }
        }
        objSetupObject(&setup->base, 5, src->anim.mapEventSlot, -1, NULL);
    }
}

/*
 * Texture-resource cache for the expgfx (explosion/effect graphics) system.
 * EXPGFX_RUNTIME_DATA->resourceTable holds EXPGFX_RESOURCE_TABLE_COUNT entries,
 * each caching one loaded texture by resourceId.
 *
 * expgfx_updateResourceEntries ages every live entry by framesThisStep and
 * frees it (via textureFree, guarded by gExpgfxTextureFreeInProgress) once its
 * eviction score hits zero. expgfx_acquireResourceEntry returns the slot index
 * for a resource: it reuses a matching live entry, else loads into a free slot,
 * else - only while object setup is allowed (Obj_CanSetupObject) - evicts the
 * lowest-scoring entry and reloads. A texture whose refCount has reached
 * EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT is treated as busy and rejected.
 */

void expgfx_updateResourceEntries(int unused) {
    ExpgfxResourceEntry* entry;
    int i;

    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->resourceId != 0) {
            entry->evictionScore -= framesThisStep;
            if (entry->evictionScore <= 0) {
                entry->resourceId = 0;
                entry->evictionScore = 0;
                entry->reserved = 0;
                gExpgfxTextureFreeInProgress = 1;
                textureFree((Texture*)((u8*)entry->resource));
                gExpgfxTextureFreeInProgress = 0;
                entry->resource = NULL;
            }
        }
    }
}

int expgfx_acquireResourceEntry(int resourceId) {
    int i;
    int minIndex;
    int minEvictionScore;
    ExpgfxResourceEntry* entry;
    ExpgfxResourceHandle* resourceHandle;
    u8 canSetupObject;

    i = 0;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->resource != NULL && resourceId == entry->resourceId) {
            resourceHandle =
                (ExpgfxResourceHandle*)((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[i].resource;
            if (resourceHandle != NULL && resourceHandle->refCount >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT) {
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            EXPGFX_RUNTIME_DATA->resourceTable[i].evictionScore = EXPGFX_RESOURCE_EVICTION_RESET;
            return (s16)i;
        }
    }
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->resource == NULL) {
            ((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[i].resource =
                textureLoadAsset(resourceId);
            resourceHandle =
                (ExpgfxResourceHandle*)((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[i].resource;
            if (resourceHandle != NULL && resourceHandle->refCount >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT) {
                gExpgfxTextureFreeInProgress = 1;
                if (resourceHandle != NULL) {
                    textureFree((Texture*)((u8*)resourceHandle));
                }
                gExpgfxTextureFreeInProgress = 0;
                ((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[i].resource = NULL;
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            if (resourceHandle != NULL) {
                EXPGFX_RUNTIME_DATA->resourceTable[i].evictionScore = EXPGFX_RESOURCE_EVICTION_RESET;
                EXPGFX_RUNTIME_DATA->resourceTable[i].resourceId = resourceId;
                return (s16)i;
            }
            return EXPGFX_RESOURCE_ACQUIRE_LOAD_FAILED;
        }
    }
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return EXPGFX_RESOURCE_ACQUIRE_LOADING_UNLOCKED;
    }
    minEvictionScore = EXPGFX_RESOURCE_EVICTION_SCAN_INITIAL;
    minIndex = 0;
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->evictionScore < minEvictionScore) {
            minEvictionScore = entry->evictionScore;
            minIndex = i;
        }
    }
    gExpgfxTextureFreeInProgress = 1;
    resourceHandle =
        (ExpgfxResourceHandle*)((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[minIndex].resource;
    if (resourceHandle != NULL) {
        textureFree((Texture*)((u8*)resourceHandle));
    }
    gExpgfxTextureFreeInProgress = 0;
    ((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[minIndex].resource = NULL;
    ((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[minIndex].resource =
        textureLoadAsset(resourceId);
    if (((ExpgfxRuntimeDataLayout*)(int)gExpgfxRuntimeData)->resourceTable[minIndex].resource != NULL) {
        EXPGFX_RUNTIME_DATA->resourceTable[minIndex].evictionScore = EXPGFX_RESOURCE_EVICTION_RESET;
        EXPGFX_RUNTIME_DATA->resourceTable[minIndex].resourceId = resourceId;
        return (s16)minIndex;
    }
    return EXPGFX_RESOURCE_ACQUIRE_RELOAD_FAILED;
}

int gExpgfxSlotType1Average;
int gExpgfxSlotType1Sum;
int gExpgfxSlotType1Count;
int gExpgfxLastAddedSlot;
u16 gExpgfxPhaseAngleB;
u16 gExpgfxPhaseAngleA;
f32 gExpgfxFrameTimerC;
f32 gExpgfxFrameTimerB;
f32 gExpgfxFrameTimerA;
int gExpgfxTextureFreeInProgress;
u8 gExpgfxRenderResetPending;
u8 lbl_803DD253;
u8 gExpgfxFrameParityBit;
s16 gExpgfxSequenceCounter;

f32 gExpgfxNearFadeDepth = -50.0f;

void expgfxRemove(u32 slotPoolBase, int poolIndex, int slotIndex, int skipTextureFree, int flushSlot) {
    ExpgfxRuntimeDataLayout* runtime;
    int activeBit[1];
    void** resources[1];
    ExpgfxSlot* slot;
    u32 inactiveBitMask;

    runtime = EXPGFX_RUNTIME_DATA;
    resources[0] = NULL;
    activeBit[0] = 1 << slotIndex;
    if ((activeBit[0] & runtime->poolActiveMasks[poolIndex]) == 0) {
        return;
    }

    slot = (ExpgfxSlot*)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
    slot->behaviorFlags = 0;

    if (skipTextureFree == 0) {
        resources[0] = &runtime->expTab[0].resource;

        if (resources[0][Expgfx_GetSlotTableIndex(slot) * 4] != 0) {
            gExpgfxTextureFreeInProgress = 1;
            textureFree((Texture*)(void*)resources[0][Expgfx_GetSlotTableIndex(slot) * 4]);
            gExpgfxTextureFreeInProgress = 0;
        }

        {
            u32 tableIndex = Expgfx_GetSlotTableIndex(slot);

            if (runtime->expTab[tableIndex].refCount != 0) {
                runtime->expTab[tableIndex].refCount--;
                if (runtime->expTab[tableIndex].refCount == 0) {
                    resources[0][tableIndex * 4] = 0;
                    runtime->expTab[tableIndex].sourceId = 0;
                }
            } else {
                debugPrintf(sExpgfxMismatchInAddRemove);
            }
        }
    }

    slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
    if ((u8)flushSlot != 0) {
        DCFlushRange(slot, EXPGFX_SLOT_SIZE);
    }

    {
        u32 currentMaskValue = runtime->poolActiveMasks[poolIndex];
        inactiveBitMask = ~activeBit[0];
        runtime->poolActiveMasks[poolIndex] = currentMaskValue & inactiveBitMask;
    }
    runtime->poolActiveCounts[poolIndex]--;
    if (runtime->poolActiveCounts[poolIndex] == 0) {
        gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
    }
}

static inline void expgfxRemoveAllBody(void) {
    ExpgfxTableEntry* expTabEntry;
    u16* refCountPtr;
    ExpgfxSlot* slot;
    int slotIndex;
    int poolIndex;
    int activeBit;
    s16* poolSlotTypeIds;
    s8* poolActiveCountPtrs;
    u32* poolActiveMasks;
    u32* slotPoolBases;
    ExpgfxRuntimeDataLayout* runtime;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotPoolBases = runtime->slotPoolBases;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCountPtrs = runtime->poolActiveCounts;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;

    while (poolIndex < EXPGFX_POOL_COUNT) {
        slot = (ExpgfxSlot*)*slotPoolBases;
        slotIndex = 0;
        while (slotIndex < EXPGFX_SLOTS_PER_POOL) {
            activeBit = 1 << slotIndex;
            if ((activeBit & *poolActiveMasks) != 0) {
                if (((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource != 0 &&
                    ((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource != 0) {
                    gExpgfxTextureFreeInProgress = 1;
                    textureFree((Texture*)((void*)((ExpgfxTableEntry*)((u8*)runtime->expTab +
                                                                       Expgfx_GetSlotTableIndex(slot) * 16))
                                               ->resource));
                    gExpgfxTextureFreeInProgress = 0;
                }

                expTabEntry = (ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16);
                refCountPtr = &expTabEntry->refCount;
                if (*refCountPtr != 0) {
                    (*refCountPtr)--;
                    if (*refCountPtr == 0) {
                        expTabEntry->resource = NULL;
                        expTabEntry->sourceId = 0;
                    }
                } else {
                    debugPrintf(sExpgfxMismatchInAddRemove);
                }

                slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
                *poolActiveMasks &= ~activeBit;
            }

            slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
            slotIndex++;
        }

        *poolActiveCountPtrs = 0;
        *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        DCFlushRange((void*)*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases++;
        poolActiveMasks++;
        poolActiveCountPtrs++;
        poolSlotTypeIds++;
        poolIndex++;
    }
}

void expgfxRemoveAll(void) {
    expgfxRemoveAllBody();
}

static inline void expgfxSetSlotResult(s16* poolIndexOut, s16* slotIndexOut, s16 poolIndex, s16 slotIndex) {
    *slotIndexOut = slotIndex;
    *poolIndexOut = poolIndex;
}

int expgfxGetSlot(short* poolIndexOut, short* slotIndexOut, short slotType, int preferredPoolIndex, u32 sourceId) {
    ExpgfxRuntimeDataLayout* runtime;
    short foundPoolIndex;
    s8* poolActiveCounts;
    int searchIndex;
    short found;
    int slotTypeVal;
    u32* sourceIdWalk;
    s16* poolSlotTypeIds;
    s8* activeCountWalk;
    int batchGroup;
    runtime = EXPGFX_RUNTIME_DATA;
    foundPoolIndex = EXPGFX_INVALID_POOL_INDEX;
    found = 0;
    searchIndex = 0;
    sourceIdWalk = runtime->poolSourceIds;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    poolActiveCounts = runtime->poolActiveCounts;
    activeCountWalk = poolActiveCounts;
    slotTypeVal = slotType;
    for (batchGroup = 0; batchGroup < EXPGFX_POOL_SEARCH_BATCH_COUNT; sourceIdWalk += EXPGFX_POOL_SEARCH_BATCH_SIZE,
        activeCountWalk += EXPGFX_POOL_SEARCH_BATCH_SIZE, poolSlotTypeIds++, searchIndex++, batchGroup++) {
        if ((sourceId == sourceIdWalk[0]) && (slotTypeVal == *poolSlotTypeIds) &&
            (activeCountWalk[0] < EXPGFX_SLOTS_PER_POOL)) {
            foundPoolIndex = searchIndex;
            found = 1;
            break;
        }
        poolSlotTypeIds = (s16*)(poolSlotTypeIds + 1);
        searchIndex++;
        if ((sourceId == sourceIdWalk[1]) && (slotTypeVal == *poolSlotTypeIds) &&
            (activeCountWalk[1] < EXPGFX_SLOTS_PER_POOL)) {
            foundPoolIndex = searchIndex;
            found = 1;
            break;
        }
        poolSlotTypeIds = (s16*)(poolSlotTypeIds + 1);
        searchIndex++;
        if ((sourceId == sourceIdWalk[2]) && (slotTypeVal == *poolSlotTypeIds) &&
            (activeCountWalk[2] < EXPGFX_SLOTS_PER_POOL)) {
            foundPoolIndex = searchIndex;
            found = 1;
            break;
        }
        poolSlotTypeIds = (s16*)(poolSlotTypeIds + 1);
        searchIndex++;
        if ((sourceId == sourceIdWalk[3]) && (slotTypeVal == *poolSlotTypeIds) &&
            (activeCountWalk[3] < EXPGFX_SLOTS_PER_POOL)) {
            foundPoolIndex = searchIndex;
            found = 1;
            break;
        }
        poolSlotTypeIds = (s16*)(poolSlotTypeIds + 1);
        searchIndex++;
        if ((sourceId == sourceIdWalk[4]) && (slotTypeVal == *poolSlotTypeIds) &&
            (activeCountWalk[4] < EXPGFX_SLOTS_PER_POOL)) {
            foundPoolIndex = searchIndex;
            found = 1;
            break;
        }
    }

    if (found) {
        u32 currentMask;
        int slotIndex;
        u32 activeBit;
        u32* activeMaskPtr;
        int chosenPool;

        slotIndex = 0;
        chosenPool = foundPoolIndex;
        activeMaskPtr = EXPGFX_POOL_ACTIVE_MASK_PTR(runtime, chosenPool);
        currentMask = *activeMaskPtr;
        for (; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
            activeBit = 1u << slotIndex;
            if ((activeBit & currentMask) == 0) {
                expgfxSetSlotResult(poolIndexOut, slotIndexOut, foundPoolIndex, slotIndex);
                *activeMaskPtr |= activeBit;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
    }

    found = 0;
    if (preferredPoolIndex == EXPGFX_INVALID_POOL_INDEX) {
        for (searchIndex = 0; searchIndex < EXPGFX_POOL_COUNT - 1; poolActiveCounts++, searchIndex++) {
            if (*poolActiveCounts <= 0) {
                foundPoolIndex = searchIndex;
                found = 1;
                runtime->poolActiveCounts[searchIndex] = 0;
                break;
            }
        }
    } else if (preferredPoolIndex != EXPGFX_INVALID_POOL_INDEX) {
        searchIndex = preferredPoolIndex;
        if (runtime->poolActiveCounts[preferredPoolIndex] < EXPGFX_SLOTS_PER_POOL) {
            foundPoolIndex = preferredPoolIndex;
            found = 1;
        }
    }

    if (found) {
        u32 currentMask;
        u32 activeBit;
        u32* activeMaskPtr;
        int slotIndex;
        int chosenPool;

        slotIndex = 0;
        chosenPool = foundPoolIndex;
        activeMaskPtr = EXPGFX_POOL_ACTIVE_MASK_PTR(runtime, chosenPool);
        currentMask = *activeMaskPtr;
        for (; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
            activeBit = 1u << slotIndex;
            if ((activeBit & currentMask) == 0) {
                expgfxSetSlotResult(poolIndexOut, slotIndexOut, foundPoolIndex, slotIndex);
                *activeMaskPtr |= activeBit;
                gExpgfxStaticPoolSlotTypeIds[searchIndex] = slotType;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
        return EXPGFX_INVALID_POOL_INDEX;
    }

    return EXPGFX_INVALID_POOL_INDEX;
}

void expgfx_initSlotQuad(void* slotPtr) {
    ExpgfxStaticDataLayout* staticData;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* entry;
    ExpgfxQuadVertex* quad;
    Vec3s* quadTemplate;
    void* resource;
    u32 behaviorFlags;
    s16 texT1;
    s16 texT0;
    s16 texS1;
    s16 texS0;
    f32 step;
    slot = (ExpgfxSlot*)slotPtr;
    staticData = EXPGFX_STATIC_DATA;
    entry = gExpgfxTableEntries;
    entry += ((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK;
    resource = entry->resource;

    slot->stateBits.bits.frameParity = 0;
    slot->stateBits.bits.quadReady = 1;

    behaviorFlags = slot->behaviorFlags;
    if ((behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0) {
        quadTemplate = staticData->quadTemplateA;
    } else {
        quadTemplate = staticData->quadTemplateB;
    }

    if ((behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 &&
        slot->velocityY < EXPGFX_Y_VELOCITY_POSITIVE_LIMIT) {
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
            slot->velocityY < EXPGFX_Y_VELOCITY_POSITIVE_LIMIT) {
            slot->velocityY -= EXPGFX_Y_VELOCITY_FAST_STEP * timeDelta;
        } else {
            slot->velocityY -= EXPGFX_Y_VELOCITY_SLOW_STEP * timeDelta;
        }
    } else if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
               slot->velocityY > EXPGFX_Y_VELOCITY_NEGATIVE_LIMIT) {
        slot->velocityY += EXPGFX_Y_VELOCITY_FAST_STEP * timeDelta;
    } else if ((behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
               slot->velocityY > EXPGFX_Y_VELOCITY_NEGATIVE_LIMIT) {
        slot->velocityY += EXPGFX_Y_VELOCITY_SLOW_STEP * timeDelta;
    }

    slot->posX.value += slot->velocityX * (step = EXPGFX_SLOT_MOTION_STEP);
    slot->posY.value += slot->velocityY * step;
    slot->posZ.value += slot->velocityZ * step;

    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0) {
        slot->scaleCurrent = (f32)slot->scaleStep * step + (f32)slot->scaleCurrent;
    } else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
        slot->scaleCurrent = (f32)slot->scaleCurrent - (f32)slot->scaleStep * step;
    }

    if (resource == 0) {
        debugPrintf(staticData->noTextureString);
        return;
    }

    texT0 = 0;
    texT1 = 0;
    texS0 = 0;
    texS1 = 0;
    if (resource != 0) {
        texS0 = EXPGFX_QUAD_TEXCOORD_MAX;
        texT0 = EXPGFX_QUAD_TEXCOORD_MAX;
        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_S) != 0) {
            texS1 = EXPGFX_QUAD_TEXCOORD_MAX;
            texS0 = 0;
        }
        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_T) != 0) {
            texT1 = EXPGFX_QUAD_TEXCOORD_MAX;
            texT0 = 0;
        }
    }

    quad = (ExpgfxQuadVertex*)slot;
    quad[0].x = quadTemplate[0].x;
    quad[0].y = quadTemplate[0].y;
    quad[0].z = quadTemplate[0].z;
    quad[0].texS = texS0;
    quad[0].texT = texT0;
    quad[1].x = quadTemplate[1].x;
    quad[1].y = quadTemplate[1].y;
    quad[1].z = quadTemplate[1].z;
    quad[1].texS = texS1;
    quad[1].texT = texT0;
    quad[2].x = quadTemplate[2].x;
    quad[2].y = quadTemplate[2].y;
    quad[2].z = quadTemplate[2].z;
    quad[2].texS = texS1;
    quad[2].texT = texT1;
    quad[3].x = quadTemplate[3].x;
    quad[3].y = quadTemplate[3].y;
    quad[3].z = quadTemplate[3].z;
    quad[3].texS = texS0;
    quad[3].texT = texT1;
}

void expgfx_updateActivePools(u8 sourceMode, int sourceId, int resetSourceFrameState) {
    ExpgfxBounds* bounds;
    ExpgfxRuntimeDataLayout* runtime;
    int nextActivePool;
    int scanIdx;
    f32* maxXPtr;
    f32* minYPtr;
    f32* maxYPtr;
    f32* minZPtr;
    f32* maxZPtr;
    u32 poolOrResource;
    int sky;
    ExpgfxStaticDataLayout* staticData;
    s16 slotIdx;
    ExpgfxSlot* slot;
    Vec3s* quadTemplate;
    s16 texT1;
    s16 texT0;
    s16 texS1;
    s16 texS0;
    GameObject* player;
    GameObject* tricky;
    u8* nextCacheBuf;
    s8* activeCountScan;
    int curPool;
    u32* maskPtr;
    u8* curPoolBuf;
    ObjAnimComponent* srcObj;
    u8 cacheQueued;
    int ambRPlus1;
    int ambGPlus1;
    int ambBPlus1;
    ExpgfxSlot* curCacheBuf;
    void* cache;
    u8 ambientScaled[3]; /* BGR order: [2]=R, [1]=G, [0]=B */
    ExpgfxRotateParams rotParams;
    f32 workVec[3];
    f32 skyLightDir[3];
    f32 rotatedPos[3];
    f32 srcWorldPos[3];
    u8 ambB8;
    u8 ambG8;
    u8 ambR8;
    f32 boundsMax;
    f32 boundsMin;
    f32 trailPrevX;
    f32 trailPrevY;
    f32 trailPrevZ;
    f32 workB; /* player dist-sq; reused as cross-product lane in the trail block */
    f32 workA; /* tricky dist-sq; reused as cross-product lane in the trail block */
    f32 ambientScale;
    f32 attractRatio; /* attract speed ratio; reused as cross-product Z lane and trail inv-scale */
    f32 trickySpeed;
    f32 playerRange;
    f32 dirX;
    f32 dirY;
    f32 dirZ;
    staticData = EXPGFX_STATIC_DATA;
    runtime = EXPGFX_RUNTIME_DATA;
    attractRatio = 1.0f;
    trickySpeed = 0.0f;
    playerRange = trickySpeed;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    cache = getCache();
    gExpgfxPhaseAngleA += (u16)(120.0f * timeDelta);
    gExpgfxPhaseAngleB += (u16)(480.0f * timeDelta);
    sky = skyGetCurrentLightIndex();
    skyGetSunLightDirection(sky, &skyLightDir[0], &skyLightDir[1], &skyLightDir[2]);
    PSMTXMultVec((void*)Camera_GetViewRotationMatrix(), (void*)skyLightDir, (void*)skyLightDir);
    ambientScale = -skyLightDir[2];
    if (ambientScale < 0.75f) {
        ambientScale = 0.75f;
    }
    skyGetSunColor(sky, &ambR8, &ambG8, &ambB8);
    ambientScaled[2] = (f32)ambR8 * ambientScale;
    ambientScaled[1] = (f32)ambG8 * ambientScale;
    ambientScaled[0] = (f32)ambB8 * ambientScale;

    activeCountScan = runtime->poolActiveCounts;
    for (scanIdx = 0; scanIdx < EXPGFX_POOL_COUNT || (scanIdx = -1, 0); scanIdx++) {
        switch (activeCountScan[scanIdx]) {
        case 0:
            continue;
        }
        break;
    }
    poolOrResource = scanIdx;
    if ((s32)poolOrResource != -1) {
        u8 cacheParity;

        copyToCache(cache, (void*)runtime->slotPoolBases[poolOrResource], EXPGFX_POOL_CACHE_LINE_COUNT);
        cacheParity = 1;
        curCacheBuf = (ExpgfxSlot*)(cache);
        Camera_GetCurrent();
        if (tricky != NULL) {
            trickySpeed = trickyGetSpeed(tricky);
        }
        if (player != NULL) {
            playerRange = playerGetAnimSpeed(player);
        }
        cacheQueued = 0;
        ambRPlus1 = ambientScaled[2] + 1;
        ambGPlus1 = ambientScaled[1] + 1;
        ambBPlus1 = ambientScaled[0] + 1;
        boundsMin = EXPGFX_BOUNDS_INIT_MIN;
        boundsMax = EXPGFX_BOUNDS_INIT_MAX;
        while ((s32)poolOrResource > -1) {
            curPoolBuf = (u8*)runtime + poolOrResource * sizeof(ExpgfxBounds);
            bounds = (ExpgfxBounds*)(curPoolBuf + EXPGFX_POOL_BOUNDS_OFFSET);
            bounds->minX = boundsMin;
            maxXPtr = &bounds->maxX;
            *maxXPtr = boundsMax;
            minYPtr = &bounds->minY;
            *minYPtr = boundsMin;
            maxYPtr = &bounds->maxY;
            *maxYPtr = boundsMax;
            minZPtr = &bounds->minZ;
            *minZPtr = boundsMin;
            maxZPtr = &bounds->maxZ;
            *maxZPtr = boundsMax;
            curPool = poolOrResource;
            scanIdx = curPool + 1;
            curPoolBuf = (u8*)runtime + scanIdx;
            activeCountScan = (s8*)curPoolBuf;
            activeCountScan += EXPGFX_POOL_ACTIVE_COUNTS_OFFSET;
            for (; scanIdx < EXPGFX_POOL_COUNT || (scanIdx = -1, 0); scanIdx++) {
                switch (*activeCountScan) {
                case 0:
                    activeCountScan++;
                    continue;
                }
                break;
            }
            nextActivePool = scanIdx;
            slot = curCacheBuf;
            if (nextActivePool > -1) {
                nextCacheBuf = (u8*)cache + cacheParity * 0x1000;
                copyToCache(nextCacheBuf, (void*)*(u32*)((u8*)runtime->slotPoolBases + nextActivePool * 4),
                            EXPGFX_POOL_CACHE_LINE_COUNT);
                curCacheBuf = (ExpgfxSlot*)(nextCacheBuf);
                cacheQueued = 1;
            }
            cacheParity ^= 1;
            cacheQueueWait(cacheQueued);
            slot--;
            slotIdx = 0;
            maskPtr = (u32*)((u8*)runtime + curPool * 4);
            maskPtr = (u32*)((u8*)maskPtr + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
            curPoolBuf = (u8*)cache + cacheParity * 0x1000;
            for (; slotIdx < EXPGFX_SLOTS_PER_POOL; slotIdx++) {
                ExpgfxQuadVertex* quad;
                ExpgfxTableEntry* entry;
                u32 phase;

                slot++;
                if ((1 << slotIdx & *maskPtr) == 0) {
                    continue;
                }
                if (slot->sequenceId == EXPGFX_INVALID_SEQUENCE_ID) {
                    continue;
                }
                entry = (ExpgfxTableEntry*)((u8*)runtime->expTab +
                                            (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16);
                srcObj = (ObjAnimComponent*)entry->sourceId;
                poolOrResource = (u32)entry->resource;
                slot->stateBits.bits.frameParity = 0;
                slot->stateBits.bits.quadReady = 1;
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_HOLD_LIFETIME_TIMER) == 0) {
                    slot->lifetimeFrame -= framesThisStep;
                }
                phase = slot->stateBits.bits.initPhase;
                if (phase == 2) {
                    slot->stateBits.bits.initPhase = 1;
                    continue;
                }
                if (phase == 1) {
                    expgfxRemove((u32)curPoolBuf, curPool, slotIdx, 0, 0);
                    continue;
                }
                if (slot->lifetimeFrame <= 0 || slot->lifetimeFrame > slot->lifetimeFrameLimit) {
                    slot->stateBits.bits.initPhase = 2;
                    continue;
                }
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0) {
                    quadTemplate = staticData->quadTemplateA;
                } else {
                    quadTemplate = staticData->quadTemplateB;
                }
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                    (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0) {
                    rotParams.x = 0.0f;
                    rotParams.y = 0.0f;
                    rotParams.z = 0.0f;
                    rotParams.scale = 1.0f;
                    rotParams.angleZ = (f32)slot->sourceVecZ * timeDelta;
                    rotParams.angleY = (f32)slot->sourceVecY * timeDelta;
                    rotParams.angleX = (f32)slot->sourceVecX * timeDelta;
                    vecRotateZXY(&rotParams.angleX, &slot->posX.value);
                }
                if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) != 0) {
                    workB = 1000000.0f;
                    workA = workB;
                    if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_PLAYER) != 0 && player != NULL &&
                        srcObj != NULL && playerRange > 0.2f) {
                        workVec[0] = player->anim.worldPosX - (slot->startPosX.value + srcObj->localPosX);
                        workVec[2] = player->anim.worldPosZ - (slot->startPosZ.value + srcObj->localPosZ);
                        workB = workVec[0] * workVec[0] + workVec[2] * workVec[2];
                        attractRatio = playerRange / workB;
                    }
                    if (workB > 300.0f && (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_TRICKY) != 0 &&
                        tricky != NULL && srcObj != NULL && trickySpeed > 0.2f) {
                        workVec[0] = tricky->anim.worldPosX - (slot->startPosX.value + srcObj->localPosX);
                        workVec[2] = tricky->anim.worldPosZ - (slot->startPosZ.value + srcObj->localPosZ);
                        workA = workVec[0] * workVec[0] + workVec[2] * workVec[2];
                        attractRatio = trickySpeed / workB;
                    }
                    if (workA < workB) {
                        workB = workA;
                    }
                    if (workB < 300.0f) {
                        if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_PLAYER) != 0) {
                            slot->renderFlags ^= EXPGFX_RENDER_ATTRACT_TO_PLAYER;
                        }
                        if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_TRICKY) != 0) {
                            slot->renderFlags ^= EXPGFX_RENDER_ATTRACT_TO_TRICKY;
                        }
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED) != 0) {
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED;
                        }
                        slot->lifetimeFrame = randomGetRange(0, 0x28) + 0xdc;
                        slot->lifetimeFrameLimit = randomGetRange(0, 0x28) + 0xdc;
                        slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1;
                        slot->renderFlags |= EXPGFX_RENDER_IMPACT_POSITION_LOCKED;
                        slot->velocityX = -workVec[0] * attractRatio;
                        slot->velocityZ = -workVec[2] * attractRatio;
                    }
                } else {
                    if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_A) != 0) {
                        slot->velocityX += 0.01f * slot->velocityX;
                        slot->velocityY += 0.01f * slot->velocityY;
                        slot->velocityZ += 0.01f * slot->velocityZ;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_B) != 0) {
                        slot->velocityX += 0.02f * slot->velocityX;
                        slot->velocityY += 0.02f * slot->velocityY;
                        slot->velocityZ += 0.02f * slot->velocityZ;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_C) != 0) {
                        slot->velocityX += 0.04f * slot->velocityX;
                        slot->velocityY += 0.04f * slot->velocityY;
                        slot->velocityZ += 0.04f * slot->velocityZ;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_DAMP) != 0) {
                        slot->velocityX = 0.99f * slot->velocityX;
                        slot->velocityY = 0.99f * slot->velocityY;
                        slot->velocityZ = 0.99f * slot->velocityZ;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 &&
                        slot->velocityY < EXPGFX_Y_VELOCITY_POSITIVE_LIMIT) {
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
                            slot->velocityY < EXPGFX_Y_VELOCITY_POSITIVE_LIMIT) {
                            slot->velocityY -= EXPGFX_Y_VELOCITY_FAST_STEP * timeDelta;
                        } else {
                            slot->velocityY -= EXPGFX_Y_VELOCITY_SLOW_STEP * timeDelta;
                        }
                    } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
                               slot->velocityY > EXPGFX_Y_VELOCITY_NEGATIVE_LIMIT) {
                        slot->velocityY += EXPGFX_Y_VELOCITY_FAST_STEP * timeDelta;
                    } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
                               slot->velocityY > EXPGFX_Y_VELOCITY_NEGATIVE_LIMIT) {
                        slot->velocityY += EXPGFX_Y_VELOCITY_SLOW_STEP * timeDelta;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_IMPACT_POSITION_LOCKED) != 0) {
                        if (slot->velocityY * timeDelta + slot->posY.value < 0.0f) {
                            slot->velocityX = 0.0f;
                            slot->velocityY = 0.0f;
                            slot->velocityZ = 0.0f;
                            slot->sourceVecX = 0;
                            slot->sourceVecY = 0;
                            slot->sourceVecZ = 0;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0) {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B;
                            }
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0) {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A;
                            }
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0) {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_FAST_Y_RESPONSE;
                            }
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0) {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY;
                            }
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER) != 0) {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER;
                            }
                            slot->renderFlags ^= EXPGFX_RENDER_IMPACT_POSITION_LOCKED;
                        }
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_MASK) != 0 &&
                        slot->velocityY * timeDelta + slot->posY.value < 0.0f) {
                        u32 rnd;
                        f32 fade;

                        rnd = randomGetRange(0, 5);
                        fade = (f32)(int)rnd;
                        fade = -(0.01f * fade + 0.25f);
                        slot->velocityY *= fade;
                        if (slot->velocityY > 0.3f) {
                            slot->velocityY = 0.3f;
                        }
                        rotParams.scale = 1.0f;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = 0;
                        if (srcObj != NULL) {
                            rotParams.x = slot->posX.value + srcObj->localPosX;
                            rotParams.y = slot->posY.value + srcObj->localPosY;
                            rotParams.z = slot->posZ.value + srcObj->localPosZ;
                        } else {
                            rotParams.x = slot->posX.value + slot->sourcePosX.value;
                            rotParams.y = slot->posY.value + slot->sourcePosY.value;
                            rotParams.z = slot->posZ.value + slot->sourcePosZ.value;
                        }
                        gExpgfxFrameParityBit = 1;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT) != 0 &&
                            (slot->renderFlags & EXPGFX_RENDER_IMPACT_POSITION_LOCKED) == 0) {
                            slot->velocityX *= EXPGFX_SLOT_MOTION_STEP;
                            slot->velocityZ *= EXPGFX_SLOT_MOTION_STEP;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT;
                            if (slot->impactEffectId != -1) {
                                (*gPartfxInterface)
                                    ->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, 0);
                                slot->impactEffectId = -1;
                            }
                        } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1) != 0) {
                            slot->velocityX *= 0.5f;
                            slot->velocityZ *= 0.5f;
                            slot->scaleCurrent *= 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1;
                        } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2) != 0) {
                            slot->velocityX *= 0.5f;
                            slot->velocityZ *= 0.5f;
                            slot->scaleCurrent *= 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1;
                        } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3) != 0) {
                            slot->velocityX *= 0.5f;
                            slot->velocityZ *= 0.5f;
                            slot->scaleCurrent *= 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2;
                            if (slot->impactEffectId != -1) {
                                (*gPartfxInterface)
                                    ->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, 0);
                            }
                            slot->impactEffectId = -1;
                        } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4) != 0) {
                            {
                                f32 v;
                                f32 st;
                                v = slot->velocityX;
                                st = EXPGFX_SLOT_MOTION_STEP;
                                slot->velocityX = v * (st - v);
                                v = slot->velocityZ;
                                slot->velocityZ = v * (st - v);
                            }
                            slot->scaleCurrent *= 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3;
                            if (slot->impactEffectId != -1) {
                                (*gPartfxInterface)
                                    ->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, 0);
                            }
                        }
                        gExpgfxFrameParityBit = 0;
                    } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT) != 0 &&
                               slot->velocityY * timeDelta + slot->posY.value < 0.0f) {
                        if (slot->impactEffectId != -1) {
                            rotParams.scale = 1.0f;
                            rotParams.angleZ = 0;
                            rotParams.angleY = 0;
                            rotParams.angleX = 0;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0) {
                                rotParams.x = slot->posX.value;
                                rotParams.y = 0.0f;
                                rotParams.z = slot->posZ.value;
                            } else if (srcObj != NULL) {
                                rotParams.x = slot->posX.value + srcObj->worldPosX;
                                rotParams.y = srcObj->worldPosY;
                                rotParams.z = slot->posZ.value + srcObj->worldPosZ;
                            } else {
                                rotParams.x = slot->posX.value;
                                rotParams.y = 0.0f;
                                rotParams.z = slot->posZ.value;
                            }
                            gExpgfxFrameParityBit = 1;
                            (*gWaterfxInterface)->spawnRipple(rotParams.x, rotParams.y, rotParams.z, 0, 0.0f, 4);
                            (*gWaterfxInterface)
                                ->spawnSplashBurst(NULL, rotParams.x, rotParams.y, rotParams.z,
                                                   EXPGFX_SLOT_MOTION_STEP);
                            if (srcObj != NULL && coordsToMapCell(srcObj->localPosX, srcObj->localPosZ) == 0x10) {
                                Sfx_PlayFromObject((GameObject*)srcObj, SFXTRIG_blkscrp6);
                            }
                            slot->impactEffectId = -1;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT;
                            slot->lifetimeFrame = 0;
                            gExpgfxFrameParityBit = 0;
                        }
                    } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_MASK) == 0 &&
                               (slot->behaviorFlags & EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT) == 0 &&
                               slot->impactEffectId != -1) {
                        rotParams.scale = 1.0f;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = 0;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0) {
                            rotParams.x = slot->posX.value;
                            rotParams.y = slot->posY.value;
                            rotParams.z = slot->posZ.value;
                        } else if (srcObj != NULL) {
                            rotParams.x = slot->posX.value + srcObj->worldPosX;
                            rotParams.y = slot->posY.value + srcObj->worldPosY;
                            rotParams.z = slot->posZ.value + srcObj->worldPosZ;
                        } else {
                            rotParams.x = slot->posX.value;
                            rotParams.y = slot->posY.value;
                            rotParams.z = slot->posZ.value;
                        }
                        gExpgfxFrameParityBit = 1;
                        (*gPartfxInterface)->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, NULL);
                        gExpgfxFrameParityBit = 0;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER) != 0 && randomGetRange(0, 4) == 1) {
                        slot->velocityX += 0.045f - randomGetRange(0, 9) / 100.0f;
                        slot->velocityZ += 0.045f - randomGetRange(0, 9) / 100.0f;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_RANDOM_VELOCITY_BURST) != 0 && randomGetRange(0, 10) == 1) {
                        if (slot->lifetimeFrameLimit > (f32)slot->lifetimeFrame) {
                            slot->velocityX += 0.0004f * randomGetRange(-800, 800) + 0.02f;
                            slot->velocityY += 0.0004f * randomGetRange(-800, 800) + 0.02f;
                            slot->velocityZ += 0.0004f * randomGetRange(-800, 800) + 0.02f;
                        }
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH) != 0) {
                        if (0.25f * slot->lifetimeFrameLimit > (f32)slot->lifetimeFrame) {
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH;
                            slot->velocityX *= -3.0f;
                            slot->velocityY *= -3.0f;
                            slot->velocityZ *= -3.0f;
                        }
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_STRETCHED_TRAIL) != 0) {
                        trailPrevX = slot->posX.value;
                        trailPrevY = slot->posY.value;
                        trailPrevZ = slot->posZ.value;
                    }
                    slot->posX.value += slot->velocityX * timeDelta;
                    slot->posY.value += slot->velocityY * timeDelta;
                    slot->posZ.value += slot->velocityZ * timeDelta;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0) {
                        slot->scaleCurrent = (f32)slot->scaleStep * timeDelta + (f32)slot->scaleCurrent;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
                        slot->scaleCurrent = slot->scaleCurrent - slot->scaleStep * framesThisStep;
                    }
                }
                quad = (ExpgfxQuadVertex*)slot;
                if (poolOrResource == 0) {
                    debugPrintf(staticData->noTextureString);
                } else {
                    GameObject* attached;

                    texT0 = 0;
                    texT1 = 0;
                    texS0 = 0;
                    texS1 = 0;
                    if (poolOrResource != 0) {
                        texS0 = 0x80;
                        texT0 = 0x80;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_S) != 0) {
                            texS1 = 0x80;
                            texS0 = 0;
                        }
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_T) != 0) {
                            texT1 = 0x80;
                            texT0 = 0;
                        }
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0) {
                        int colR;
                        int colG;
                        int colB;
                        f32 ratio;

                        ratio = (f32)slot->lifetimeFrame / slot->lifetimeFrameLimit;
                        colR = (int)(ratio * (f32)(quad[1].alpha - slot->colorByte0) + slot->colorByte0);
                        colG = (int)(ratio * (f32)(quad[2].alpha - slot->colorByte1) + slot->colorByte1);
                        colB = (int)(ratio * (f32)(quad[3].alpha - slot->colorByte2) + slot->colorByte2);
                        if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_DIRECT) != 0) {
                            quad[0].colorR = (s16)colR * (ambR8 + 1) >> 8;
                            quad[0].colorG = (s16)colG * (ambG8 + 1) >> 8;
                            quad[0].colorB = (s16)colB * (ambB8 + 1) >> 8;
                        } else if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_SCALED) != 0) {
                            quad[0].colorR = (s16)colR * ambRPlus1 >> 8;
                            quad[0].colorG = (s16)colG * ambGPlus1 >> 8;
                            quad[0].colorB = (s16)colB * ambBPlus1 >> 8;
                        } else {
                            quad[0].colorR = colR;
                            quad[0].colorG = colG;
                            quad[0].colorB = colB;
                        }
                    } else if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_DIRECT) != 0) {
                        quad[0].colorR = ambR8;
                        quad[0].colorG = ambG8;
                        quad[0].colorB = ambB8;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_SCALED) != 0) {
                        quad[0].colorR = ambientScaled[2];
                        quad[0].colorG = ambientScaled[1];
                        quad[0].colorB = ambientScaled[0];
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_STRETCHED_TRAIL) != 0) {
                        f32 sx;
                        f32 sy;
                        f32 sz;
                        f32 prevDX;
                        f32 prevDY;
                        f32 prevDZ;
                        f32 normSq;
                        f32 norm;
                        f32 axisX;
                        f32 axisY;
                        f32 axisZ;

                        sx = 0.0f;
                        sy = sx;
                        sz = sx;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) == 0) {
                            if (srcObj != NULL) {
                                sx = srcObj->worldPosX;
                                sy = srcObj->worldPosY;
                                sz = srcObj->worldPosZ;
                            } else {
                                sx = slot->sourcePosX.value;
                                sy = slot->sourcePosY.value;
                                sz = slot->sourcePosZ.value;
                            }
                        }
                        dirX = sx - slot->posX.value;
                        dirY = sy - slot->posY.value;
                        dirZ = sz - slot->posZ.value;
                        prevDX = trailPrevX - slot->posX.value;
                        prevDY = trailPrevY - slot->posY.value;
                        prevDZ = trailPrevZ - slot->posZ.value;
                        workA = dirZ * prevDY - prevDZ * dirY;
                        workB = -(prevDX * dirZ - prevDZ * dirX);
                        attractRatio = dirY * prevDX - prevDY * dirX;
                        normSq = attractRatio * attractRatio + (workA * workA + workB * workB);
                        if (normSq != 0.0f) {
                            norm = sqrtf(normSq);
                        } else {
                            norm = 1.0f;
                        }
                        axisX = 250.0f * (workA / norm);
                        axisY = 250.0f * (workB / norm);
                        axisZ = 250.0f * (attractRatio / norm);
                        attractRatio = 2.0f / (EXPGFX_U16_TO_UNIT_SCALE * (f32)slot->scaleTarget);
                        quad[0].x = (s16)axisX;
                        quad[0].y = (s16)axisY;
                        quad[0].z = (s16)axisZ;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = attractRatio * (slot->posX.value - trailPrevX) + axisX;
                        quad[1].y = attractRatio * (slot->posY.value - trailPrevY) + axisY;
                        quad[1].z = attractRatio * (slot->posZ.value - trailPrevZ) + axisZ;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = attractRatio * (slot->posX.value - trailPrevX) - axisX;
                        quad[2].y = attractRatio * (slot->posY.value - trailPrevY) - axisY;
                        quad[2].z = attractRatio * (slot->posZ.value - trailPrevZ) - axisZ;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = -(s16)axisX;
                        quad[3].y = -(s16)axisY;
                        quad[3].z = -(s16)axisZ;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0 &&
                               (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0) {
                        rotParams.x = 0.0f;
                        rotParams.y = 0.0f;
                        rotParams.z = 0.0f;
                        slot->sourceVecX = slot->sourceVecX + (int)slot->sourcePosX.value * framesThisStep;
                        slot->sourceVecY = slot->sourceVecY + (int)slot->sourcePosY.value * framesThisStep;
                        slot->sourceVecZ = slot->sourceVecZ + (int)slot->sourcePosZ.value * framesThisStep;
                        rotParams.scale = 1.0f;
                        workVec[0] = (f32)quadTemplate[0].x;
                        workVec[1] = (f32)quadTemplate[0].y;
                        workVec[2] = (f32)quadTemplate[0].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[0].x = workVec[0];
                        quad[0].y = workVec[1];
                        quad[0].z = workVec[2];
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        workVec[0] = (f32)quadTemplate[1].x;
                        workVec[1] = (f32)quadTemplate[1].y;
                        workVec[2] = (f32)quadTemplate[1].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[1].x = workVec[0];
                        quad[1].y = workVec[1];
                        quad[1].z = workVec[2];
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        workVec[0] = (f32)quadTemplate[2].x;
                        workVec[1] = (f32)quadTemplate[2].y;
                        workVec[2] = (f32)quadTemplate[2].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[2].x = workVec[0];
                        quad[2].y = workVec[1];
                        quad[2].z = workVec[2];
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        workVec[0] = (f32)quadTemplate[3].x;
                        workVec[1] = (f32)quadTemplate[3].y;
                        workVec[2] = (f32)quadTemplate[3].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[3].x = workVec[0];
                        quad[3].y = workVec[1];
                        quad[3].z = workVec[2];
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0) {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SCALE_Y8) != 0) {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].y <<= 3;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].y <<= 3;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].y <<= 3;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].y <<= 3;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SWAP_XZ_SCALE_Z32) != 0) {
                        quad[0].z = quadTemplate[0].x;
                        quad[0].z <<= 5;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].x = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].z = quadTemplate[1].x;
                        quad[1].z <<= 5;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].x = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].z = quadTemplate[2].x;
                        quad[2].z <<= 5;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].x = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].z = quadTemplate[3].x;
                        quad[3].z <<= 5;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].x = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    } else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SCALE_X32) != 0) {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].x <<= 5;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].x <<= 5;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].x <<= 5;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].x <<= 5;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    } else {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    attached =
                        (GameObject*)((ExpgfxTableEntry*)((u8*)runtime->expTab + (((u32)slot->encodedTableIndex >> 1) &
                                                                                  EXPGFX_SLOT_TABLE_INDEX_MASK) *
                                                                                     16))
                            ->attachedTableKey;
                    rotParams.x = 0.0f;
                    rotParams.y = 0.0f;
                    rotParams.z = 0.0f;
                    rotParams.scale = 1.0f;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0) {
                        rotParams.x = slot->posX.value;
                        rotParams.y = slot->posY.value;
                        rotParams.z = slot->posZ.value;
                    }
                    rotParams.angleZ = 0;
                    rotParams.angleY = 0;
                    rotParams.angleX = 0;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0 &&
                        (slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0) {
                        if (srcObj != NULL) {
                            rotParams.angleX = srcObj->rotX;
                            rotParams.angleY = srcObj->rotY;
                            rotParams.angleZ = srcObj->rotZ;
                        } else {
                            rotParams.angleX = slot->sourceVecX;
                            rotParams.angleY = slot->sourceVecY;
                            rotParams.angleZ = slot->sourceVecZ;
                        }
                    }
                    rotatedPos[0] = slot->posX.value;
                    rotatedPos[1] = slot->posY.value;
                    rotatedPos[2] = slot->posZ.value;
                    if ((rotParams.angleX | rotParams.angleY | rotParams.angleZ) != 0) {
                        vecRotateZXY(&rotParams.angleX, rotatedPos);
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) == 0) {
                        if (srcObj != NULL) {
                            srcWorldPos[0] = srcObj->worldPosX;
                            srcWorldPos[1] = srcObj->worldPosY;
                            srcWorldPos[2] = srcObj->worldPosZ;
                        } else {
                            srcWorldPos[0] = slot->sourcePosX.value;
                            srcWorldPos[1] = slot->sourcePosY.value;
                            srcWorldPos[2] = slot->sourcePosZ.value;
                            if (attached != NULL) {
                                Obj_RotateLocalOffsetByYaw(&slot->sourcePosX.value, srcWorldPos,
                                                           attached->anim.transformMatrixIndex);
                            }
                        }
                    } else {
                        srcWorldPos[0] = 0.0f;
                        srcWorldPos[1] = 0.0f;
                        srcWorldPos[2] = 0.0f;
                    }
                    rotParams.angleZ = 0;
                    rotParams.angleY = 0;
                    rotParams.angleX = 0;
                    rotParams.x = srcWorldPos[0] + rotatedPos[0];
                    rotParams.y = srcWorldPos[1] + rotatedPos[1];
                    rotParams.z = srcWorldPos[2] + rotatedPos[2];
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                        (slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0) {
                        rotParams.x += slot->sourcePosX.value;
                        rotParams.y += slot->sourcePosY.value;
                        rotParams.z += slot->sourcePosZ.value;
                    }
                    slot->renderX = rotParams.x;
                    slot->renderY = rotParams.y;
                    slot->renderZ = rotParams.z;
                    if (rotParams.x < bounds->minX) {
                        bounds->minX = rotParams.x;
                    }
                    if (rotParams.x > *maxXPtr) {
                        *maxXPtr = rotParams.x;
                    }
                    if (rotParams.y < *minYPtr) {
                        *minYPtr = rotParams.y;
                    }
                    if (rotParams.y > *maxYPtr) {
                        *maxYPtr = rotParams.y;
                    }
                    if (rotParams.z < *minZPtr) {
                        *minZPtr = rotParams.z;
                    }
                    if (rotParams.z > *maxZPtr) {
                        *maxZPtr = rotParams.z;
                    }
                }
            }
            memcpyToCache((void*)*(u32*)((u8*)runtime->slotPoolBases + curPool * 4), curPoolBuf,
                          EXPGFX_POOL_CACHE_LINE_COUNT);
            cacheQueued = 1;
            poolOrResource = nextActivePool;
        }
        cacheQueueWait(0);
    }
}

u8 gExpgfxRuntimeData[0x980];

char sExpgfxMismatchInAddRemove[] = "expgfx.c: mismatch in add/remove in exptab\n";

char sExpgfxNoTexture[11] = "notexture \n";

char sExpgfxAddToTableUsageOverflow[] = "expgfx.c: addToTable usage overflow\n";

char sExpgfxExpTabIsFull[] = "expgfx.c: exptab is FULL\n";

char sExpgfxInvalidTabIndex[] = "expgfx.c: invalid tabindex\n";

char sExpgfxScaleOverflow[] = "expgfx.c: scale overflow\n";

int expgfx_addToTable(u32 resourceHandle, u32 sourceId, u32 attachedTableKey, s16 resourceId) {
    ExpgfxTableEntry* entry;
    int tableIndex;
    int freeIndex;

    for (tableIndex = 0; tableIndex < EXPGFX_EXPTAB_ENTRY_COUNT; tableIndex++) {
        entry = &gExpgfxTableEntries[tableIndex];
        if ((entry->refCount != 0) && ((u32)entry->resource == resourceHandle) && (entry->sourceId == sourceId) &&
            (entry->attachedTableKey == attachedTableKey)) {
            if (gExpgfxTableEntries[tableIndex].refCount >= EXPGFX_REFCOUNT_OVERFLOW) {
                debugPrintf(sExpgfxAddToTableUsageOverflow);
                return EXPGFX_INVALID_TABLE_INDEX;
            }
            gExpgfxTableEntries[tableIndex].refCount++;
            return (s16)tableIndex;
        }
    }

    for (freeIndex = 0; freeIndex < EXPGFX_EXPTAB_ENTRY_COUNT; freeIndex++) {
        if (gExpgfxTableEntries[freeIndex].refCount == 0) {
            gExpgfxTableEntries[freeIndex].refCount = 1;
            gExpgfxTableEntries[freeIndex].resource = (void*)resourceHandle;
            gExpgfxTableEntries[freeIndex].sourceId = sourceId;
            gExpgfxTableEntries[freeIndex].attachedTableKey = attachedTableKey;
            gExpgfxTableEntries[freeIndex].resourceId = resourceId;
            return (s16)freeIndex;
        }
    }

    debugPrintf(sExpgfxExpTabIsFull);
    return EXPGFX_INVALID_TABLE_INDEX;
}

int expgfx_updateSourceFrameFlags(void* sourceObject) {
    int result;
    s16 poolIndex;

    result = EXPGFX_SOURCE_FRAME_STATE_NONE;
    lbl_803DD253 = 0;

    for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT; poolIndex++) {
        if ((((ObjAnimComponent*)sourceObject)->romDefNo == EXPGFX_SOURCE_SEQID_MATCH_ALL) ||
            (gExpgfxTrackedPoolSourceIds[poolIndex] == sourceObject)) {
            s64 frameBit;

            frameBit = 1 << (poolIndex >> 1);
            if ((frameBit & gExpgfxTrackedSourceFrameMasks[poolIndex & 1]) != 0) {
                gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_B;
                if ((s8)result == EXPGFX_SOURCE_FRAME_STATE_A) {
                    result = EXPGFX_SOURCE_FRAME_STATE_MIXED;
                } else {
                    result = EXPGFX_SOURCE_FRAME_STATE_B;
                }
            } else {
                gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_A;
                if ((s8)result == EXPGFX_SOURCE_FRAME_STATE_B) {
                    result = EXPGFX_SOURCE_FRAME_STATE_MIXED;
                } else {
                    result = EXPGFX_SOURCE_FRAME_STATE_A;
                }
            }
        } else {
            gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }
    }

    return result;
}

void expgfx_ownerFree3(u32 sourceId) {
    expgfx_free(sourceId);
    return;
}

void expgfx_func0B_nop(void) {
}

void expgfx_func0A_nop(void) {
}

int expgfx_func09(void) {
    return 0;
}

void expgfx_renderSourcePools(int sourceId, int sourceMode) {
    ExpgfxRuntimeDataLayout* runtime;
    ExpgfxPlaneOffsets* planeOffsets;
    s8* poolActiveCounts;
    u32* poolSourceIds;
    u8* poolSourceModes;
    u8* poolPlaneOffsetSetIds;
    ExpgfxBounds* poolBounds;
    u32* slotPoolBases;
    int poolIndex;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSourceIds = runtime->poolSourceIds;
    poolSourceModes = runtime->poolSourceModes;
    poolPlaneOffsetSetIds = runtime->poolPlaneOffsetSetIds;
    poolBounds = runtime->poolBounds;
    slotPoolBases = runtime->slotPoolBases;

    while (poolIndex < EXPGFX_POOL_COUNT) {
        if ((*poolActiveCounts != 0) && (*poolSourceIds == sourceId) &&
            (*poolSourceModes == sourceMode + EXPGFX_POOL_SOURCE_MODE_SOURCE_OFFSET)) {
            planeOffsets = Expgfx_GetPlaneOffsets(*poolPlaneOffsetSetIds);
            if ((u8)frustumTestAabbWithPlaneOffsets(poolBounds->minX - playerMapOffsetX,
                                                    poolBounds->maxX - playerMapOffsetX, poolBounds->minY,
                                                    poolBounds->maxY, poolBounds->minZ - playerMapOffsetZ,
                                                    poolBounds->maxZ - playerMapOffsetZ, planeOffsets->offsets) != 0) {
                drawGlow(*slotPoolBases, poolIndex);
            }
        }
        poolActiveCounts++;
        poolSourceIds++;
        poolSourceModes++;
        poolPlaneOffsetSetIds++;
        poolBounds++;
        slotPoolBases++;
        poolIndex++;
    }
}

void drawGlow(u32 slotPoolBase, int poolIndex) {
    ExpgfxBillboardAngles angles;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* tabBase;
    ExpgfxTableEntry* tabEntry;
    f32 sinB, cosB;
    int slotIndex;
    int alpha;
    ObjAnimComponent* sourceObject;
    u32 stateBitsValue;
    Camera* cameraSlot;
    f32 halfLifeFrames;
    f32 scaleSize;
    f32 centerX, centerY, centerZ;
    f32 scaleFactor;
    Texture* texture;
    MtxPtr viewMatrix;
    f32 sinA, cosA;
    u32 behaviorFlags;
    f32 sinC, cosC;
    f32 worldX, worldY, worldZ;
    f32 px, nx, py, pz, ny;
    Vec aimDelta;
    ExpgfxQuadVertex* quad;
    ExpgfxQuadVertex* vertexStream;
    int vertexIndex;
    f32 viewDepth;
    int hudHiddenFrameCount;
    u32* activeMasks;
    s8 alphaMode;
    s8 blendMode;
    s8 zMode;
    s8 zCompLoc;
    Texture* currentTexture;
    u8 lastOverrideColorFlag;
    ExpgfxSlot* cachedSlots;
    cachedSlots = getCache();
    lastOverrideColorFlag = 0;
    hudHiddenFrameCount = getHudHiddenFrameCount();
    Camera_GetProjectionMatrix();
    copyToCache(cachedSlots, (void*)slotPoolBase, EXPGFX_POOL_CACHE_LINE_COUNT);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCurrentMtx(GX_PNMTX0);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetCullMode(GX_CULL_NONE);
    viewMatrix = (MtxPtr)Camera_GetViewMatrix();
    GXLoadPosMtxImm(viewMatrix, GX_PNMTX0);
    PSMTXCopy(viewMatrix, gCameraModelViewMatrix);
    loadReflectionTexMtxs();
    _gxSetFogParams();
    if ((short)renderModeSetOrGet(EXPGFX_INVALID_SLOT_TYPE) == 1) {
        return;
    }
    cameraSlot = Camera_GetCurrent();
    _textSetColor(0, 0xff, 0xff, 0xff, 0xff);
    alphaMode = -1;
    blendMode = -1;
    zMode = -1;
    zCompLoc = -1;
    currentTexture = 0;
    cacheQueueWait(0);

    slot = cachedSlots - 1;
    slotIndex = 0;
    activeMasks = &gExpgfxSlotActiveMasks[poolIndex];
    tabBase = gExpgfxTableEntries;
    do {
        slot++;
        tabEntry = &tabBase[((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK];
        sourceObject = (ObjAnimComponent*)tabEntry->sourceId;
        texture = tabEntry->resource;
        if ((1U << slotIndex & *activeMasks) != 0) {
            stateBitsValue = slot->stateBits.value;
            if (((stateBitsValue >> 2) & 3) == 0 && ((stateBitsValue >> 1) & 1) != 0 &&
                slot->sequenceId != EXPGFX_INVALID_SEQUENCE_ID && (stateBitsValue & 1) == 0) {
                halfLifeFrames = 0.5f * (f32)slot->lifetimeFrameLimit;
                behaviorFlags = slot->behaviorFlags;
                if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_TO_OPAQUE) != 0) {
                    f32 ratio = (f32)slot->lifetimeFrame / (f32)slot->lifetimeFrameLimit;
                    if (ratio < 0.0f) {
                        ratio = 0.0f;
                    } else if (ratio > 1.0f) {
                        ratio = 1.0f;
                    }
                    {
                        u32 baseAlpha = slot->initialAlpha;
                        alpha = (int)((f32)((s32)baseAlpha - 0xff) * ratio + (f32)baseAlpha);
                    }
                } else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_OUT) != 0) {
                    f32 ratio = (f32)slot->lifetimeFrame / (f32)slot->lifetimeFrameLimit;
                    if (ratio < 0.0f) {
                        ratio = 0.0f;
                    } else if (ratio > 1.0f) {
                        ratio = 1.0f;
                    }
                    alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                } else if ((slot->renderFlags & EXPGFX_RENDER_ALPHA_FADE_IN) != 0 &&
                           (f32)slot->lifetimeFrame <= halfLifeFrames) {
                    f32 ratio = (f32)slot->lifetimeFrame / halfLifeFrames;
                    if (ratio < 0.0f) {
                        ratio = 0.0f;
                    } else if (ratio > 1.0f) {
                        ratio = 1.0f;
                    }
                    alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                } else {
                    u32 pulse = behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_PULSE;
                    if (pulse != 0 && (f32)slot->lifetimeFrame <= halfLifeFrames) {
                        f32 ratio = (f32)slot->lifetimeFrame / halfLifeFrames;
                        if (ratio < 0.0f) {
                            ratio = 0.0f;
                        } else if (ratio > 1.0f) {
                            ratio = 1.0f;
                        }
                        alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                    } else if (pulse != 0) {
                        f32 ratio = (halfLifeFrames - ((f32)slot->lifetimeFrame - halfLifeFrames)) / halfLifeFrames;
                        if (ratio < 0.0f) {
                            ratio = 0.0f;
                        } else if (ratio > 1.0f) {
                            ratio = 1.0f;
                        }
                        alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                    } else {
                        alpha = slot->initialAlpha;
                    }
                }

                angles.pitch = 0;
                angles.yaw = angles.pitch;
                centerX = slot->renderX;
                centerY = slot->renderY;
                centerZ = slot->renderZ;
                scaleSize = EXPGFX_U16_TO_UNIT_SCALE * (f32)(u32)slot->scaleCurrent;
                if ((behaviorFlags & EXPGFX_BEHAVIOR_RANDOMIZE_SCALE) != 0 && hudHiddenFrameCount == 0) {
                    f32 base = 0.5f * scaleSize;
                    f32 rnd = randomGetRange(1, 10);
                    scaleFactor = base + base / rnd;
                } else {
                    scaleFactor = scaleSize;
                }

                {
                    u32 behavior = slot->behaviorFlags;
                    if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0) {
                        angles.pitch = 0;
                        if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_A) != 0) {
                            angles.yaw = angles.pitch;
                        } else if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_USE_PITCH) != 0) {
                            if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_SOURCE_OBJECT) != 0 && sourceObject != NULL) {
                                aimDelta.x = cameraSlot->x - sourceObject->worldPosX;
                                aimDelta.y = cameraSlot->y - sourceObject->worldPosY;
                                aimDelta.z = cameraSlot->z - sourceObject->worldPosZ;
                                PSVECNormalize(&aimDelta, &aimDelta);
                                {
                                    f32 absX = __fabsf(aimDelta.x);
                                    f32 absZ = __fabsf(aimDelta.z);
                                    if (absX > absZ) {
                                        getAngle(absX, aimDelta.y);
                                        angles.pitch = (s16)(getAngle(absX, aimDelta.y) - 0x3800);
                                    } else {
                                        getAngle(absZ, aimDelta.y);
                                        angles.pitch = (s16)(getAngle(absZ, aimDelta.y) - 0x3800);
                                    }
                                    angles.yaw = (s16)getAngle(aimDelta.x, aimDelta.z);
                                }
                            } else {
                                angles.yaw = (s16)(0x10000 - cameraSlot->yaw);
                                angles.pitch = cameraSlot->pitch;
                            }
                        } else {
                            angles.yaw = (s16)(0x10000 - cameraSlot->yaw);
                        }
                    }
                }

                angleToVec2((u16)angles.yaw, &cosA, &sinA);
                angleToVec2((u16)angles.pitch, &cosB, &sinB);
                if ((slot->renderFlags & EXPGFX_RENDER_PHASE_ROTATE_A) != 0) {
                    angleToVec2((u16)(gExpgfxPhaseAngleA + (((u32)slot << 8) & 0xFF00)), &sinC, &cosC);
                } else if ((slot->renderFlags & EXPGFX_RENDER_PHASE_ROTATE_B) != 0) {
                    angleToVec2((u16)(gExpgfxPhaseAngleB + (((u32)slot << 8) & 0xFF00)), &sinC, &cosC);
                }
                if (sourceObject != NULL && (slot->renderFlags & EXPGFX_RENDER_MODULATE_ALPHA_SOURCE) != 0) {
                    alpha = (alpha * sourceObject->alpha) >> 8;
                }

                if (currentTexture != texture) {
                    selectTexture(texture, 0);
                    currentTexture = texture;
                }

                {
                    u32 flags = slot->renderFlags;
                    if ((flags & EXPGFX_RENDER_ALPHA_TEXTURE_SETUP) != 0) {
                        if (alphaMode != 0) {
                            gxTevResetStages();
                            gxTevPassRasStage();
                            gxTevCommitStages();
                            alphaMode = 0;
                        }
                    } else if ((flags & EXPGFX_RENDER_ALT_ALPHA_SETUP) != 0) {
                        if (!(alphaMode == 4 &&
                              ((lastOverrideColorFlag != flags) & EXPGFX_RENDER_OVERRIDE_COLORS) == 0)) {
                            int masked;
                            setupReflectionIndirectTev(flags & EXPGFX_RENDER_OVERRIDE_COLORS);
                            alphaMode = 4;
                            masked = slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS;
                            lastOverrideColorFlag = masked;
                        }
                    } else if (alphaMode != 1) {
                        gxTevResetStages();
                        gxTevTextureTimesRasStage();
                        gxTevCommitStages();
                        alphaMode = 1;
                    }
                }
                if ((slot->renderFlags & EXPGFX_RENDER_DEPTH_BLEND_MODE) != 0) {
                    if (blendMode != 0) {
                        Camera_ApplyFullViewport();
                        gxSetZMode_(1, GX_LEQUAL, 1);
                        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                        gxSetPeControl_ZCompLoc_(0);
                        GXSetAlphaCompare(GX_GREATER, 0xfe, GX_AOP_AND, GX_GREATER, 0xfe);
                        blendMode = 0;
                        zMode = 0;
                        zCompLoc = 0;
                    }
                } else {
                    if (zCompLoc != 1) {
                        gxSetPeControl_ZCompLoc_(1);
                        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                        zCompLoc = 1;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_DEPTH_MODE_OVERRIDE) != 0) {
                        if (zMode != 1) {
                            Camera_ApplyEffectDepthViewport();
                            gxSetZMode_(1, GX_LEQUAL, 0);
                            zMode = 1;
                        }
                    } else if (zMode != 2) {
                        Camera_ApplyFullViewport();
                        gxSetZMode_(1, GX_LEQUAL, 0);
                        zMode = 2;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_BLEND_ADDITIVE) != 0) {
                        if (blendMode != 1) {
                            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
                            blendMode = 1;
                        }
                    } else if (blendMode != 2) {
                        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                        blendMode = 2;
                    }
                }

                centerX -= playerMapOffsetX;
                centerZ -= playerMapOffsetZ;
                quad = (ExpgfxQuadVertex*)slot;
                vertexStream = quad;
                GXBegin(GX_QUADS, GX_VTXFMT4, 4);
                for (vertexIndex = 0; vertexIndex < 4; vertexIndex++) {
                    px = scaleFactor * __OSs16tof32(&vertexStream->x);
                    py = scaleFactor * __OSs16tof32(&vertexStream->y);
                    pz = scaleFactor * __OSs16tof32(&vertexStream->z);
                    if ((slot->renderFlags & (EXPGFX_RENDER_PHASE_ROTATE_A | EXPGFX_RENDER_PHASE_ROTATE_B)) != 0) {
                        nx = px * cosC - py * sinC;
                        ny = px * sinC + py * cosC;
                        worldX = centerX + (nx * sinA + cosA * (ny * cosB) + cosA * (pz * sinB));
                        worldY = centerY + (ny * sinB + (-pz) * cosB);
                        worldZ = centerZ + ((-nx) * cosA + sinA * (ny * cosB) + sinA * (pz * sinB));
                    } else {
                        worldX = centerX + (px * sinA + cosA * (py * cosB) + cosA * (pz * sinB));
                        worldY = centerY + (py * sinB + (-pz) * cosB);
                        worldZ = centerZ + ((-px) * cosA + sinA * (py * cosB) + sinA * (pz * sinB));
                    }
                    viewDepth = viewMatrix[2][0] * worldX + viewMatrix[2][1] * worldY + viewMatrix[2][2] * worldZ +
                                viewMatrix[2][3];
                    if (viewDepth > gExpgfxNearFadeDepth) {
                        alpha = (int)((f32)alpha * ((-viewDepth) - 2.5f) / ((-gExpgfxNearFadeDepth) - 2.5f));
                    }
                    GXWGFifo.f32 = worldX;
                    GXWGFifo.f32 = worldY;
                    GXWGFifo.f32 = worldZ;
                    {
                        u8 colorR;
                        u8 colorG;
                        u8 colorB;
                        colorB = quad->colorB;
                        colorG = quad->colorG;
                        colorR = quad->colorR;
                        GXWGFifo.u8 = colorR;
                        GXWGFifo.u8 = colorG;
                        GXWGFifo.u8 = colorB;
                    }
                    GXWGFifo.u8 = alpha;
                    {
                        s16 texU;
                        s16 texV;
                        texV = vertexStream->texT;
                        texU = vertexStream->texS;
                        GXWGFifo.s16 = texU;
                        GXWGFifo.s16 = texV;
                    }
                    vertexStream++;
                }
            }
        }

        slotIndex++;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);

    if (gExpgfxRenderResetPending != 0) {
        expgfx_updateResourceEntries(0);
        gExpgfxRenderResetPending = 0;
    }
}

static inline void renderParticlesBody(void) {
    float queuePosition[3];
    f32* currentMatrix;
    int poolIndex;
    u32* slotPoolBases;
    ExpgfxRuntimeDataLayout* runtime;
    register s16* poolSlotTypeIds;
    u32* poolSourceIds;
    ExpgfxBounds* poolBounds;
    u8* poolPlaneOffsetSetIds;
    u8* poolSourceModes;
    s8* poolActiveCounts;
    ExpgfxPoolSourcePosition* sourcePosition;
    ExpgfxPlaneOffsets* planeOffsets;

    runtime = EXPGFX_RUNTIME_DATA;
    currentMatrix = Camera_GetViewMatrix();
    poolIndex = 0;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSourceModes = runtime->poolSourceModes;
    poolPlaneOffsetSetIds = runtime->poolPlaneOffsetSetIds;
    poolBounds = runtime->poolBounds;
    poolSourceIds = runtime->poolSourceIds;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    slotPoolBases = runtime->slotPoolBases;
    do {
        if ((*poolActiveCounts != 0) && (*poolSourceModes == EXPGFX_POOL_SOURCE_MODE_STANDALONE)) {
            planeOffsets = Expgfx_GetPlaneOffsets(*poolPlaneOffsetSetIds);
            if ((u8)frustumTestAabbWithPlaneOffsets(
                    (double)(poolBounds->minX - playerMapOffsetX), (double)(poolBounds->maxX - playerMapOffsetX),
                    (double)poolBounds->minY, (double)poolBounds->maxY, (double)(poolBounds->minZ - playerMapOffsetZ),
                    (double)(poolBounds->maxZ - playerMapOffsetZ), planeOffsets->offsets) != 0) {
                sourcePosition = (ExpgfxPoolSourcePosition*)*poolSourceIds;
                if (sourcePosition != (ExpgfxPoolSourcePosition*)0x0) {
                    queuePosition[0] = sourcePosition->x - playerMapOffsetX;
                    queuePosition[1] = sourcePosition->y;
                    queuePosition[2] = sourcePosition->z - playerMapOffsetZ;
                } else {
                    queuePosition[0] = 0.5f * (poolBounds->minX + poolBounds->maxX) - playerMapOffsetX;
                    queuePosition[1] = 0.5f * (poolBounds->minY + poolBounds->maxY);
                    queuePosition[2] = 0.5f * (poolBounds->minZ + poolBounds->maxZ) - playerMapOffsetZ;
                }
                PSMTXMultVec((float (*)[4])currentMatrix, (Vec*)queuePosition, (Vec*)queuePosition);
                if (*poolSourceIds != 0) {
                    queuePosition[2] = queuePosition[2] - (float)(*poolSlotTypeIds & EXPGFX_QUEUE_DEPTH_SLOT_TYPE_MASK);
                }
                lightmap_queueExternalRenderEntry(*slotPoolBases, poolIndex, queuePosition);
            }
        }
        poolActiveCounts += 1;
        poolSourceModes += 1;
        poolPlaneOffsetSetIds += 1;
        poolBounds += 1;
        poolSourceIds += 1;
        poolSlotTypeIds += 1;
        slotPoolBases += 1;
        poolIndex += 1;
    } while (poolIndex < EXPGFX_POOL_COUNT);
    return;
}

void renderParticles(void) {
    renderParticlesBody();
}

void expgfx_free2(u32 sourceId) {
    expgfx_free(sourceId);
    return;
}

void expgfx_free(u32 sourceId) {
    s8* poolActiveCounts[1];
    int slotIndex;
    ExpgfxTableEntry* tableEntry;
    u32* slotPoolBases[1];
    ExpgfxRuntimeDataLayout* runtime;
    u32* poolSourceIds[1];
    int poolIndex;
    ExpgfxSlot* slot;

    runtime = EXPGFX_RUNTIME_DATA;
    if (sourceId == 0) {
        return;
    }

    poolIndex = 0;
    slotPoolBases[0] = runtime->slotPoolBases;
    poolSourceIds[0] = runtime->poolSourceIds;
    poolActiveCounts[0] = runtime->poolActiveCounts;

    while (poolIndex < EXPGFX_POOL_COUNT) {
        slot = (ExpgfxSlot*)*slotPoolBases[0];
        if (sourceId == *poolSourceIds[0]) {
            for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
                if (slot != NULL) {
                    tableEntry =
                        (ExpgfxTableEntry*)((u8*)runtime->expTab +
                                            (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16);
                    if (tableEntry->sourceId == sourceId) {
                        expgfxRemove(*slotPoolBases[0], poolIndex, slotIndex, 0, 1);
                    }
                }
                slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
                if (*poolActiveCounts[0] == 0) {
                    gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
                }
            }
            *poolSourceIds[0] = 0;
            gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }

        slotPoolBases[0]++;
        poolSourceIds[0]++;
        poolActiveCounts[0]++;
        poolIndex++;
    }
}

static inline void expgfx_clearResourceTable(ExpgfxResourceEntry* resourceEntry) {
    int resourceIndex;
    for (resourceIndex = 0; resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT; resourceEntry++, resourceIndex++) {
        gExpgfxTextureFreeInProgress = 1;
        if (resourceEntry->resource != NULL) {
            textureFree((Texture*)(resourceEntry->resource));
        }
        gExpgfxTextureFreeInProgress = 0;
        resourceEntry->resource = NULL;
        resourceEntry->resourceId = 0;
        resourceEntry->evictionScore = 0;
        resourceEntry->reserved = 0;
    }
}

void expgfx_resetAllPools(void) {
    u16* refCountPtr;
    u32* poolActiveMasks[1];
    s8* poolActiveCounts[1];
    s16* poolSlotTypeIds[1];
    u32* poolSourceIds[1];
    u8* poolFrameFlags[1];
    int activeBit;
    int poolIndex;
    ExpgfxResourceEntry* resourceEntry;
    ExpgfxTableEntry* tableEntry;
    ExpgfxStaticDataLayout* staticData;
    u32* slotPoolBases[1];
    ExpgfxRuntimeDataLayout* runtime[1];
    int slotIndex;
    ExpgfxSlot* slot;
    staticData = EXPGFX_STATIC_DATA;
    slotPoolBases[0] = NULL;
    poolActiveMasks[0] = NULL;
    poolActiveCounts[0] = NULL;
    poolSlotTypeIds[0] = NULL;
    poolSourceIds[0] = NULL;
    poolFrameFlags[0] = NULL;
    runtime[0] = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotPoolBases[0] = runtime[0]->slotPoolBases;
    poolActiveMasks[0] = runtime[0]->poolActiveMasks;
    poolActiveCounts[0] = runtime[0]->poolActiveCounts;
    poolSlotTypeIds[0] = staticData->poolSlotTypeIds;
    poolSourceIds[0] = runtime[0]->poolSourceIds;
    poolFrameFlags[0] = staticData->poolFrameFlags;

    while (poolIndex < EXPGFX_POOL_COUNT) {
        slot = (ExpgfxSlot*)*slotPoolBases[0];
        for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
            activeBit = 1 << slotIndex;
            if ((activeBit & *poolActiveMasks[0]) != 0) {
                if (((ExpgfxTableEntry*)((u8*)runtime[0]->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource !=
                    0) {
                    gExpgfxTextureFreeInProgress = 1;
                    textureFree((Texture*)((void*)((ExpgfxTableEntry*)((u8*)runtime[0]->expTab +
                                                                       Expgfx_GetSlotTableIndex(slot) * 16))
                                               ->resource));
                    gExpgfxTextureFreeInProgress = 0;
                }

                tableEntry = (ExpgfxTableEntry*)((u8*)runtime[0]->expTab + Expgfx_GetSlotTableIndex(slot) * 16);
                refCountPtr = &tableEntry->refCount;
                if (*refCountPtr != 0) {
                    (*refCountPtr)--;
                    if (*refCountPtr == 0) {
                        tableEntry->resource = NULL;
                        tableEntry->sourceId = 0;
                    }
                } else {
                    debugPrintf(staticData->mismatchInAddRemoveString);
                }

                slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
                *poolActiveMasks[0] &= ~activeBit;
            }

            slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
        }

        *poolActiveCounts[0] = 0;
        *poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
        *poolSourceIds[0] = 0;
        *poolFrameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        DCFlushRange((void*)*slotPoolBases[0], EXPGFX_POOL_BYTES);

        slotPoolBases[0]++;
        poolActiveMasks[0]++;
        poolActiveCounts[0]++;
        poolSlotTypeIds[0]++;
        poolSourceIds[0]++;
        poolFrameFlags[0]++;
        poolIndex++;
    }

    resourceEntry = runtime[0]->resourceTable;
    {
        expgfx_clearResourceTable(resourceEntry);
    }
}

void expgfx_updateFrameState(int sourceMode, int sourceId) {
    int renderMode;
    int poolIndex;
    f32 frameStep;
    f32 frameValue;

    renderMode = renderModeSetOrGet(EXPGFX_INVALID_SLOT_TYPE);
    if ((short)renderMode != 1) {
        frameValue = gExpgfxFrameTimerA + (frameStep = timeDelta);
        gExpgfxFrameTimerA = frameValue;
        if (frameValue >= 1024.0f) {
            gExpgfxFrameTimerA = 0.0f;
        }
        frameValue = gExpgfxFrameTimerB + frameStep;
        gExpgfxFrameTimerB = frameValue;
        if (frameValue >= 10.0f) {
            gExpgfxFrameTimerB = 0.0f;
        }
        frameValue = gExpgfxFrameTimerC + frameStep;
        gExpgfxFrameTimerC = frameValue;
        if (frameValue >= 1.0f) {
            gExpgfxFrameTimerC = 0.0f;
        }
        gExpgfxUpdatingActivePools = 1;
        expgfx_updateActivePools((u8)sourceMode, sourceId, 0);
        gExpgfxUpdatingActivePools = 0;
        poolIndex = EXPGFX_POOL_COUNT;
        while ((u8)poolIndex > 0) {
            poolIndex--;
            gExpgfxStaticPoolFrameFlags[(u8)poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }
        (*gPartfxInterface)->updateFrameState(0);
        gExpgfxRenderResetPending = 1;
    }
    return;
}

int expgfx_addremove(ExpgfxSpawnConfig* config, int preferredPoolIndex, int slotType, int planeOffsetSetId) {
    u32 behaviorFlags;
    ExpgfxSlot* slot;
    ObjAnimComponent* attachedSource;
    ExpgfxResourceHandle* resourceHandle;
    ExpgfxRuntimeDataLayout* runtime;
    GameObject* playerObj;
    s16 texT1;
    int expTabIndex;
    int attachedTableKey;
    short poolIndex;
    short slotIndex;
    s16 texT0;
    s16 texS1;
    s16 texS0;
    short resourceTableIndex;
    f32 scaleVal;
    u32 sourceModeValue;

    ExpgfxQuadVertex* quadVertices;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotIndex = 0;
    texT1 = 0;
    texT0 = 0;
    texS1 = 0;
    texS0 = 0;
    if (getHudHiddenFrameCount() != 0) {
        return EXPGFX_INVALID_POOL_INDEX;
    }
    if (expgfxGetSlot(&poolIndex, &slotIndex, slotType, preferredPoolIndex, (u32)(int)config->attachedSource) ==
        EXPGFX_INVALID_POOL_INDEX) {
        return EXPGFX_INVALID_POOL_INDEX;
    }
    {
        int poolIdx = poolIndex;

        if (poolIdx < EXPGFX_POOL_COUNT) {
            runtime->poolSourceIds[poolIdx] = (int)config->attachedSource;
        }
        if (poolIdx < EXPGFX_POOL_COUNT && (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) != 0) {
            runtime->trackedSourceFrameMasks[poolIdx & 1] |= (s64)(1 << (poolIdx >> 1));
        } else {
            runtime->trackedSourceFrameMasks[poolIdx & 1] &= (s64) ~(1 << (poolIdx >> 1));
        }
        slot = (ExpgfxSlot*)runtime->slotPoolBases[poolIdx];
        slot += slotIndex;
        quadVertices = (ExpgfxQuadVertex*)slot;
        gExpgfxSequenceCounter++;
        if (gExpgfxSequenceCounter > EXPGFX_SEQUENCE_COUNTER_MAX) {
            gExpgfxSequenceCounter = 0;
        }
        slot->sequenceId = gExpgfxSequenceCounter;
        slot->behaviorFlags = config->behaviorFlags;
        slot->renderFlags = config->renderFlags;
        slot->stateBits.bits.initPhase = 0;

        resourceTableIndex = expgfx_acquireResourceEntry(config->texture.parts.textureId);
        if (resourceTableIndex < 0) {
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        resourceHandle = runtime->resourceTable[resourceTableIndex].resource;
        if (resourceHandle != NULL) {
            if (resourceHandle->refCount >= EXPGFX_REFCOUNT_OVERFLOW) {
                expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
                return EXPGFX_INVALID_POOL_INDEX;
            }
            resourceHandle->refCount++;
            resourceHandle->linkGroup = config->linkGroup;
        } else {
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }

        behaviorFlags = slot->behaviorFlags;
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_S) != 0) {
            texS1 = 0;
            texS0 = 0;
        }
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_T) != 0) {
            texT1 = 0;
            texT0 = 0;
        }

        attachedSource = (ObjAnimComponent*)config->attachedSource;
        attachedTableKey = 0;
        if (attachedSource == NULL) {
            slot->sourcePosX.value = config->sourcePosX.value;
            slot->sourcePosY.value = config->sourcePosY.value;
            slot->sourcePosZ.value = config->sourcePosZ.value;
            slot->sourceScale.value = config->sourceScale.value;
            slot->sourceVecZ = config->sourceVecZ;
            slot->sourceVecY = config->sourceVecY;
            slot->sourceVecX = config->sourceVecX;
        } else if ((behaviorFlags & EXPGFX_BEHAVIOR_COPY_ATTACHED_SOURCE) != 0) {
            slot->sourcePosX.value = attachedSource->worldPosX;
            slot->sourcePosY.value = attachedSource->worldPosY;
            slot->sourcePosZ.value = attachedSource->worldPosZ;
            slot->sourceScale.value = attachedSource->rootMotionScale;
            slot->sourceVecZ = attachedSource->rotZ;
            slot->sourceVecY = attachedSource->rotY;
            slot->sourceVecX = attachedSource->rotX;
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A) != 0 ||
                (slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0) {
                config->velocityX += attachedSource->velocityX;
                config->velocityY += attachedSource->velocityY;
                config->velocityZ += attachedSource->velocityZ;
            }

            if (attachedSource != NULL) {
                attachedTableKey = attachedSource->parentAddress;
            }
            attachedSource = NULL;
        }

        expTabIndex = expgfx_addToTable((u32)resourceHandle, (u32)attachedSource, attachedTableKey,
                                        config->texture.parts.textureId);
        if ((short)expTabIndex == EXPGFX_INVALID_TABLE_INDEX) {
            debugPrintf(sExpgfxInvalidTabIndex);
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        ((struct {
             u8 tableIndex : 7;
             u8 lowBit : 1;
         }*)&slot->encodedTableIndex)
            ->tableIndex = (u8)expTabIndex;

        slot->posX.value = slot->startPosX.value = config->startPosX.value;
        slot->posY.value = slot->startPosY.value = config->startPosY.value;
        slot->posZ.value = slot->startPosZ.value = config->startPosZ.value;
        slot->velocityX = config->velocityX;
        slot->velocityY = config->velocityY;
        slot->velocityZ = config->velocityZ;
        slot->initialAlpha = config->initialAlpha;
        quadVertices[3].pad06 = config->quadVertex3Pad06;
        slot->lifetimeFrame = config->lifetimeFrames;
        slot->lifetimeFrameLimit = config->lifetimeFrames;

        if (config->scale > 1.0f) {
            debugPrintf(sExpgfxScaleOverflow);
        }
        scaleVal = 65535.0f * config->scale;

        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0) {
            slot->scaleCurrent = 0;
            slot->scaleStep = (scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
            slot->scaleTarget = scaleVal;
        } else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
            slot->scaleCurrent = scaleVal;
            slot->scaleStep = (scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
            slot->scaleTarget = scaleVal;
        } else {
            slot->scaleCurrent = scaleVal;
            slot->scaleTarget = slot->scaleCurrent;
            slot->scaleStep = 0;
        }

        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 ||
            (slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_B) != 0) {
            slot->sourcePosX.value = config->sourcePosX.value;
            slot->sourcePosY.value = config->sourcePosY.value;
            slot->sourcePosZ.value = config->sourcePosZ.value;
            slot->sourceScale.value = config->sourceScale.value;
            slot->sourceVecZ = config->sourceVecZ;
            slot->sourceVecY = config->sourceVecY;
            slot->sourceVecX = config->sourceVecX;
        }
        slot->stateBits.bits.frameParity = gExpgfxFrameParityBit;

        if ((slot->renderFlags & EXPGFX_RENDER_BACKDATE_MOTION) != 0) {
            slot->renderFlags ^= EXPGFX_RENDER_BACKDATE_MOTION;
            slot->posX.value = slot->velocityX * (1.5f * (f32)(s32)slot->lifetimeFrame) + slot->posX.value;
            slot->posY.value = slot->velocityY * (1.5f * (f32)(s32)slot->lifetimeFrame) + slot->posY.value;
            slot->posZ.value = slot->velocityZ * (1.5f * (f32)(s32)slot->lifetimeFrame) + slot->posZ.value;
            slot->velocityX *= -1.0f;
            slot->velocityY *= -1.0f;
            slot->velocityZ *= -1.0f;
        }

        if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_ACTOR) != 0) {
            f32 dx;
            f32 dz;
            f32 distSq;
            playerObj = (GameObject*)Obj_GetPlayerObject();
            slot->renderFlags ^= EXPGFX_RENDER_AIM_AT_ACTOR;
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0) {
                dx = playerObj->anim.worldPosX - slot->startPosX.value;
                dz = playerObj->anim.worldPosZ - slot->startPosZ.value;
                distSq = dx * dx + dz * dz;
                if (distSq < 3600.0f && playerObj->anim.velocityX != 0.0f && 0.0f != playerObj->anim.velocityZ) {
                    slot->velocityX = slot->velocityX + dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityY = slot->velocityY + ((30.0f + playerObj->anim.worldPosY) - slot->startPosY.value) /
                                                            (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityZ = slot->velocityZ + (playerObj->anim.worldPosZ - slot->startPosZ.value) /
                                                            (f32)(s32)((int)slot->lifetimeFrame << 1);
                }
            } else {
                dx = playerObj->anim.worldPosX - (slot->startPosX.value + attachedSource->localPosX);
                dz = playerObj->anim.worldPosZ - (slot->startPosZ.value + attachedSource->localPosZ);
                distSq = dx * dx + dz * dz;
                if (distSq < 3600.0f && playerObj->anim.velocityX != 0.0f && 0.0f != playerObj->anim.velocityZ) {
                    slot->velocityX = slot->velocityX - dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityY = slot->velocityY - ((30.0f + playerObj->anim.worldPosY) -
                                                         (slot->startPosY.value + attachedSource->localPosY)) /
                                                            (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityZ = slot->velocityZ - (playerObj->anim.worldPosZ -
                                                         (slot->startPosZ.value + attachedSource->localPosZ)) /
                                                            (f32)(s32)((int)slot->lifetimeFrame << 1);
                }
            }
        }

        if (resourceTableIndex == 1) {
            gExpgfxSlotType1Count += 1;
            gExpgfxSlotType1Average = gExpgfxSlotType1Sum / gExpgfxSlotType1Count;
        }

        slot->colorByte0 = (u8)((int)*(u16*)&config->colorByte0 >> 8);
        slot->colorByte1 = (u8)((int)*(u16*)&config->colorByte1 >> 8);
        slot->colorByte2 = (u8)((int)*(u16*)&config->colorByte2 >> 8);

        if ((config->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0) {
            quadVertices[1].alpha = (u8)((int)config->overrideColor0 >> 8);
            quadVertices[2].alpha = (u8)((int)config->overrideColor1 >> 8);
            quadVertices[3].alpha = (u8)((int)config->overrideColor2 >> 8);
        }

        quadVertices[0].colorR = 0xff;
        quadVertices[0].colorG = 0xff;
        quadVertices[0].colorB = 0xff;

        quadVertices[0].texS = texS0;
        quadVertices[0].texT = texT0;
        quadVertices[1].texS = texS1;
        quadVertices[1].texT = texT0;
        quadVertices[2].texS = texS1;
        quadVertices[2].texT = texT1;
        quadVertices[3].texS = texS0;
        quadVertices[3].texT = texT1;

        if ((slot->renderFlags & EXPGFX_RENDER_INIT_QUAD) != 0) {
            expgfx_initSlotQuad(slot);
        }

        {
            int modePoolIndex;

            if ((config->behaviorFlags & EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG) != 0) {
                sourceModeValue = 1;
            } else {
                sourceModeValue = 0;
            }
            sourceModeValue = (u8)sourceModeValue;
            modePoolIndex = poolIndex;
            runtime->poolSourceModes[modePoolIndex] = sourceModeValue;
            if (runtime->poolSourceModes[modePoolIndex] != 0 &&
                (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) == 0) {
                runtime->poolSourceModes[modePoolIndex]++;
            }
            runtime->poolPlaneOffsetSetIds[modePoolIndex] = (u8)planeOffsetSetId;
        }

        DCFlushRange(slot, EXPGFX_SLOT_SIZE);
        gExpgfxLastAddedSlot = (int)slot;
        return slot->sequenceId;
    }
}

void expgfx_onMapSetup(void) {
    ExpgfxRuntimeDataLayout* runtime[1];
    ExpgfxResourceEntry* resourceEntry;
    s64* trackedFrameMasks;
    u32* poolActiveMasks[1];
    s8* poolActiveCounts[1];
    s16* poolSlotTypeIds[1];
    u8* poolFrameFlags[1];
    u8* poolSourceModes;
    u32* poolSourceIds;
    int poolIndex;

    runtime[0] = EXPGFX_RUNTIME_DATA;
    expgfxRemoveAll();

    poolActiveMasks[0] = runtime[0]->poolActiveMasks;
    poolActiveCounts[0] = runtime[0]->poolActiveCounts;
    poolSlotTypeIds[0] = gExpgfxStaticPoolSlotTypeIds;
    poolFrameFlags[0] = gExpgfxStaticPoolFrameFlags;
    poolSourceModes = runtime[0]->poolSourceModes;
    poolSourceIds = runtime[0]->poolSourceIds;

    for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT; poolIndex++) {
        *poolActiveMasks[0] = 0;
        *poolActiveCounts[0] = 0;
        *poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
        *poolFrameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        *poolSourceModes = EXPGFX_POOL_SOURCE_MODE_STANDALONE;
        *poolSourceIds = 0;

        poolActiveMasks[0]++;
        poolActiveCounts[0]++;
        poolSlotTypeIds[0]++;
        poolFrameFlags[0]++;
        poolSourceModes++;
        poolSourceIds++;
    }

    trackedFrameMasks = runtime[0]->trackedSourceFrameMasks;
    trackedFrameMasks[0] = 0;
    trackedFrameMasks[1] = 0;

    gExpgfxTextureFreeInProgress = 1;
    poolIndex = 0;
    resourceEntry = runtime[0]->resourceTable;
    while (poolIndex < EXPGFX_RESOURCE_TABLE_COUNT) {
        if (resourceEntry->resource != NULL) {
            textureFree((Texture*)(resourceEntry->resource));
        }
        resourceEntry->resource = NULL;
        resourceEntry->resourceId = 0;
        resourceEntry->evictionScore = 0;
        resourceEntry->reserved = 0;
        resourceEntry++;
        poolIndex++;
    }
    gExpgfxTextureFreeInProgress = 0;
}

void expgfx_release(void) {
    int poolIndex;

    expgfxRemoveAll();
    poolIndex = 0;
    do {
        mm_free((void*)gExpgfxSlotPoolBases[poolIndex]);
        poolIndex += 1;
    } while (poolIndex < EXPGFX_POOL_COUNT);
    return;
}

void expgfx_initialise(void) {
    ExpgfxRuntimeDataLayout* runtime;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    s16* poolSlotTypeIds[1];
    u32* slotPoolBases[1];
    int poolIndex[1];
    int groupCount;

    runtime = EXPGFX_RUNTIME_DATA;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCounts = runtime->poolActiveCounts;
    slotPoolBases[0] = NULL;
    poolSlotTypeIds[0] = gExpgfxStaticPoolSlotTypeIds;
    for (groupCount = EXPGFX_POOL_GROUP_COUNT; groupCount != 0; groupCount--) {
        poolIndex[0] = 0;
        *poolActiveMasks = poolIndex[0];
        *poolActiveCounts = poolIndex[0];
        *poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[1] = poolIndex[0];
        poolActiveCounts[1] = poolIndex[0];
        poolSlotTypeIds[0][1] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[2] = poolIndex[0];
        poolActiveCounts[2] = poolIndex[0];
        poolSlotTypeIds[0][2] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[3] = poolIndex[0];
        poolActiveCounts[3] = poolIndex[0];
        poolSlotTypeIds[0][3] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[4] = poolIndex[0];
        poolActiveCounts[4] = poolIndex[0];
        poolSlotTypeIds[0][4] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[5] = poolIndex[0];
        poolActiveCounts[5] = poolIndex[0];
        poolSlotTypeIds[0][5] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[6] = poolIndex[0];
        poolActiveCounts[6] = poolIndex[0];
        poolSlotTypeIds[0][6] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[7] = poolIndex[0];
        poolActiveCounts[7] = poolIndex[0];
        poolSlotTypeIds[0][7] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks += 8;
        poolActiveCounts += 8;
        poolSlotTypeIds[0] += 8;
    }

    slotPoolBases[0] = runtime->slotPoolBases;
    do {
        *slotPoolBases[0] = (u32)mmAlloc(EXPGFX_POOL_BYTES, EXPGFX_POOL_ALLOC_HEAP, 0);
        memset((void*)*slotPoolBases[0], 0, EXPGFX_POOL_BYTES);
        DCFlushRange((void*)*slotPoolBases[0], EXPGFX_POOL_BYTES);
        slotPoolBases[0]++;
        poolIndex[0]++;
    } while (poolIndex[0] < EXPGFX_POOL_COUNT);
    memset(runtime->expTab, 0, EXPGFX_EXPTAB_BYTES);
    return;
}

u32 gExpgfxSlotPoolBases[0x50];
u32 gExpgfxSlotActiveMasks[0x50];
u64 gExpgfxTrackedSourceFrameMasks[0xB0 / sizeof(u64)];
ObjAnimComponent* gExpgfxTrackedPoolSourceIds[0x50];
ExpgfxTableEntry gExpgfxTableEntries[0x550 / sizeof(ExpgfxTableEntry)];
