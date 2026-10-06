/*
 * SB_MiniFire (DLL 0x1F3) - the small fire/spark projectile spawned during
 * the ShipBattle (SB) set. At init it picks a randomised launch velocity,
 * a cycling resource variant (gSbMiniFireResourceVariant, 1..3) and plays
 * its spawn sfx. Each tick it integrates its position, spins, spawns three
 * partfx bursts (a base puff, a velocity-aligned trail and a scaled trail),
 * fades out over its final frames and frees itself when its lifetime
 * (userData1) expires.
 */
#include "dlls/objects/499_SB_MiniFire.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0075_modgfx.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/rcp_dolphin_api.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

int gSbMiniFireResourceVariant = 1;

#define SB_MINIFIRE_PARTFX_ID            0xA0
#define SB_MINIFIRE_PARTFX_MODE          1
#define SB_MINIFIRE_PARTFX_MODEL_NONE    -1
#define SB_MINIFIRE_RENDER_FLAGS         8
#define SB_MINIFIRE_RESOURCE_ID          117
#define SB_MINIFIRE_RESOURCE_SPAWN_FLAGS 0x10002
#define SB_MINIFIRE_VARIANT_FIRST        1
#define SB_MINIFIRE_VARIANT_LAST         3
#define SB_MINIFIRE_LIFETIME             180
#define SB_MINIFIRE_FADE_FRAMES          60
#define SB_MINIFIRE_ROT_X_STEP           0x374
#define SB_MINIFIRE_ROT_Y_STEP           0x12C

int SB_MiniFire_getExtraSize(void) {
    return sizeof(SBMiniFireState);
}

int SB_MiniFire_getObjectTypeId(void) {
    return 0;
}

void SB_MiniFire_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2(obj);
    (*gModgfxInterface)->detachSource(obj);
}

void SB_MiniFire_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        Rcp_SetRenderFlags(SB_MINIFIRE_RENDER_FLAGS);
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        Rcp_ClearRenderFlags(SB_MINIFIRE_RENDER_FLAGS);
    }
}

void SB_MiniFire_hitDetect(void) {
}

void SB_MiniFire_update(GameObject* obj) {
    PartFxSpawnParams effect;
    f32 dx;
    f32 dy;
    f32 dz;
    obj->anim.localPosX += obj->anim.velocityX * timeDelta;
    obj->anim.localPosY += obj->anim.velocityY * timeDelta;
    obj->anim.localPosZ += obj->anim.velocityZ * timeDelta;
    effect.posX = 0.0f;
    effect.posY = 0.0f;
    effect.posZ = 0.0f;
    effect.scale = 1.0f;
    if (obj->userData1 <= SB_MINIFIRE_FADE_FRAMES) {
        effect.scale = obj->userData1 / 60.0f;
        obj->anim.alpha = (u8)(int)(255.0f * ((f32)obj->userData1 / 60.0f));
    }
    /* Retail leaves the packet's fourth header halfword uninitialised. */
    effect.rotZ = 0;
    effect.rotY = 0;
    effect.rotX = 0;
    (*gPartfxInterface)
        ->spawnEffect(obj, SB_MINIFIRE_PARTFX_ID, &effect, SB_MINIFIRE_PARTFX_MODE, SB_MINIFIRE_PARTFX_MODEL_NONE,
                      NULL);
    dy = obj->anim.localPosY - obj->anim.previousLocalPosY;
    dz = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
    dx = obj->anim.localPosX - obj->anim.previousLocalPosX;
    effect.posX = dx / 3.0f;
    effect.posY = dy / 3.0f;
    effect.posZ = dz / 3.0f;
    (*gPartfxInterface)
        ->spawnEffect(obj, SB_MINIFIRE_PARTFX_ID, &effect, SB_MINIFIRE_PARTFX_MODE, SB_MINIFIRE_PARTFX_MODEL_NONE,
                      NULL);
    effect.posX *= 2.0f;
    effect.posY *= 2.0f;
    effect.posZ *= 2.0f;
    (*gPartfxInterface)
        ->spawnEffect(obj, SB_MINIFIRE_PARTFX_ID, &effect, SB_MINIFIRE_PARTFX_MODE, SB_MINIFIRE_PARTFX_MODEL_NONE,
                      NULL);
    obj->anim.rotX += framesThisStep * SB_MINIFIRE_ROT_X_STEP;
    obj->anim.rotY += framesThisStep * SB_MINIFIRE_ROT_Y_STEP;
    obj->userData1 -= framesThisStep;
    if (obj->userData1 < 0) {
        Obj_FreeObject(obj);
    }
}

void SB_MiniFire_init(GameObject* obj) {
    Dll75Interface** resource;

    obj->userData1 = SB_MINIFIRE_LIFETIME;
    obj->anim.velocityX = -(0.01f * (f32)(s32)randomGetRange(20, 40) + 0.8f);
    obj->anim.velocityY = 0.0f;
    obj->anim.velocityZ = -0.3f;
    obj->anim.rootMotionScale *= 0.8f;

    resource = Resource_Acquire(SB_MINIFIRE_RESOURCE_ID, 1);
    (*resource)->spawn(obj, gSbMiniFireResourceVariant, NULL, SB_MINIFIRE_RESOURCE_SPAWN_FLAGS, -1, NULL);
    gSbMiniFireResourceVariant++;
    if (gSbMiniFireResourceVariant > SB_MINIFIRE_VARIANT_LAST) {
        gSbMiniFireResourceVariant = SB_MINIFIRE_VARIANT_FIRST;
    }
    Resource_Release(resource);
    Sfx_PlayFromObject(obj, SFXTRIG_en_trpopn_c_35);
    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_2ca);
}

void SB_MiniFire_release(void) {
}

void SB_MiniFire_initialise(void) {
}

ObjectDescriptor gSB_MiniFireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_MiniFire_initialise,
    SB_MiniFire_release,
    0,
    (ObjectDescriptorCallback)SB_MiniFire_init,
    (ObjectDescriptorCallback)SB_MiniFire_update,
    SB_MiniFire_hitDetect,
    (ObjectDescriptorCallback)SB_MiniFire_render,
    (ObjectDescriptorCallback)SB_MiniFire_free,
    (ObjectDescriptorCallback)SB_MiniFire_getObjectTypeId,
    SB_MiniFire_getExtraSize,
};
