/*
 * Shield object family (DLL slot 229 / 0xE5).
 *
 * The shield (romDefNo 0x836 uses mode 5, otherwise mode 7) is a four-segment
 * ring driven by Shield_setMode. Each mode sets the per-segment fade/scale
 * targets in ShieldState, drives a point light (modelLightStruct_*) and the
 * 0x42C/0x42D loop sfx, and seeds the fsin16 wobble for the four segments.
 * Shield_update advances the fade toward its target, modulates alpha from a
 * random flicker, and updates the segment cosine; Shield_render re-renders
 * the four segments with per-segment rotation and (off-HUD) spawns particle
 * fx 2028 at the staff tips.
 *
 * Shield_setMode is also used by the staff object. Its per-segment scale
 * table and switch table are owned by this TU.
 */
#include "dlls/objects/229_Shield.h"
#include "main/audio/sfx_object_volume_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/player_objects.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/trig.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "dlls/objects/226.h"
#include "main/hud_visibility_api.h"

#define SHIELD_NORMAL_WAVE_SCALE 0.5f
#define SHIELD_SFX_VOLUME_SCALE  0.5f
#define SHIELD_ZERO              0.0f
#define SHIELD_PARTICLE_OFFSET_X 6.0f
#define SHIELD_PARTICLE_OFFSET_Y -10.0f
#define SHIELD_SFX_VOLUME_MAX    127.0f
#define SHIELD_OMNI_WAVE_SCALE   0.25f

/* anim.romDefNo of the omni_shield variant (retail OBJECTS.bin name; DLL 0xE5
 * also hosts 0x773 "fox_shield"); this variant uses staff-mode 5, otherwise
 * mode 7. */
#define SHIELD_SEQID_OMNI_SHIELD 0x836
/* shield-ring particle spawned around the object in the deflect loop */
#define SHIELD_PARTICLE_ID                2028
#define SHIELD_PARTICLE_COUNT_PER_SEGMENT 2
#define SHIELD_PARTICLE_FLAGS             0x200001
#define SHIELD_SEGMENT_FLAG_HIDDEN        0x1
#define SHIELD_SEGMENT_HALF_TURN          32767
#define SHIELD_SEGMENT_RATE_RANDOM_MIN    120
#define SHIELD_SEGMENT_RATE_RANDOM_MAX    127
#define SHIELD_SEGMENT_RATE_BASE          136.0f
#define SHIELD_SPAWN_SETUP_SIZE           0x24

#define SHIELD_STAFF_GLOW_SLOT     7
#define SHIELD_STAFF_GLOW_DISABLED 0
#define SHIELD_STAFF_GLOW_ENABLED  8

#define SHIELD_SCALE_TABLE_OFFSET      0
#define SHIELD_ALPHA_TABLE_OFFSET      4
#define SHIELD_OMNI_SCALE_TABLE_OFFSET 8
#define SHIELD_OMNI_ALPHA_TABLE_OFFSET 12

#define SHIELD_SEGMENT_ALPHA_F32_INDEX (offsetof(ShieldState, segmentAlpha) / sizeof(f32))
#define SHIELD_SEGMENT_SCALE_F32_INDEX (offsetof(ShieldState, segmentScale) / sizeof(f32))
#define SHIELD_SEGMENT_PHASE_S16_INDEX (offsetof(ShieldState, segmentPhase) / sizeof(s16))
#define SHIELD_SEGMENT_RATE_S16_INDEX  (offsetof(ShieldState, segmentRate) / sizeof(s16))

s16 gShieldRotXRates[SHIELD_SEGMENT_COUNT] = {-1024, -512, 512, 1024};
s16 gOmniShieldRotXRates[SHIELD_SEGMENT_COUNT] = {-500, 50, 50, 200};
s16 gOmniShieldRotYRates[SHIELD_SEGMENT_COUNT] = {50, -512, 50, 100};
s16 gOmniShieldRotZRates[SHIELD_SEGMENT_COUNT] = {50, 50, 512, 512};

f32 gShieldSegmentTable[SHIELD_SEGMENT_TABLE_COUNT] = {
    0.5f, 0.55f, 0.65f, 0.7f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.3f, 0.3f, 0.3f, 0.3f,
};

ObjectDescriptor gShieldObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Shield_initialise,
    (ObjectDescriptorCallback)Shield_release,
    0,
    (ObjectDescriptorCallback)Shield_init,
    (ObjectDescriptorCallback)Shield_update,
    (ObjectDescriptorCallback)Shield_hitDetect,
    (ObjectDescriptorCallback)Shield_render,
    (ObjectDescriptorCallback)Shield_free,
    (ObjectDescriptorCallback)Shield_getObjectTypeId,
    Shield_getExtraSize,
};

GameObject* Shield_spawnOmniShield(GameObject* obj, f32 rootMotionScale) {
    ObjPlacement* setup;
    GameObject* shield;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return NULL;
    }
    setup = Obj_AllocObjectSetup(SHIELD_SPAWN_SETUP_SIZE, SHIELD_SEQID_OMNI_SHIELD);
    setup->posX = obj->anim.worldPosX;
    setup->posY = obj->anim.worldPosY;
    setup->posZ = obj->anim.worldPosZ;
    setup->color[0] = 1;
    setup->color[1] = 1;
    setup->color[3] = 255;
    shield = objSetupObject(setup, 5, -1, -1, 0);
    if (shield != NULL) {
        shield->anim.rootMotionScale = rootMotionScale;
    }
    return shield;
}

void Shield_setMode(GameObject* obj, u8 mode) {
    f32* tableCursor[1];
    ShieldState* state;
    void* stateData;
    GameObject* player;
    GameObject* staff;
    tableCursor[0] = gShieldSegmentTable + SHIELD_SCALE_TABLE_OFFSET;
    state = obj->extra;
    stateData = state;
    player = Obj_GetPlayerObject();
    staff = NULL;
    if (player != NULL) {
        staff = Player_GetStaffObject(player);
    }
    switch (mode) {
    case SHIELD_MODE_INIT_STANDARD:
        if (staff != NULL) {
            staffSetGlow(staff, SHIELD_STAFF_GLOW_SLOT, SHIELD_STAFF_GLOW_DISABLED);
        }
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
        }
        {
            f32 fade = 0.0f;
            state->fadeTarget = fade;
            state->fadeRate = fade;
            state->fadeMax = fade;
            state->fadeValue = fade;
        }
        state->segmentFlags[0] |= SHIELD_SEGMENT_FLAG_HIDDEN;
        state->segmentFlags[1] |= SHIELD_SEGMENT_FLAG_HIDDEN;
        state->segmentFlags[2] |= SHIELD_SEGMENT_FLAG_HIDDEN;
        state->segmentFlags[3] |= SHIELD_SEGMENT_FLAG_HIDDEN;
        break;
    case SHIELD_MODE_STANDARD_FADE_OUT_SHORT:
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
        }
        if (state->fadeTarget != 0.0f) {
            f32 fade = 2.0f;
            state->fadeMax = fade;
            state->fadeValue = fade;
            if (staff != NULL) {
                staffSetGlow(staff, SHIELD_STAFF_GLOW_SLOT, SHIELD_STAFF_GLOW_DISABLED);
            }
        }
        state->fadeTarget = 0.0f;
        state->fadeRate = -1.0f;
        Sfx_StopFromObject(obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject(obj, SFXTRIG_lockon3_on);
        break;
    case SHIELD_MODE_STANDARD_FADE_IN_SHORT:
        if (state->fadeTarget == 0.0f) {
            if (staff != NULL) {
                staffSetGlow(staff, SHIELD_STAFF_GLOW_SLOT, SHIELD_STAFF_GLOW_ENABLED);
            }
            if (state->light == NULL) {
                state->light = objCreateLight(NULL, 1);
            }
            if (state->light != NULL) {
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(state->light, obj->anim.localPosX, obj->anim.localPosY - 15.0f,
                                             obj->anim.localPosZ);
                modelLightStruct_setDiffuseColor(state->light, 0, 255, 255, 255);
                modelLightStruct_setSpecularColor(state->light, 0, 255, 255, 255);
                modelLightStruct_setDistanceAttenuation(state->light, 40.0f, 55.0f);
                lightSetField4D(state->light, 1);
                modelLightStruct_setEnabled(state->light, 1, 0.0f);
                modelLightStruct_startColorFade(state->light, 0, 0);
                modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
            }
            {
                f32 fade = 0.0f;
                if (fade == state->fadeTarget) {
                    state->fadeMax = 2.0f;
                    state->fadeValue = fade;
                }
            }
            state->fadeTarget = 2.0f;
            {
                f32 amp;
                f32 k;
                s16* phaseCursor;
                f32* valueCursor;
                f32* segmentAlphaCursor;
                int i;
                amp = 1.0f;
                state->fadeRate = amp;
                i = 0;
                phaseCursor = stateData;
                valueCursor = stateData;
                segmentAlphaCursor = tableCursor[0] + SHIELD_ALPHA_TABLE_OFFSET;
                k = 0.5f;
                for (; i < SHIELD_SEGMENT_COUNT; i++) {
                    f32 wave;
                    f32 sum;
                    phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX] = -0x4000;
                    wave = fsin16((u16)phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX]);
                    sum = amp + wave;
                    wave = sum * k;
                    valueCursor[SHIELD_SEGMENT_SCALE_F32_INDEX] = *tableCursor[0] * wave;
                    valueCursor[SHIELD_SEGMENT_ALPHA_F32_INDEX] = *segmentAlphaCursor;
                    phaseCursor[SHIELD_SEGMENT_RATE_S16_INDEX] =
                        (s16)((f32)(i * randomGetRange(SHIELD_SEGMENT_RATE_RANDOM_MIN,
                                                            SHIELD_SEGMENT_RATE_RANDOM_MAX)) +
                              SHIELD_SEGMENT_RATE_BASE);
                    phaseCursor += 1;
                    tableCursor[0] += 1;
                    valueCursor += 1;
                    segmentAlphaCursor += 1;
                }
            }
            Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
            Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        }
        break;
    case SHIELD_MODE_STANDARD_FADE_OUT_LONG:
        if (staff != NULL) {
            staffSetGlow(staff, SHIELD_STAFF_GLOW_SLOT, SHIELD_STAFF_GLOW_DISABLED);
        }
        if (state->fadeTarget != 0.0f) {
            state->fadeMax = 60.0f;
        }
        state->fadeTarget = 0.0f;
        state->fadeRate = -1.0f;
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
        }
        Sfx_StopFromObject(obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject(obj, SFXTRIG_lockon3_on);
        break;
    case SHIELD_MODE_STANDARD_FADE_IN_LONG:
        if (staff != NULL) {
            staffSetGlow(staff, SHIELD_STAFF_GLOW_SLOT, SHIELD_STAFF_GLOW_ENABLED);
        }
        if (state->light == NULL) {
            state->light = objCreateLight(NULL, 1);
        }
        if (state->light != NULL) {
            modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(state->light, obj->anim.localPosX, obj->anim.localPosY - 15.0f,
                                         obj->anim.localPosZ);
            modelLightStruct_setDiffuseColor(state->light, 0, 255, 255, 255);
            modelLightStruct_setSpecularColor(state->light, 0, 255, 255, 255);
            modelLightStruct_setDistanceAttenuation(state->light, 40.0f, 55.0f);
            lightSetField4D(state->light, 1);
            modelLightStruct_setEnabled(state->light, 1, 0.0f);
            modelLightStruct_startColorFade(state->light, 0, 0);
            modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
        }
        if (state->fadeTarget == 0.0f) {
            state->fadeMax = 60.0f;
        }
        state->fadeTarget = 60.0f;
        {
            int i;
            s16* phaseCursor;
            f32* valueCursor;
            f32* segmentAlphaCursor;
            f32 k;
            f32 amp;
            amp = 1.0f;
            state->fadeRate = amp;
            i = 0;
            phaseCursor = stateData;
            valueCursor = stateData;
            segmentAlphaCursor = tableCursor[0] + SHIELD_ALPHA_TABLE_OFFSET;
            k = 0.5f;
            for (; i < SHIELD_SEGMENT_COUNT; i++) {
                f32 wave;
                f32 sum;
                phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX] = 0;
                wave = fsin16((u16)phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX]);
                sum = amp + wave;
                wave = sum * k;
                valueCursor[SHIELD_SEGMENT_SCALE_F32_INDEX] = *tableCursor[0] * wave;
                valueCursor[SHIELD_SEGMENT_ALPHA_F32_INDEX] = *segmentAlphaCursor;
                phaseCursor += 1;
                tableCursor[0] += 1;
                valueCursor += 1;
                segmentAlphaCursor += 1;
            }
        }
        Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
        break;
    case SHIELD_MODE_INIT_OMNI:
        state->fadeTarget = 0.0f;
        state->fadeRate = -1.0f;
        state->fadeMax = 60.0f;
        Sfx_StopFromObject(obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject(obj, SFXTRIG_lockon3_on);
        break;
    case SHIELD_MODE_OMNI_ACTIVE: {
        f32 fade = 60.0f;
        f32 amp;
        state->fadeTarget = fade;
        amp = 1.0f;
        state->fadeRate = amp;
        state->fadeMax = fade;
        {
            int i;
            s16* phaseCursor;
            f32* segmentScaleCursor;
            f32* valueCursor;
            f32* segmentAlphaCursor;
            f32 k;
            i = 0;
            phaseCursor = stateData;
            segmentScaleCursor = tableCursor[0] + SHIELD_OMNI_SCALE_TABLE_OFFSET;
            valueCursor = stateData;
            segmentAlphaCursor = tableCursor[0] + SHIELD_OMNI_ALPHA_TABLE_OFFSET;
            k = 0.5f;
            for (; i < SHIELD_SEGMENT_COUNT; i++) {
                f32 wave;
                f32 sum;
                phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX] = -0x4000;
                wave = fsin16((u16)phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX]);
                sum = amp + wave;
                wave = sum * k;
                valueCursor[SHIELD_SEGMENT_SCALE_F32_INDEX] = *segmentScaleCursor * wave;
                valueCursor[SHIELD_SEGMENT_ALPHA_F32_INDEX] = *segmentAlphaCursor;
                phaseCursor[SHIELD_SEGMENT_RATE_S16_INDEX] =
                    (s16)((f32)(i *
                                     randomGetRange(SHIELD_SEGMENT_RATE_RANDOM_MIN, SHIELD_SEGMENT_RATE_RANDOM_MAX)) +
                          SHIELD_SEGMENT_RATE_BASE);
                phaseCursor += 1;
                segmentScaleCursor += 1;
                valueCursor += 1;
                segmentAlphaCursor += 1;
            }
        }
        Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
        break;
    }
    case SHIELD_MODE_OMNI_HIT: {
        int i;
        s16* phaseCursor;
        f32* segmentScaleCursor;
        f32* valueCursor;
        f32* segmentAlphaCursor;
        f32 amp;
        f32 k;
        i = 0;
        phaseCursor = stateData;
        segmentScaleCursor = tableCursor[0] + SHIELD_OMNI_SCALE_TABLE_OFFSET;
        valueCursor = stateData;
        segmentAlphaCursor = tableCursor[0] + SHIELD_OMNI_ALPHA_TABLE_OFFSET;
        amp = 1.0f;
        k = 0.5f;
        for (; i < SHIELD_SEGMENT_COUNT; i++) {
            f32 wave;
            f32 sum;
            phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX] = 0x4000;
            wave = fsin16((u16)phaseCursor[SHIELD_SEGMENT_PHASE_S16_INDEX]);
            sum = amp + wave;
            wave = sum * k;
            valueCursor[SHIELD_SEGMENT_SCALE_F32_INDEX] = *segmentScaleCursor * wave;
            valueCursor[SHIELD_SEGMENT_ALPHA_F32_INDEX] = *segmentAlphaCursor;
            phaseCursor += 1;
            segmentScaleCursor += 1;
            valueCursor += 1;
            segmentAlphaCursor += 1;
        }
        break;
    }
    }
}

int Shield_getExtraSize(void) {
    return sizeof(ShieldState);
}

int Shield_getObjectTypeId(void) {
    return 0;
}

void Shield_free(GameObject* obj) {
    ShieldState* state = obj->extra;
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    Sfx_StopFromObject(obj, SFXTRIG_lrope_powerup);
    Sfx_StopFromObject(obj, SFXTRIG_lockon3_on);
}

typedef struct ShieldParticleParams {
    u8 pad0[8]; /* 0x00 */
    f32 alpha;  /* 0x08 */
    f32 pos[3]; /* 0x0C */
} ShieldParticleParams;

STATIC_ASSERT(offsetof(ShieldParticleParams, pad0) == 0x0);
STATIC_ASSERT(offsetof(ShieldParticleParams, alpha) == 0x8);
STATIC_ASSERT(offsetof(ShieldParticleParams, pos) == 0xC);
STATIC_ASSERT(sizeof(ShieldParticleParams) == 0x18);

void Shield_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    ShieldState* state = obj->extra;
    s32 isVisible = visible;
    if (isVisible != 0) {
        u8 i;
        u8 j;
        s16 savedRotX;
        f32 savedScale;
        s16 savedRotY;
        s16 savedRotZ;
        u8 hudHiddenFrames;
        ObjModel* model;
        f32 frameDelta;
        ShieldParticleParams particle;
        u8 savedAlpha;
        model = Obj_GetActiveModel(obj);
        savedScale = obj->anim.rootMotionScale;
        savedAlpha = obj->anim.alpha;
        savedRotX = obj->anim.rotX;
        savedRotY = obj->anim.rotY;
        savedRotZ = obj->anim.rotZ;
        hudHiddenFrames = (u8)getHudHiddenFrameCount();
        if (hudHiddenFrames != 0) {
            frameDelta = SHIELD_ZERO;
        } else {
            frameDelta = timeDelta;
        }
        if (obj->anim.romDefNo == SHIELD_SEQID_OMNI_SHIELD) {
            for (i = 0; i < SHIELD_SEGMENT_COUNT; i++) {
                if ((state->segmentFlags[i] & SHIELD_SEGMENT_FLAG_HIDDEN) == 0) {
                    u32 k = i;
                    obj->anim.rotX = state->segmentRotX[k];
                    obj->anim.rotY = state->segmentRotY[k];
                    obj->anim.rotZ = state->segmentRotZ[k];
                    state->segmentRotX[k] = (s16)(frameDelta * gOmniShieldRotXRates[k] + (f32)state->segmentRotX[k]);
                    state->segmentRotY[k] = (s16)(frameDelta * gOmniShieldRotYRates[k] + (f32)state->segmentRotY[k]);
                    state->segmentRotZ[k] = (s16)(frameDelta * gOmniShieldRotZRates[k] + (f32)state->segmentRotZ[k]);
                    {
                        obj->anim.rootMotionScale =
                            state->segmentScale[k] * savedScale * (state->fadeValue / state->fadeMax);
                        obj->anim.renderAlpha = (u8)(state->segmentAlpha[k] * savedAlpha);
                    }
                    model->bufferFlags &= ~0x8;
                    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
                }
            }
        } else {
            i = 0;
            for (; i < SHIELD_SEGMENT_COUNT; i++) {
                if ((state->segmentFlags[i] & SHIELD_SEGMENT_FLAG_HIDDEN) == 0) {
                    u32 k = i;
                    obj->anim.rotX = state->segmentRotX[k];
                    state->segmentRotX[k] = (s16)(frameDelta * gShieldRotXRates[k] + (f32)state->segmentRotX[k]);
                    {
                        obj->anim.rootMotionScale = state->segmentScale[k] * savedScale;
                        obj->anim.renderAlpha = (u8)(state->segmentAlpha[k] * savedAlpha);
                    }
                    model->bufferFlags &= ~0x8;
                    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
                    if (hudHiddenFrames == 0) {
                        f32 particleAlpha;
                        f32 particleOffsetZ;
                        f32 particleOffsetY;
                        f32 particleOffsetX;
                        j = 0;
                        particleOffsetX = SHIELD_PARTICLE_OFFSET_X;
                        particleOffsetY = SHIELD_PARTICLE_OFFSET_Y;
                        particleOffsetZ = SHIELD_ZERO;
                        particleAlpha = 1.0f;
                        for (; j < SHIELD_PARTICLE_COUNT_PER_SEGMENT; j++) {
                            f32 segmentScale = obj->anim.rootMotionScale;
                            particle.pos[0] = particleOffsetX * segmentScale;
                            particle.pos[1] = particleOffsetY * segmentScale;
                            particle.pos[2] = particleOffsetZ;
                            obj->anim.rotX += SHIELD_SEGMENT_HALF_TURN;
                            vecRotateZXY(&obj->anim.rotX, particle.pos);
                            particle.pos[0] += obj->anim.localPosX;
                            particle.pos[1] += obj->anim.localPosY;
                            particle.pos[2] += obj->anim.localPosZ;
                            particle.alpha = particleAlpha;
                            (*gPartfxInterface)
                                ->spawnObject(obj, SHIELD_PARTICLE_ID, &particle, SHIELD_PARTICLE_FLAGS, -1, NULL);
                        }
                    }
                }
            }
        }
        obj->anim.rootMotionScale = savedScale;
        obj->anim.alpha = savedAlpha;
        obj->anim.rotX = savedRotX;
        obj->anim.rotY = savedRotY;
        obj->anim.rotZ = savedRotZ;
    }
}

void Shield_hitDetect(GameObject* obj) {
    (void)obj;
}

void Shield_update(GameObject* obj) {
    f32* tableCursor[1];
    ShieldState* state;

    tableCursor[0] = gShieldSegmentTable + SHIELD_SCALE_TABLE_OFFSET;
    state = obj->extra;

    if (state->fadeValue != state->fadeTarget) {
        state->fadeValue += state->fadeRate * timeDelta;
        if (state->fadeRate > SHIELD_ZERO) {
            if (state->fadeValue >= state->fadeTarget) {
                state->fadeValue = state->fadeTarget;
            }
            state->segmentFlags[0] &= ~SHIELD_SEGMENT_FLAG_HIDDEN;
            state->segmentFlags[1] &= ~SHIELD_SEGMENT_FLAG_HIDDEN;
            state->segmentFlags[2] &= ~SHIELD_SEGMENT_FLAG_HIDDEN;
            state->segmentFlags[3] &= ~SHIELD_SEGMENT_FLAG_HIDDEN;
        } else {
            if (state->fadeValue <= state->fadeTarget) {
                state->fadeValue = state->fadeTarget;
                state->segmentFlags[0] |= SHIELD_SEGMENT_FLAG_HIDDEN;
                state->segmentFlags[1] |= SHIELD_SEGMENT_FLAG_HIDDEN;
                state->segmentFlags[2] |= SHIELD_SEGMENT_FLAG_HIDDEN;
                state->segmentFlags[3] |= SHIELD_SEGMENT_FLAG_HIDDEN;
            }
        }
    }
    if (obj->anim.romDefNo == SHIELD_SEQID_OMNI_SHIELD) {
        obj->anim.alpha = (u8)(state->fadeValue / state->fadeMax * (f32)randomGetRange(96, 127));
    } else {
        obj->anim.alpha = (u8)(state->fadeValue / state->fadeMax * (f32)randomGetRange(192, 255));
    }
    Sfx_SetObjectSfxVolume(obj, SFXTRIG_lockon3_on, (SHIELD_SFX_VOLUME_MAX * (state->fadeValue / state->fadeMax)),
                           SHIELD_SFX_VOLUME_SCALE);
    if (obj->anim.alpha != 0) {
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    } else {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    {
        int i;
        f32* omniAlphaCursor;
        f32* alphaCursor;
        s16* stateS16;
        f32* omniScaleCursor;
        f32* stateF32;
        i = 0;
        stateS16 = (s16*)state;
        omniScaleCursor = tableCursor[0] + SHIELD_OMNI_SCALE_TABLE_OFFSET;
        stateF32 = (f32*)state;
        omniAlphaCursor = tableCursor[0] + SHIELD_OMNI_ALPHA_TABLE_OFFSET;
        alphaCursor = tableCursor[0] + SHIELD_ALPHA_TABLE_OFFSET;
        for (; i < SHIELD_SEGMENT_COUNT; i++) {
            stateS16[SHIELD_SEGMENT_PHASE_S16_INDEX] = (s16)((f32)stateS16[SHIELD_SEGMENT_RATE_S16_INDEX] * timeDelta +
                                                             stateS16[SHIELD_SEGMENT_PHASE_S16_INDEX]);
            if (obj->anim.romDefNo == SHIELD_SEQID_OMNI_SHIELD) {
                f32 wave = fsin16((u16)stateS16[SHIELD_SEGMENT_PHASE_S16_INDEX]);
                wave = wave / 4.0f + 1.0f;
                stateF32[SHIELD_SEGMENT_SCALE_F32_INDEX] = *omniScaleCursor * wave;
                stateF32[SHIELD_SEGMENT_ALPHA_F32_INDEX] = *omniAlphaCursor;
            } else {
                f32 wave = fsin16((u16)stateS16[SHIELD_SEGMENT_PHASE_S16_INDEX]);
                f32 sum = 1.0f + wave;
                wave = sum / 2.0f;
                stateF32[SHIELD_SEGMENT_SCALE_F32_INDEX] = *tableCursor[0] * wave;
                stateF32[SHIELD_SEGMENT_ALPHA_F32_INDEX] = *alphaCursor;
            }
            stateS16++;
            omniScaleCursor++;
            stateF32++;
            omniAlphaCursor++;
            tableCursor[0]++;
            alphaCursor++;
        }
    }
}

void Shield_init(GameObject* obj, void* unused) {
    ObjModel* model = Obj_GetActiveModel(obj);

    (void)unused;

    ObjModel_SetPostRenderCallback(model, postRenderSetAlphaBlendState);
    if (obj->anim.romDefNo == SHIELD_SEQID_OMNI_SHIELD) {
        Shield_setMode(obj, SHIELD_MODE_INIT_OMNI);
    } else {
        Shield_setMode(obj, SHIELD_MODE_INIT_STANDARD);
    }
}

void Shield_release(void) {
}

void Shield_initialise(void) {
}
