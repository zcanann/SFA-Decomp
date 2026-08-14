/*
 * DIMExplosio (DLL 0x1CA) - the generic explosion/fireball effect object.
 *
 * The extra block (explosion_getExtraSize == 0xA60, DimExplosionState) holds a
 * flame pool (50 x DimExplosionFlame, 0x30 each, from offset 0) and a gravity
 * debris pool (6 x 0x24 records, from 0x964). Functions are kept in binary
 * (address) order:
 *   explosion_spawnFlame   - seed one flame slot (speed/colour/spin/sfx)
 *   explosion_computeColor - age/lifetime -> RGB ramp via per-channel expf
 *   explosion_render       - draw each live flame as a billboarded quad
 *                            through the GX FIFO
 *   explosion_update       - age the flames, integrate the gravity debris,
 *                            spawn particle fx, fade the light
 *   explosion_init         - seed flames/debris/light from placement flags
 *   explosion_initialise   - precompute the expf falloff scales
 */

#include "dlls/objects/458_DIMExplosio.h"
#include "dolphin/mtx.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/gx/GXGeometry.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/shader_api.h"
#include "main/texture.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "track/intersect_render_setup_api.h"
#include "main/camera.h"

typedef void (*ExplosionSpawnFlameSpeedFirstFn)(int obj, f32 speed, int generation, f32 x, f32 y, f32 z);

typedef struct DimExplosionPartfxSource {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 flags;
    f32 rootMotionScale;
    f32 localPosX;
    f32 localPosY;
    f32 localPosZ;
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* parent;
    u8 hostedMapSlot;
    s8 transformMatrixIndex;
    u8 alpha;
    u8 renderAlpha;
} DimExplosionPartfxSource;

typedef struct DimExplosionTextureTable {
    int assetIds[4];
} DimExplosionTextureTable;

STATIC_ASSERT(sizeof(DimExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, velocityX) == 0x24);
STATIC_ASSERT(sizeof(DimExplosionTextureTable) == 0x10);

#define DIM_EXPLOSION_PARTICLE_EFFECT_ID 0x5E
#define DIM_EXPLOSION_TEXTURE_COUNT      4

void* gExplosionTextures[DIM_EXPLOSION_TEXTURE_COUNT];
extern int lbl_803E8468;
f32 gExplosionDebrisSpeedScale;
f32 gExplosionDebrisAlphaScale;
f32 gExplosionDebrisColorScale;
f32 gExplosionFalloffScaleRed;
f32 gExplosionFalloffScaleGreen;
f32 gExplosionFalloffScaleBlue;
u8 gExplosionUpdateTick;
extern Vec gExplosionSpreadDirs[];
const DimExplosionTextureTable gExplosionTexTable = {{0x5e1, 0x5f7, 0x5f8, 0x5f9}};

volatile PPCWGPipe GXWGFifo : (0xCC008000);

static const int sExplosionQuadColorA[1] = {-1};
static const f32 sExplosionBaseScale[1] = {1.0f};
static const f32 sExplosionLifeScale[1] = {15.0f};
static const f32 sExplosionFadeInExponent[1] = {10.0f};
static const f32 sExplosionColorMax[1] = {255.0f};
static const f32 sExplosionFadeOutExponent[1] = {25.0f};
static const f32 sExplosionSpawnDelay[1] = {8.0f};

void explosion_spawnFlame(GameObject* obj, u8 generation, f32 speed, f32 x, f32 y, f32 z) {
    DimExplosionPlacement* placement = (DimExplosionPlacement*)(obj)->anim.placementData;
    DimExplosionState* state = (obj)->extra;
    DimExplosionFlame* flames = (DimExplosionFlame*)state->flames;
    int flameIndex = state->flameCount++;
    flames[flameIndex].posX = x;
    flames[flameIndex].posY = y;
    flames[flameIndex].posZ = z;
    flames[flameIndex].baseScale = sExplosionBaseScale[0];
    flames[flameIndex].scale = flames[0].baseScale;
    flames[flameIndex].speed = speed;
    flames[flameIndex].generation = generation;
    flames[flameIndex].age = 0;
    flames[flameIndex].lifetime = (int)(sExplosionLifeScale[0] * sqrtf(speed));
    {
        int clampedLifetime = flames[flameIndex].lifetime;
        if (clampedLifetime < 0) {
            clampedLifetime = 0;
        } else if (clampedLifetime > 0x3c) {
            clampedLifetime = 0x3c;
        }
        flames[flameIndex].lifetime = clampedLifetime;
    }
    if (flames[flameIndex].generation < 1) {
        s8 sfxKind = placement->sfxKind;
        if (sfxKind != 0) {
            if (sfxKind == 2) {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_sexpl2_c_4bf);
            } else if (sfxKind == 3) {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_sexpl2_c_4c2);
            } else {
                s8 mapEventSlot = (obj)->anim.mapEventSlot;
                switch (mapEventSlot) {
                case 0x2c:
                case 0x3a:
                case 0x3b:
                case 0x3c:
                case 0x3d:
                case 0x3e:
                    Sfx_PlayFromObjectLimited(obj, SFXTRIG_wp_sexpl2_c_4b8, 2);
                    break;
                default:
                    Sfx_PlayFromObject(obj, SFXTRIG_sexpl2_c);
                    break;
                }
            }
        }
    }
    flames[flameIndex].spinAngle = randomGetRange(0, 0xffff);
    flames[flameIndex].spinSpeed = randomGetRange(0xc8, 0x12c);
    if (randomGetRange(0, 1) != 0) {
        flames[flameIndex].spinSpeed = -flames[flameIndex].spinSpeed;
    }
    flames[flameIndex].textureVariant = randomGetRange(0, 3);
    {
        f32 initialSpeed = flames[flameIndex].speed;
        f32 curve =
            expf((sExplosionFadeInExponent[0] * ((f32)flames[flameIndex].lifetime - (f32)flames[flameIndex].age)) /
                 (f32)flames[flameIndex].lifetime);
        f32 scaleRange = initialSpeed - flames[flameIndex].baseScale;
        curve = scaleRange * curve;
        flames[flameIndex].scale = initialSpeed - gExplosionDebrisSpeedScale * curve;
        curve = expf((sExplosionFadeOutExponent[0] * (f32)flames[flameIndex].age) / (f32)flames[flameIndex].lifetime);
        curve = sExplosionColorMax[0] * curve;
        flames[flameIndex].alpha = sExplosionColorMax[0] - gExplosionDebrisAlphaScale * curve;
        flames[flameIndex].spawnTimer = sExplosionSpawnDelay[0];
        flames[flameIndex].spawnInterval = flames[flameIndex].spawnTimer;
        flames[flameIndex].active = 1;
    }
}

void explosion_computeColor(f32 age, f32 lifetime, u8 colorMode, u8* outputColor) {
    s16 r;
    s16 g;
    s16 b;
    s16 rawR;
    s16 rawG;
    s16 rawB;
    rawR = 0xff - (u8)(int)(gExplosionFalloffScaleRed * (sExplosionColorMax[0] * expf((7.5f * age) / lifetime)));
    rawG = 0xff - (u8)(int)(gExplosionFalloffScaleGreen * (sExplosionColorMax[0] * expf((2.5f * age) / lifetime)));
    rawB = 0xff - (u8)(int)(gExplosionFalloffScaleBlue * (sExplosionColorMax[0] * expf(age / lifetime)));
    r = (rawR < 1) ? 1 : ((rawR > 0xff) ? 0xff : rawR);
    g = (rawG < 1) ? 1 : ((rawG > 0xff) ? 0xff : rawG);
    b = (rawB < 1) ? 1 : ((rawB > 0xff) ? 0xff : rawB);
    switch (colorMode) {
    case 0:
        outputColor[0] = r;
        outputColor[1] = g;
        outputColor[2] = b;
        break;
    case 1:
        outputColor[0] = r;
        outputColor[1] = b;
        outputColor[2] = b;
        break;
    case 2:
        outputColor[0] = b;
        outputColor[1] = r;
        outputColor[2] = b;
        break;
    case 3:
        outputColor[0] = b;
        outputColor[1] = b;
        outputColor[2] = r;
        break;
    }
}

static const f32 sExplosionFlickerExponent[1] = {3.0f};
static const f32 sExplosionChildOffsetStep[1] = {0.09f};
static const f32 sExplosionZero[1] = {0.0f};
static const f64 sExplosionPi[1] = {3.142};
static const f32 sExplosionAngleScale[1] = {32768.0f};
static const f32 sExplosionSpeedScale[1] = {0.00390625f};

int explosion_getExtraSize(void) {
    return sizeof(DimExplosionState);
}

int explosion_getObjectTypeId(GameObject* obj) {
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelKind = (int)((DimExplosionPlacement*)obj->anim.placementData)->configFlags &
                    DIM_EXPLOSION_MODEL_KIND_MASK;
    if (modelKind >= objAnim->modelInstance->modelCount) {
        modelKind = 0;
    }
    return (modelKind << 11) | 0x400;
}

void explosion_free(GameObject* obj) {
    ModelLightStruct* light = ((DimExplosionState*)obj->extra)->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
    }
}

void explosion_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    u32 colA;
    u32 colB;
    u32 colA2;
    u32 colB2;
    Mtx mE;
    Mtx m4;
    Mtx m3;
    Mtx m2;
    Mtx m1;
    DimExplosionState* state;
    ObjModel* model;
    int i;
    int cursor;
    colA = sExplosionQuadColorA[0];
    colB = lbl_803E8468;
    state = obj->extra;
    model = Obj_GetActiveModel(obj);
    cursor = (int)state;
    if (visible != 0) {
        GXClearVtxDesc();
        GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
        GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
        GXSetCurrentMtx(GX_PNMTX0);
        for (i = 0, cursor = (int)state; i < state->flameCount; i++) {
            if (((DimExplosionFlame*)cursor)->active != 0) {
                void** tex;
                int k;
                u8 cv;
                Obj_BuildWorldTransformMatrix(obj, (f32*)mE, 0);
                PSMTXRotRad(m1, 'z', (f32)((6.2832 * (f64)(int)((DimExplosionFlame*)cursor)->spinAngle) / 65536.0));
                PSMTXRotRad(m3, 'x',
                            (f32)((6.2832 * ((f64)(u32)(Camera_GetCurrentViewPitch() & 0xffff) - 0.0)) / 65536.0));
                PSMTXConcat(m3, m1, m3);
                PSMTXRotRad(m2, 'y',
                            (f32)((6.2832 * (f64)(int)(0x10000 - (Camera_GetCurrentViewYaw() & 0xffff))) / 65536.0));
                PSMTXConcat(m2, m3, m2);
                PSMTXScale(m4, ((DimExplosionFlame*)cursor)->scale, ((DimExplosionFlame*)cursor)->scale,
                           ((DimExplosionFlame*)cursor)->scale);
                PSMTXConcat(m4, m2, m4);
                PSMTXTrans(mE, ((DimExplosionFlame*)cursor)->posX - playerMapOffsetX,
                           ((DimExplosionFlame*)cursor)->posY, ((DimExplosionFlame*)cursor)->posZ - playerMapOffsetZ);
                PSMTXConcat(mE, m4, mE);
                PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), mE, mE);
                GXLoadPosMtxImm((const f32(*)[4])mE, GX_PNMTX0);
                ((u8*)&colA)[3] = ((DimExplosionFlame*)cursor)->alpha;
                cv = gExplosionDebrisColorScale *
                     (sExplosionColorMax[0] *
                      expf((sExplosionFlickerExponent[0] *
                            ((f32)((DimExplosionFlame*)cursor)->lifetime - (f32)((DimExplosionFlame*)cursor)->age)) /
                           (f32)((DimExplosionFlame*)cursor)->lifetime));
                ((u8*)&colB)[0] = cv;
                ((u8*)&colB)[1] = cv;
                ((u8*)&colB)[2] = cv;
                ((u8*)&colB)[3] = cv;
                explosion_computeColor((f32)((DimExplosionFlame*)cursor)->age,
                                       (f32)((DimExplosionFlame*)cursor)->lifetime,
                                       state->modelKind, (u8*)&colA);
                tex = (void**)((int*)gExplosionTextures)[state->modelKind];
                for (k = 0; k < ((DimExplosionFlame*)cursor)->textureVariant; k++) {
                    tex = (void**)*tex;
                }
                colB2 = colB;
                colA2 = colA;
                setupAdditiveTintedTexture(tex, &colA2, &colB2);
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                {
                    f32 fc, fb, fa;
                    GXWGFifo.f32 = (fa = -1.0f);
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = (fb = sExplosionZero[0]);
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = (fc = sExplosionBaseScale[0]);
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                }
            }
            cursor += sizeof(DimExplosionFlame);
        }
        if (state->frameCounter < state->lifeFrames &&
            state->rayCount != 0) {
            for (i = 0; i < state->rayCount; i++) {
                obj->anim.rotY = (s16)state->rays[i].yaw;
                obj->anim.rotX = (s16)state->rays[i].pitch;
                objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, visible);
                if (i < state->rayCount - 1) {
                    model->bufferFlags &= ~8;
                }
            }
        }
    }
    objRenderInvalidateStateCache();
}

void explosion_hitDetect(void) {
}

void explosion_update(GameObject* obj) {
    DimExplosionPartfxSource fake;
    u16 ang[6];
    Vec vpos;
    Mtx m;
    u8 rgb[3];
    int state = (int)obj->extra;
    int i;
    int cursor;
    gExplosionUpdateTick += 1;
    cursor = state;
    ((DimExplosionState*)state)->frameCounter += framesThisStep;
    for (i = 0, cursor = state; i < ((DimExplosionState*)state)->flameCount; i++) {
        ((DimExplosionFlame*)cursor)->age += framesThisStep;
        if (((DimExplosionFlame*)cursor)->active != 0) {
            f32 sp = ((DimExplosionFlame*)cursor)->speed;
            f32 ev = expf((sExplosionFadeInExponent[0] *
                           ((f32)((DimExplosionFlame*)cursor)->lifetime - (f32)((DimExplosionFlame*)cursor)->age)) /
                          (f32)(int)((DimExplosionFlame*)cursor)->lifetime);
            f32 d = sp - ((DimExplosionFlame*)cursor)->baseScale;
            ev = d * ev;
            ((DimExplosionFlame*)cursor)->scale = sp - gExplosionDebrisSpeedScale * ev;
            ev = expf((sExplosionFadeOutExponent[0] * (f32)((DimExplosionFlame*)cursor)->age) /
                      (f32)((DimExplosionFlame*)cursor)->lifetime);
            ev = sExplosionColorMax[0] * ev;
            *(s8*)&((DimExplosionFlame*)cursor)->alpha = sExplosionColorMax[0] - gExplosionDebrisAlphaScale * ev;
            if (((DimExplosionFlame*)cursor)->age >= ((DimExplosionFlame*)cursor)->lifetime) {
                ((DimExplosionFlame*)cursor)->active = 0;
            } else {
                ((DimExplosionFlame*)cursor)->spinAngle +=
                    framesThisStep * ((DimExplosionFlame*)cursor)->spinSpeed;
                if (((DimExplosionFlame*)cursor)->textureVariant >= DIM_EXPLOSION_TEXTURE_COUNT) {
                    ((DimExplosionFlame*)cursor)->textureVariant -= DIM_EXPLOSION_TEXTURE_COUNT;
                }
                if (((DimExplosionFlame*)cursor)->generation < 5) {
                    if ((f32)((DimExplosionFlame*)cursor)->age / (f32)((DimExplosionFlame*)cursor)->lifetime < 0.2f) {
                        ((DimExplosionFlame*)cursor)->spawnTimer -= framesThisStep;
                        if (((DimExplosionFlame*)cursor)->spawnTimer <= 0) {
                            DimExplosionState* spawnState;
                            u8 parentGeneration;
                            f32 parentSpeed;
                            f32 childSpeed;
                            parentGeneration = ((DimExplosionFlame*)cursor)->generation;
                            parentSpeed = ((DimExplosionFlame*)cursor)->speed;
                            spawnState = obj->extra;
                            vpos.x = ((DimExplosionFlame*)cursor)->scale *
                                      (sExplosionChildOffsetStep[0] * (f32)randomGetRange(-5, 3) +
                                       sExplosionBaseScale[0]);
                            vpos.y = sExplosionZero[0];
                            vpos.z = sExplosionZero[0];
                            PSMTXRotRad(m, 'z',
                                        (f32)(sExplosionPi[0] *
                                              (f64)((f32)randomGetRange(0, 0xffff) / sExplosionAngleScale[0])));
                            PSMTXConcat((MtxPtr)Camera_GetInverseViewRotationMatrix(), m, m);
                            PSMTXMultVecSR(m, &vpos, &vpos);
                            vpos.x += ((DimExplosionFlame*)cursor)->posX;
                            vpos.y += ((DimExplosionFlame*)cursor)->posY;
                            vpos.z += ((DimExplosionFlame*)cursor)->posZ;
                            childSpeed = parentSpeed * (f32)randomGetRange(0xc0, 0x100);
                            childSpeed = childSpeed * sExplosionSpeedScale[0];
                            if (spawnState->flameCount < DIM_EXPLOSION_FLAME_CAPACITY) {
                                explosion_spawnFlame(obj, (u8)(parentGeneration + 1), childSpeed, vpos.x, vpos.y,
                                                     vpos.z);
                            }
                            ((DimExplosionFlame*)cursor)->spawnTimer = ((DimExplosionFlame*)cursor)->spawnInterval;
                        }
                    }
                }
            }
        }
        cursor += sizeof(DimExplosionFlame);
    }
    memcpy(&fake, (void*)obj, sizeof(fake));
    fake.rootMotionScale = sExplosionBaseScale[0];
    fake.velocityX = sExplosionZero[0];
    fake.velocityY = sExplosionZero[0];
    fake.velocityZ = sExplosionZero[0];
    for (i = 0, cursor = state; i < ((DimExplosionState*)state)->debrisCount; i++) {
        DimExplosionGravityDebris* debris =
            (DimExplosionGravityDebris*)((char*)cursor + offsetof(DimExplosionState, debris));
        if (debris->active != 0) {
            debris->age += framesThisStep;
            if (debris->age >= debris->lifetime) {
                debris->active = 0;
            } else {
                f32 gravity = ((DimExplosionState*)state)->gravity;
                u32 elapsedFrames = framesThisStep;
                f32 nextVelocityY = -(gravity * (f32)elapsedFrames - debris->velocityY);
                debris->posY = -(0.5f * (gravity * (f32)(int)(elapsedFrames * elapsedFrames)) -
                                 (debris->velocityY * (f32)elapsedFrames + debris->posY));
                debris->velocityY = nextVelocityY;
                debris->posX += debris->velocityX * (f32)(u32)framesThisStep;
                debris->posZ += debris->velocityZ * (f32)(u32)framesThisStep;
                if (((DimExplosionState*)state)->nearGround != 0 &&
                    debris->posY < ((DimExplosionState*)state)->groundY && debris->velocityY < sExplosionZero[0]) {
                    debris->velocityY = 0.95f * -debris->velocityY;
                }
                fake.localPosX = debris->posX;
                fake.localPosY = debris->posY;
                fake.localPosZ = debris->posZ;
                fake.worldPosX = fake.localPosX;
                fake.worldPosY = fake.localPosY;
                fake.worldPosZ = fake.localPosZ;
                if (gExplosionUpdateTick & 1) {
                    int debrisAge = debris->age;
                    if (debrisAge < 0x40) {
                        int fadeStep = debrisAge << 6;
                        ang[0] = 0xffff - fadeStep;
                        ang[1] = ang[0];
                        ang[2] = 0x8000;
                        ang[3] = 0xc000 - fadeStep;
                        ang[4] = 0xa000 - fadeStep;
                        ang[5] = 0;
                    } else if (debrisAge < 0x80) {
                        int fadeStep = debrisAge << 6;
                        ang[0] = 0xc000 - fadeStep;
                        ang[1] = 0xa000 - fadeStep;
                        ang[2] = 0;
                        ang[3] = 0x8000;
                        ang[4] = 0;
                        ang[5] = 0;
                    } else {
                        ang[0] = 0xa000;
                        ang[1] = 0;
                        ang[2] = 0;
                        ang[3] = 0;
                        ang[4] = 0;
                        ang[5] = 0;
                    }
                    {
                        u8 modelKind;
                        modelKind = ((DimExplosionState*)state)->modelKind;
                        switch (modelKind) {
                        case 0:
                            break;
                        case 1:
                            ang[1] = ang[2];
                            ang[4] = ang[5];
                            break;
                        case 2:
                            ang[1] = ang[0];
                            ang[4] = ang[3];
                            ang[0] = ang[2];
                            ang[3] = ang[5];
                            break;
                        case 3: {
                            u16 sv5;
                            u16 sv = ang[2];
                            ang[1] = sv;
                            sv5 = ang[5];
                            ang[4] = sv5;
                            ang[2] = ang[0];
                            ang[5] = ang[3];
                            ang[0] = sv;
                            ang[3] = sv5;
                        } break;
                        }
                    }
                    (*gPartfxInterface)
                        ->spawnObject((void*)obj, DIM_EXPLOSION_PARTICLE_EFFECT_ID, &fake, 0x200001, -1, ang);
                }
            }
        }
        cursor += sizeof(DimExplosionGravityDebris);
    }
    {
        int frameCounter = ((DimExplosionState*)state)->frameCounter;
        int lifeFrames = ((DimExplosionState*)state)->lifeFrames;
        if (frameCounter > lifeFrames << 1) {
            Obj_FreeObject(obj);
        } else {
            if (frameCounter > lifeFrames) {
                if ((void*)((DimExplosionState*)state)->light != NULL) {
                    modelLightStruct_setEnabled(((DimExplosionState*)state)->light, 0, sExplosionZero[0]);
                }
            } else {
                explosion_computeColor((f32)frameCounter, (f32)lifeFrames, ((DimExplosionState*)state)->modelKind, rgb);
                if ((void*)((DimExplosionState*)state)->light != NULL) {
                    modelLightStruct_setDiffuseColor(((DimExplosionState*)state)->light, rgb[0], rgb[1], rgb[2], 0xff);
                }
            }
            {
                f32 frac =
                    (f32)((DimExplosionState*)state)->frameCounter / (f32)((DimExplosionState*)state)->lifeFrames;
                (obj)->anim.rootMotionScale = 0.1f * (frac * ((DimExplosionState*)state)->scale);
                (obj)->anim.alpha = sExplosionColorMax[0] - sExplosionColorMax[0] * frac;
            }
            if (((DimExplosionState*)state)->halfLifeFired == 0 &&
                ((DimExplosionState*)state)->frameCounter >= (((DimExplosionState*)state)->lifeFrames >> 1)) {
                u32 k;
                u16 r0v = randomGetRange(0x1000, 0x6000);
                ang[0] = r0v;
                ang[1] = r0v;
                ang[2] = r0v;
                ang[3] = ((DimExplosionFlame*)state)->lifetime;
                k = 0;
                while ((f32)(int)k < ((DimExplosionState*)state)->scale) {
                    k++;
                }
                ((DimExplosionState*)state)->halfLifeFired = 1;
            }
        }
    }
}

void explosion_init(GameObject* obj, DimExplosionPlacement* placementAddress) {
    Vec vsp;
    Mtx mB;
    Mtx mA;
    int cursor;
    DimExplosionState* state = obj->extra;
    f32 scale;
    int i;
    int debrisCount;
    state->flameCount = 0;
    if (placementAddress->scaleParam == 0) {
        scale = 100.0f;
    } else {
        scale = (f32)(int)placementAddress->scaleParam * sExplosionSpeedScale[0];
        if (scale > 100.0f) {
            scale = 100.0f;
        }
    }
    ((ExplosionSpawnFlameSpeedFirstFn)explosion_spawnFlame)((int)obj, 0.4f * scale, 0, obj->anim.localPosX,
                                                            obj->anim.localPosY, obj->anim.localPosZ);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->modelKind =
        placementAddress->configFlags & DIM_EXPLOSION_MODEL_KIND_MASK;
    Obj_SetActiveModelIndex(obj, state->modelKind);
    if (placementAddress->configFlags & DIM_EXPLOSION_CONFIG_HAS_GRAVITY) {
        state->gravity = 0.1f;
    } else {
        state->gravity = sExplosionZero[0];
    }
    state->nearGround = 0;
    if (trackGetNearestGroundOffset(obj, obj->anim.localPosX, 5.0f + obj->anim.localPosY, obj->anim.localPosZ,
                             (f32*)((u8*)state + offsetof(DimExplosionState, groundY)), 0) == 0) {
        if (state->groundY < 20.0f) {
            state->nearGround = 1;
        }
        state->groundY = obj->anim.localPosY - state->groundY;
    } else {
        state->groundY = obj->anim.localPosY;
    }
    if (placementAddress->configFlags & DIM_EXPLOSION_CONFIG_SPAWNS_DEBRIS) {
        debrisCount = (int)((f32)(6.0f * scale) / 100.0f);
        for (i = 0, cursor = (int)state; i < debrisCount; i++) {
            if (state->nearGround != 0) {
                f32 mag = 2.0f * ((f32)randomGetRange(0x14, 0x28) * 0.01f) + 2.0f;
                vsp.x = mag;
                vsp.y = sExplosionZero[0];
                vsp.z = sExplosionZero[0];
                PSMTXRotRad(mB, 'z',
                            (f32)(sExplosionPi[0] * (f64)((f32)randomGetRange(0x2000, 0x6000) / 65535.0f)));
                PSMTXRotRad(
                    mA, 0x79,
                    (f32)(sExplosionPi[0] * (f64)((f32)randomGetRange(0, 0xffff) / sExplosionAngleScale[0])));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, &vsp, &vsp);
            } else {
                f32 mag = 2.0f * ((f32)randomGetRange(0x14, 0x28) * 0.01f) + 2.0f;
                u8 spreadDirectionIndex;
                spreadDirectionIndex = i % 4;
                vsp.x = mag * gExplosionSpreadDirs[spreadDirectionIndex].x;
                vsp.y = mag * gExplosionSpreadDirs[spreadDirectionIndex].y;
                vsp.z = mag * gExplosionSpreadDirs[spreadDirectionIndex].z;
                PSMTXRotRad(
                    mB, 0x7a,
                    (f32)(sExplosionPi[0] * (f64)(((f32)randomGetRange(0, 0x8000) - 16384.0f) / 65535.0f)));
                PSMTXRotRad(
                    mA, 0x78,
                    (f32)(sExplosionPi[0] * (f64)(((f32)randomGetRange(0, 0x8000) - 16384.0f) / 65535.0f)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, &vsp, &vsp);
            }
            {
                DimExplosionGravityDebris* debris =
                    (DimExplosionGravityDebris*)((char*)cursor + offsetof(DimExplosionState, debris));
                debris->posX = obj->anim.localPosX;
                debris->posY = obj->anim.localPosY;
                debris->posZ = obj->anim.localPosZ;
                debris->velocityX = vsp.x;
                debris->velocityY = vsp.y;
                debris->velocityZ = vsp.z;
                debris->age = 0;
                debris->lifetime = randomGetRange(0x28, 0x32);
                debris->active = 1;
            }
            cursor += sizeof(DimExplosionGravityDebris);
        }
        state->debrisCount = i;
    } else {
        state->debrisCount = 0;
    }
    state->light = 0;
    if (placementAddress->configFlags & DIM_EXPLOSION_CONFIG_HAS_LIGHT) {
        state->light = objCreateLight(0, 1);
        if ((void*)state->light != NULL) {
            modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(state->light, obj->anim.worldPosX, obj->anim.worldPosY,
                                         obj->anim.worldPosZ);
            modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)state->light, 1);
            modelLightStruct_setEnabled(state->light, 1, sExplosionZero[0]);
            modelLightStruct_setDistanceAttenuation(state->light, (f32)(1.5f * scale),
                                                    (f32)(sExplosionFlickerExponent[0] * scale));
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0xeb, 0xa0, 0xff);
        }
    }
    obj->anim.alpha = 0xff;
    if (placementAddress->configFlags & DIM_EXPLOSION_CONFIG_HAS_RAYS) {
        if (state->nearGround == 0) {
            state->rayCount = 2;
            state->rays[0].yaw = randomGetRange(0, 0x4000);
            state->rays[0].pitch = randomGetRange(0, 0x8000);
            state->rays[1].yaw = state->rays[0].yaw + 0x4000;
            state->rays[1].pitch = state->rays[0].pitch;
        } else {
            state->rayCount = 1;
            state->rays[0].yaw = 0;
            state->rays[0].pitch = 0;
        }
    } else {
        state->rayCount = 0;
    }
    state->halfLifeFired = 0;
    state->frameCounter = 0;
    state->lifeFrames = (int)(sExplosionLifeScale[0] * sqrtf(scale));
    {
        int clampedLifeFrames = state->lifeFrames;
        if (clampedLifeFrames < 0) {
            clampedLifeFrames = 0;
        } else if (clampedLifeFrames > 0x3c) {
            clampedLifeFrames = 0x3c;
        }
        state->lifeFrames = clampedLifeFrames;
    }
    state->scale = scale;
    obj->anim.rootMotionScale = sExplosionZero[0];
}

void explosion_release(u32 unused) {
    int i;

    for (i = 0; i < DIM_EXPLOSION_TEXTURE_COUNT; i++) {
        if (gExplosionTextures[i] != NULL) {
            textureFree((Texture*)gExplosionTextures[i]);
            gExplosionTextures[i] = NULL;
        }
    }
}

void explosion_initialise(void) {
    DimExplosionTextureTable t;
    int i;
    t = gExplosionTexTable;
    gExplosionDebrisSpeedScale = sExplosionBaseScale[0] / expf(sExplosionFadeInExponent[0]);
    gExplosionDebrisAlphaScale = sExplosionBaseScale[0] / expf(sExplosionFadeOutExponent[0]);
    gExplosionDebrisColorScale = sExplosionBaseScale[0] / expf(sExplosionFlickerExponent[0]);
    gExplosionFalloffScaleRed = sExplosionBaseScale[0] / expf(7.5f);
    gExplosionFalloffScaleGreen = sExplosionBaseScale[0] / expf(2.5f);
    gExplosionFalloffScaleBlue = sExplosionBaseScale[0] / expf(sExplosionBaseScale[0]);
    for (i = 0; i < DIM_EXPLOSION_TEXTURE_COUNT; i++) {
        gExplosionTextures[i] = textureLoadAsset(t.assetIds[i]);
    }
}

Vec gExplosionSpreadDirs[] = {
    {1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {-1.0f, 0.0f, 0.0f}, {0.0f, -1.0f, 0.0f},
};

ObjectDescriptor gExplosionObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)explosion_initialise,
    (ObjectDescriptorCallback)explosion_release,
    0,
    (ObjectDescriptorCallback)explosion_init,
    (ObjectDescriptorCallback)explosion_update,
    (ObjectDescriptorCallback)explosion_hitDetect,
    (ObjectDescriptorCallback)explosion_render,
    (ObjectDescriptorCallback)explosion_free,
    (ObjectDescriptorCallback)explosion_getObjectTypeId,
    explosion_getExtraSize,
};
