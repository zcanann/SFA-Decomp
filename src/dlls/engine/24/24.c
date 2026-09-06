#include "main/dll/dll_0018_boneparticleeffect.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/model.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/lightmap_text_color_api.h"
#include "main/vecmath.h"
#include "main/camera.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/mtx.h"
#include "main/rcp_dolphin_api.h"
#include "track/intersect_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_render_setup_api.h"

s16 gBoneParticleEffectTimer;
s32 gBoneParticleScrollOffset;
s16 gBoneParticleStageIndex;
s32 gBoneParticleJointIndex;
f32 gBoneParticleDrift;
void* gBoneParticleTextureB;
void* gBoneParticleTextureA;
s32 gBoneParticleBufferFlip;

#define BONE_PARTICLE_EFFECT_PARTFX       0x28c
#define BONE_PARTICLE_EFFECT_BUFFER_COUNT 7
#define BONE_PARTICLE_EFFECT_BUFFER_BYTES 0x140
#define BONE_PARTICLE_EFFECT_SLOT_COUNT   20

void* gBoneParticleEffectBuffers[8];
f32 gBoneParticleDriftVelocity[2] = {10.0f, 0.0f};

/* the two bone-particle texture assets loaded at init (gBoneParticleTextureA/B) */
#define BONE_PARTICLE_TEXTURE_A_ID 0x16b
#define BONE_PARTICLE_TEXTURE_B_ID 0x201



void boneParticleEffect_func08_nop(void) {
}

static Vec3f gBoneParticleCornersXZ[12] = {
    {-1500.0f, 0.0f, -1500.0f},
    {-1500.0f, 0.0f, 1500.0f},
    {1500.0f, 0.0f, 1500.0f},
    {1500.0f, 0.0f, -1500.0f},
    {-1500.0f, 0.0f, -1500.0f},
    {-1500.0f, 0.0f, 1500.0f},
    {1500.0f, 0.0f, 1500.0f},
    {1500.0f, 0.0f, -1500.0f},
    {-1500.0f, 0.0f, -1500.0f},
    {-1500.0f, 0.0f, 1500.0f},
    {1500.0f, 0.0f, 1500.0f},
    {1500.0f, 0.0f, -1500.0f}
};
static Vec3f gBoneParticleCornersYZ[12] = {
    {0.0f, -1500.0f, -1500.0f},
    {0.0f, -1500.0f, 1500.0f},
    {0.0f, 1500.0f, 1500.0f},
    {0.0f, 1500.0f, -1500.0f},
    {0.0f, -1500.0f, -1500.0f},
    {0.0f, -1500.0f, 1500.0f},
    {0.0f, 1500.0f, 1500.0f},
    {0.0f, 1500.0f, -1500.0f},
    {0.0f, -1500.0f, -1500.0f},
    {0.0f, -1500.0f, 1500.0f},
    {0.0f, 1500.0f, 1500.0f},
    {0.0f, 1500.0f, -1500.0f}
};
static Vec3f gBoneParticleCornersXY[12] = {
    {-1500.0f, -1500.0f, 0.0f},
    {1500.0f, -1500.0f, 0.0f},
    {1500.0f, 1500.0f, 0.0f},
    {-1500.0f, 1500.0f, 0.0f},
    {-1500.0f, -1500.0f, 0.0f},
    {1500.0f, -1500.0f, 0.0f},
    {1500.0f, 1500.0f, 0.0f},
    {-1500.0f, 1500.0f, 0.0f},
    {-1500.0f, -1500.0f, 0.0f},
    {1500.0f, -1500.0f, 0.0f},
    {1500.0f, 1500.0f, 0.0f},
    {-1500.0f, 1500.0f, 0.0f}
};
static LightmapVertex gBoneParticleInitVertices[20] = {
{-500, -900, -500, 0, 0, 0, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 0, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 0, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 0, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 127, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 127, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 127, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 127, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 255, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 255, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 255, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 255, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 383, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 383, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 383, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 383, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 511, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 511, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 511, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 511, 255, 255, 255, 255},
};
/* The final ten records cap the five rings; update draws only the 32 side triangles. */
static LightmapTriangle gBoneParticleTriangles[42] = {
    {0, {0, 4, 5}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {0, 5, 1}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {1, 5, 6}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {1, 6, 2}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {2, 6, 7}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {2, 7, 3}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {3, 7, 4}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {3, 4, 0}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {4, 8, 9}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {4, 9, 5}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {5, 9, 10}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {5, 10, 6}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {6, 10, 11}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {6, 11, 7}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {7, 11, 8}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {7, 8, 4}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {8, 12, 13}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {8, 13, 9}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {9, 13, 14}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {9, 14, 10}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {10, 14, 15}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {10, 15, 11}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {11, 15, 12}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {11, 12, 8}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {12, 16, 17}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {12, 17, 13}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {13, 17, 18}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {13, 18, 14}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {14, 18, 19}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {14, 19, 15}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {15, 19, 16}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {15, 16, 12}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {0, 2, 1}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {0, 2, 3}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {4, 6, 5}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {4, 6, 7}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {8, 10, 9}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {8, 10, 11}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {12, 14, 13}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {12, 14, 15}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {16, 18, 17}, {{0, 0}, {0, 0}, {0, 0}}},
    {0, {16, 18, 19}, {{0, 0}, {0, 0}, {0, 0}}}
};
static u8 gBoneParticleJointPlanes[34] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1
};
static u8 gBoneParticleJointIds[7][5] = {
    {0, 1, 2, 3, 4},
    {0, 5, 6, 7, 8},
    {9, 10, 11, 13, 13},
    {16, 17, 18, 19, 20},
    {22, 23, 24, 25, 26},
    {15, 29, 32, 15, 15},
    {28, 28, 33, 0, 0}
};
static f32 gBoneParticleJointXYScales[35] = {
    0.94f, 0.66f, 0.493f, 0.568f, 0.518f, 0.5f, 0.463f, 0.618f, 0.518f, 0.45f, 0.638f, 0.842f, 0.6f, 0.413f, 0.9f, 0.862f, 0.518f, 0.585f, 0.285f, 0.465f, 0.375f, 0.75f, 0.54f, 0.615f, 0.15f, 0.458f, 0.397f, 0.75f, 0.937f, 0.945f, 0.75f, 0.75f, 0.862f, 0.947f, 0.75f
};
static f32 gBoneParticleJointZScales[35] = {
    0.75f, 1.0f, 0.772f, 0.967f, 0.967f, 1.13f, 0.712f, 1.037f, 0.757f, 0.45f, 0.178f, 0.463f, 0.6f, 0.413f, 0.9f, 0.862f, 0.518f, 0.585f, 0.555f, 0.465f, 0.375f, 0.75f, 0.54f, 0.615f, 0.51f, 0.458f, 0.397f, 0.75f, 0.488f, 0.945f, 0.75f, 0.75f, 0.862f, 0.558f, 0.75f
};


/* Per-bone particle vertex update + draw. */
void boneParticleEffect_update(void* ctx, int renderParam, GameObject* obj) {
    MatrixTransform transform;
    s16 jointSlot;
    s16 cornerIndex;
    int vertexBase;
    ObjModel* model;
    u32 jointId;
    u32 plane;
    u8* jointMatrix;
    const Vec3f* cornersYZ;
    const Vec3f* cornersXZ;
    const Vec3f* cornersXY;
    void** updateBufferCursor;
    void** drawBufferCursor;
    int bufferIndex;
    f32 jointPositionScale;
    f32 one;
    f32 zero;
    f32 jointX;
    f32 jointY;
    f32 jointZ;

    if (mainGetBit(GAMEBIT_TRICKYCURVE_PLAYER_HIT) != 0) {
        mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 0);
        gBoneParticleEffectTimer = 0xf;
        Sfx_PlayFromObject(obj, SFXTRIG_id_281);
    }
    model = (ObjModel*)obj->anim.banks[obj->anim.bankIndex];
    if (gBoneParticleStageIndex > 6) {
        gBoneParticleStageIndex = 0;
    }
    if (gBoneParticleJointIndex > model->file->jointCount - 1) {
        gBoneParticleJointIndex = 0;
    }
    gBoneParticleScrollOffset = gBoneParticleScrollOffset + framesThisStep;
    if (gBoneParticleScrollOffset > 0x1f) {
        gBoneParticleScrollOffset = gBoneParticleScrollOffset - 0x1f;
    }
    gBoneParticleDrift = gBoneParticleDriftVelocity[0] * timeDelta + gBoneParticleDrift;
    if (gBoneParticleDrift > 500.0f) {
        gBoneParticleDriftVelocity[0] *= -1.0f;
        gBoneParticleDrift = 500.0f;
        Sfx_PlayFromObject(obj, SFXTRIG_id_282);
    } else if (gBoneParticleDrift < -500.0f) {
        gBoneParticleDriftVelocity[0] *= -1.0f;
        gBoneParticleDrift = -500.0f;
        Sfx_PlayFromObject(obj, SFXTRIG_id_282);
    }
    bufferIndex = 0;
    drawBufferCursor = gBoneParticleEffectBuffers;
    updateBufferCursor = gBoneParticleEffectBuffers;
    for (; bufferIndex < BONE_PARTICLE_EFFECT_BUFFER_COUNT; bufferIndex++) {
        if (bufferIndex != 5) {
            gBoneParticleStageIndex = bufferIndex;
            vertexBase = 0;
            jointSlot = 0;
            zero = (0.0f);
            one = (1.0f);
            jointPositionScale = 20.02f;
            while (jointSlot < 5) {
                transform.x = zero;
                transform.y = zero;
                transform.z = zero;
                transform.scale = one;
                transform.rotZ = 0;
                transform.rotY = 0;
                transform.rotX = 0;
                jointMatrix = model->jointMatrices[model->bufferFlags & 1];
                jointId = gBoneParticleJointIds[gBoneParticleStageIndex][jointSlot];
                /* Retail advances by 16 matrix rows per joint in this renderer. */
                jointMatrix = (u8*)((MtxPtr)jointMatrix + (jointId << 4));
                jointX = (*(Mtx44*)jointMatrix)[3][0] + playerMapOffsetX;
                jointY = (*(Mtx44*)jointMatrix)[3][1];
                jointZ = (*(Mtx44*)jointMatrix)[3][2] + playerMapOffsetZ;
                jointX = jointX - obj->anim.localPosX;
                jointY = jointY - obj->anim.localPosY;
                jointZ = jointZ - obj->anim.localPosZ;
                jointX = jointX * jointPositionScale;
                if (jointId == 0x1d || jointId == 0x1d) {
                    jointY = 20.02f * (8.0f + jointY);
                } else {
                    jointY = jointY * jointPositionScale;
                }
                jointZ = jointZ * jointPositionScale;
                Matrix_TransformPoint((f32*)jointMatrix, transform.x, transform.y, transform.z, &transform.x, &transform.y, &transform.z);
                cornerIndex = 0;
                cornersYZ = gBoneParticleCornersYZ;
                cornersXZ = gBoneParticleCornersXZ;
                cornersXY = gBoneParticleCornersXY;
                while (cornerIndex < 4) {
                    f32 xyScale;
                    jointId = gBoneParticleJointIds[gBoneParticleStageIndex][jointSlot];
                    plane = gBoneParticleJointPlanes[jointId];
                    if (plane == 0) {
                        transform.x = cornersYZ->x * (xyScale = gBoneParticleJointXYScales[jointId]);
                        transform.y = cornersYZ->y * xyScale;
                        transform.z = cornersYZ->z * gBoneParticleJointZScales[jointId];
                    } else if (plane == 1) {
                        transform.x = cornersXZ->x * (xyScale = gBoneParticleJointXYScales[jointId]);
                        transform.y = cornersXZ->y * xyScale;
                        transform.z = cornersXZ->z * gBoneParticleJointZScales[jointId];
                    } else if (plane == 2) {
                        transform.x = cornersXY->x * (xyScale = gBoneParticleJointXYScales[jointId]);
                        transform.y = cornersXY->y * xyScale;
                        transform.z = cornersXY->z * gBoneParticleJointZScales[jointId];
                    }
                    Matrix_TransformPoint((f32*)jointMatrix, transform.x, transform.y, transform.z, &transform.x, &transform.y, &transform.z);
                    transform.x = transform.x + playerMapOffsetX;
                    transform.z = transform.z + playerMapOffsetZ;
                    ((LightmapVertex*)*updateBufferCursor)[cornerIndex + vertexBase].x = jointX + (transform.x - obj->anim.localPosX);
                    ((LightmapVertex*)*updateBufferCursor)[cornerIndex + vertexBase].y = jointY + (transform.y - obj->anim.localPosY);
                    ((LightmapVertex*)*updateBufferCursor)[cornerIndex + vertexBase].z = jointZ + (transform.z - obj->anim.localPosZ);
                    ((LightmapVertex*)*updateBufferCursor)[cornerIndex + vertexBase].a = 0x9b;
                    ((LightmapVertex*)*updateBufferCursor)[cornerIndex + vertexBase].t =
                        (s16)(gBoneParticleInitVertices[cornerIndex + vertexBase].t -
                              (gBoneParticleScrollOffset << 2));
                    cornersYZ++;
                    cornersXZ++;
                    cornersXY++;
                    cornerIndex += 1;
                }
                vertexBase += 4;
                jointSlot += 1;
            }
        }
        updateBufferCursor += 1;
    }
    transform.x = obj->anim.localPosX;
    transform.y = obj->anim.localPosY;
    transform.z = obj->anim.localPosZ;
    transform.scale = 0.0495f;
    setTextColor(ctx, 0xff, 0xff, 0xff, 0xff);
    if (gBoneParticleEffectTimer != 0) {
        (*gPartfxInterface)->spawnObject(obj, BONE_PARTICLE_EFFECT_PARTFX, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, BONE_PARTICLE_EFFECT_PARTFX, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, BONE_PARTICLE_EFFECT_PARTFX, NULL, 1, -1, NULL);
        if (randomGetRange(0, 1) != 0) {
            textureSelectAnimationFramePair(ctx, gBoneParticleTextureA, 0, 0, 0, 0, 0);
        } else {
            textureSelectAnimationFramePair(ctx, gBoneParticleTextureB, 0, 0, 0, 0, 0);
        }
        gBoneParticleEffectTimer -= framesThisStep;
        if (gBoneParticleEffectTimer < 0) {
            gBoneParticleEffectTimer = 0;
        }
    } else {
        textureSelectAnimationFramePair(ctx, gBoneParticleTextureA, 0, 0, 0, 0, 0);
    }
    Camera_LoadModelViewMatrix((int)ctx, renderParam, &transform, 1.0f, 0.0f, NULL);
    GXSetCullMode(GX_CULL_NONE);
    _textSetColor(ctx, 0xff, 0xff, 0xff, 0xff);
    gxTevResetStages();
    gxTevTextureTimesRasStage();
    gxTevModulateColor1Stage();
    gxTevCommitStages();
    gxSetAlphaBlendZTest();
    {
        int i;
        i = 0;
        do {
            lightmapDrawTriangleList(*drawBufferCursor, (u8*)gBoneParticleTriangles, 0x20);
            drawBufferCursor += 1;
            i += 1;
        } while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    }
    gBoneParticleBufferFlip = 1 - gBoneParticleBufferFlip;
}

void boneParticleEffect_func06_nop(void) {
}







void boneParticleEffect_spawnAtBones(GameObject* obj, int effectId, void* extraArg, u8 probability, const PartFxSpawnParams* spawnParams) {
    ObjModel* model;
    int jointIndex;
    PartFxSpawnParams params;

    model = Obj_GetActiveModel(obj);
    for (jointIndex = 0; jointIndex < model->file->jointCount; jointIndex++) {
        if (randomGetRange(1, 0x64) <= probability) {
            MtxPtr jointMatrix;
            params.posX = (0.0f);
            params.posY = (0.0f);
            params.posZ = (0.0f);
            params.scale = (1.0f);
            params.unk4 = 0;
            params.unk2 = 0;
            params.unk0 = 0;
            jointMatrix = (MtxPtr)ObjModel_GetJointMatrix((u8*)model, jointIndex);
            PSMTXMultVec(jointMatrix, &params.pos, &params.pos);
            params.posX = params.posX - (obj)->anim.worldPosX;
            params.posY = params.posY - (obj)->anim.worldPosY;
            params.posZ = params.posZ - (obj)->anim.worldPosZ;
            params.posX = params.posX + playerMapOffsetX;
            params.posZ = params.posZ + playerMapOffsetZ;
            if (spawnParams != NULL) {
                params.scale = spawnParams->scale;
                params.unk0 = spawnParams->unk0;
                params.unk4 = spawnParams->unk4;
                params.unk2 = spawnParams->unk2;
                params.effectParam = spawnParams->effectParam;
            } else {
                params.scale = (1.0f);
                params.unk0 = 0;
                params.unk4 = 0;
                params.unk2 = 0;
                params.effectParam = 0;
            }
            (*gPartfxInterface)->spawnObject(obj, effectId, &params, 2, -1, extraArg);
        }
    }
}

void boneParticleEffect_func04_nop(void) {
}

void boneParticleEffect_func03_nop(void) {
}

void boneParticleEffect_release(void) {
    int bufferIndex;
    for (bufferIndex = 0; bufferIndex < BONE_PARTICLE_EFFECT_BUFFER_COUNT; bufferIndex++) {
        if (gBoneParticleEffectBuffers[bufferIndex] != NULL) {
            mm_free(gBoneParticleEffectBuffers[bufferIndex]);
        }
        gBoneParticleEffectBuffers[bufferIndex] = NULL;
    }
    if (gBoneParticleTextureA != NULL) {
        textureFree((Texture*)(gBoneParticleTextureA));
    }
    if (gBoneParticleTextureB != NULL) {
        textureFree((Texture*)(gBoneParticleTextureB));
    }
}

void boneParticleEffect_initialise(void) {
    int bufferIndex;
    int vertexIndex;

    gBoneParticleTextureA = textureLoadAsset(BONE_PARTICLE_TEXTURE_A_ID);
    gBoneParticleTextureB = textureLoadAsset(BONE_PARTICLE_TEXTURE_B_ID);
    gBoneParticleEffectBuffers[0] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[1] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[2] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[3] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[4] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[5] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[6] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    for (bufferIndex = 0; bufferIndex < BONE_PARTICLE_EFFECT_BUFFER_COUNT; bufferIndex++) {
        for (vertexIndex = 0; vertexIndex < BONE_PARTICLE_EFFECT_SLOT_COUNT; vertexIndex++) {
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].x = gBoneParticleInitVertices[vertexIndex].x;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].y = gBoneParticleInitVertices[vertexIndex].y;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].z = gBoneParticleInitVertices[vertexIndex].z;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].s = gBoneParticleInitVertices[vertexIndex].s;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].t = gBoneParticleInitVertices[vertexIndex].t;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].r = gBoneParticleInitVertices[vertexIndex].r;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].g = gBoneParticleInitVertices[vertexIndex].g;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].b = gBoneParticleInitVertices[vertexIndex].b;
            ((LightmapVertex*)gBoneParticleEffectBuffers[bufferIndex])[vertexIndex].a = 0xff;
        }
    }
}


BoneParticleEffectDllInterface boneParticleEffect_funcs = {
    0,
    0,
    0,
    0x00080000,
    boneParticleEffect_initialise,
    boneParticleEffect_release,
    0,
    boneParticleEffect_func03_nop,
    boneParticleEffect_func04_nop,
    (ObjectDescriptorCallback)boneParticleEffect_spawnAtBones,
    boneParticleEffect_func06_nop,
    (ObjectDescriptorCallback)boneParticleEffect_update,
    boneParticleEffect_func08_nop,
    0,
};
