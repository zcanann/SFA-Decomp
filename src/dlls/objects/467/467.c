/*
 * DLL 0x1D3 - world-map models, paths, presentation effects, and orbiting
 * scenery.
 */
#include "dlls/objects/467.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/stream_api.h"
#include "main/camera.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/objfx.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gx_scissor_api.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/screen_transition.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define GREAT_FOX_EFFECT_COUNT 10

/*
 * World-map object IDs resolved through the active-target OBJECTS.bin and
 * OBJINDEX.bin. The WORLDOBJ_SUN_OBJ case spawns 11 WORLDOBJ_SUNRAY_OBJ
 * children with random rotation and per-axis spin.
 *
 * WORLDOBJ_ASTEROID_OBJ belongs to slot 0x1D4, WORLDOBJ_COMM_OBJ belongs to
 * slot 0x0C6, and WORLDOBJ_SKYSCAPE_OBJ has no retail DLL assignment. Their
 * cases are retained because this TU's callbacks explicitly handle those IDs.
 * WORLDcloudl is kept truncated because retail supplies no longer name.
 */
#define WORLDOBJ_CLOUDRUNNER_OBJ 0x5d5
#define WORLDOBJ_DRAGONROCK_OBJ  0x5d6
#define WORLDOBJ_WALLEDCITY_OBJ  0x5d7
#define WORLDOBJ_DARKICE_OBJ     0x5d8
#define WORLDOBJ_SUNRAY_OBJ      0x5da
#define WORLDOBJ_SUNFLARE_OBJ    0x5db
#define WORLDOBJ_CLOUDL_OBJ      0x5dc
#define WORLDOBJ_PATH1_OBJ       0x5dd
#define WORLDOBJ_ARWING_OBJ      0x5de
#define WORLDOBJ_GREATFOX_OBJ    0x5df
#define WORLDOBJ_SUN_OBJ         0x5e2
#define WORLDOBJ_PEPPER_OBJ      0x5e3
#define WORLDOBJ_PATH2_OBJ       0x5ed
#define WORLDOBJ_PATH3_OBJ       0x5ee
#define WORLDOBJ_PATH4_OBJ       0x5ef
#define WORLDOBJ_PATH5_OBJ       0x5f0
#define WORLDOBJ_PATH6_OBJ       0x5f1
#define WORLDOBJ_PATH7_OBJ       0x5f2
#define WORLDOBJ_PATH8_OBJ       0x5f3
#define WORLDOBJ_ASTEROID_OBJ    0x5f4
#define WORLDOBJ_SKYSCAPE_OBJ    0x5f5
#define WORLDOBJ_COMM_OBJ        0x602
#define WORLDOBJ_ASTEROIDGEN_OBJ 0x61e
#define WORLDOBJ_ARROW_OBJ       0x740
#define WORLDOBJ_COMET_OBJ       0x80f

typedef struct GreatFoxFxEntry {
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    f32 effectScale;
    u8 effectType;
    u8 mask;
    u8 unknown12[2];
} GreatFoxFxEntry;

STATIC_ASSERT(offsetof(GreatFoxFxEntry, offsetX) == 0x00);
STATIC_ASSERT(offsetof(GreatFoxFxEntry, offsetY) == 0x04);
STATIC_ASSERT(offsetof(GreatFoxFxEntry, offsetZ) == 0x08);
STATIC_ASSERT(offsetof(GreatFoxFxEntry, effectScale) == 0x0C);
STATIC_ASSERT(offsetof(GreatFoxFxEntry, effectType) == 0x10);
STATIC_ASSERT(offsetof(GreatFoxFxEntry, mask) == 0x11);
STATIC_ASSERT(sizeof(GreatFoxFxEntry) == 0x14);

extern GreatFoxFxEntry gGreatFoxEffects[GREAT_FOX_EFFECT_COUNT];
extern f32 gWorldObjAdvanceMoveTable[4];

u8 gWorldObjVariantAlphaTable[8] = {0xFF, 0x99, 0x1A, 0, 0, 0, 0, 0};
int gWorldObjEffectRenderDelay;
GameObject* gWorldObjEffectTargetObj;

void worldobj_spawnGreatFoxEffects(GameObject* obj) {
    WorldObjEffectParams params;
    u8 i;
    f32 scale;

    for (i = 0; i < GREAT_FOX_EFFECT_COUNT; i++) {
        scale = obj->anim.rootMotionScale;
        params.offsetX = 0.64f * (scale * gGreatFoxEffects[i].offsetX);
        params.offsetY = 0.64f * (scale * gGreatFoxEffects[i].offsetY);
        params.offsetZ = 0.64f * (scale * gGreatFoxEffects[i].offsetZ);
        objfx_spawnMaskedHitEffect(obj, scale * gGreatFoxEffects[i].effectScale, 3, gGreatFoxEffects[i].effectType,
                                   gGreatFoxEffects[i].mask, &params);
    }
    params.effectScale = -1.0f;
    params.offsetX = 0.64f * (-0.823f * obj->anim.rootMotionScale);
    params.offsetY = 0.64f * (-0.084f * obj->anim.rootMotionScale);
    params.offsetZ = 0.64f * (-2.6f * obj->anim.rootMotionScale);
    objfx_spawnLightPulse(obj, 0.025f * obj->anim.rootMotionScale, 1, 0, 6, 0.7f, &params);
    params.offsetX = 0.0f;
    params.offsetY = 0.64f * (0.209f * obj->anim.rootMotionScale);
    params.offsetZ = 0.64f * (-3.6f * obj->anim.rootMotionScale);
    objfx_spawnLightPulse(obj, 0.025f * obj->anim.rootMotionScale, 1, 0, 6, 0.5f, &params);
    params.offsetX = 0.64f * (0.823f * obj->anim.rootMotionScale);
    params.offsetY = 0.64f * (-0.084f * obj->anim.rootMotionScale);
    params.offsetZ = 0.64f * (-2.6f * obj->anim.rootMotionScale);
    objfx_spawnLightPulse(obj, 0.025f * obj->anim.rootMotionScale, 1, 0, 6, 0.7f, &params);
}

void worldobj_spawnAsteroidBatch(GameObject* obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId) {
    s16 rot[3];
    f32 vec[3];
    WorldObjEffectParams params;
    int i;
    f32 base;

    for (i = 0, base = 0.0f; i < count; i++) {
        vec[0] = base;
        vec[1] = (f32)randomGetRange(xMin, xMax);
        vec[2] = (f32)randomGetRange(yMin, yMax);
        rot[0] = 0;
        rot[1] = 0;
        rot[2] = randomGetRange(-0x7fff, 0x7fff);
        vecRotateZXY(rot, vec);
        params.offsetX = vec[0];
        params.offsetY = vec[1];
        params.offsetZ = vec[2];
        params.dispatchTimer = 0x64;
        (*gPartfxInterface)->spawnObject((void*)obj, dispatchId, &params, 2, -1, NULL);
    }
}

int worldobj_getExtraSize(void) {
    return sizeof(WorldObjState);
}

int worldobj_getObjectTypeId(GameObject* obj) {
    if (((WorldObjSetup*)obj->anim.placementData)->base.objectId != WORLDOBJ_PEPPER_OBJ) {
        return 0x0;
    }
    return 0x8;
}

void worldobj_free(GameObject* obj) {
    WorldObjState* state = obj->extra;
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    (*gExpgfxInterface)->freeSource((int)obj);
}

void worldobj_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    WorldObjState* state = obj->extra;
    int objectId = ((WorldObjSetup*)obj->anim.placementData)->base.objectId;

    if (objectId == WORLDOBJ_SKYSCAPE_OBJ) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        return;
    }
    if (visible == 0) {
        return;
    }
    switch (objectId) {
    case WORLDOBJ_ASTEROIDGEN_OBJ:
        return;
    case WORLDOBJ_ARWING_OBJ:
        if (state->effectState == 0) {
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        }
        break;
    case WORLDOBJ_PEPPER_OBJ:
        if (randomGetRange(0, 0x19) != 0 && state->effectState != 0) {
            GXSetScissor(0x1e0, 0x32, 0x82, 0x96);
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            Camera_ApplyCurrentViewport((void*)renderArg2);
        }
        break;
    case WORLDOBJ_ARROW_OBJ:
        if (state->effectState != 0 && getWorldMapVoiceoverTimer() == 0 &&
            (*gScreenTransitionInterface)->isFinished() != 0) {
            if (gWorldObjEffectRenderDelay != 0) {
                gWorldObjEffectRenderDelay = gWorldObjEffectRenderDelay - 1;
            } else {
                objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            }
        } else {
            gWorldObjEffectRenderDelay = 2;
        }
        break;
    case WORLDOBJ_COMET_OBJ:
        if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0) {
            queueGlowRender(state->light);
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        break;
    case WORLDOBJ_SUNRAY_OBJ:
    case WORLDOBJ_SUNFLARE_OBJ:
    default:
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        break;
    }
}

void worldobj_hitDetect(void) {
}

void worldobj_update(GameObject* obj) {
    s16 rot[3];
    f32 vec[10];
    WorldObjState* state;
    WorldObjSetup* setup;
    GameObject* objA;
    GameObject* objB;
    int tmp;
    u8 i;
    GameObject* child;
    ObjTextureRuntimeSlot* tex;
    Camera* view;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;
    f32 sv;

    state = obj->extra;
    setup = (WorldObjSetup*)obj->anim.placementData;

    switch (setup->base.objectId) {
    case WORLDOBJ_COMET_OBJ:
        if (state->orbitAngle > 0x8000 || state->orbitAngle < 0) {
            if (state->light != NULL) {
                modelLightStruct_setEnabled(state->light, 0, 1.0f);
            }
            tmp = (int)((f32)obj->anim.alpha - 4.0f * timeDelta);
            if (tmp < 0) {
                tmp = 0;
            }
            obj->anim.alpha = tmp;
            if (obj->anim.alpha == 0) {
                Obj_FreeObject(obj);
            }
        } else {
            objA = ObjList_FindObjectById(0x42fe7);
            objB = ObjList_FindObjectById(0x4305a);
            if (objA != NULL && objB != NULL) {
                state->orbitAngle = (int)((f32)state->spinXStep * timeDelta + state->orbitAngle);
                vec[0] = state->orbitRadiusX * mathCosf(3.1415927f * state->orbitAngle / 32768.0f);
                vec[1] = 0.0f;
                vec[2] = state->orbitRadiusZ * mathSinf(3.1415927f * state->orbitAngle / 32768.0f);
                dx = objB->anim.localPosX - objA->anim.localPosX;
                dz = objB->anim.localPosZ - objA->anim.localPosZ;
                rot[0] = getAngle(dx, dz);
                rot[1] = 0;
                rot[2] = 0;
                vecRotateZXY(rot, vec);
                obj->anim.localPosX = vec[0] + (objA->anim.localPosX - dx);
                obj->anim.localPosY =
                    state->orbitStartY + state->orbitAngle * (state->orbitEndY - state->orbitStartY) / 16384.0f;
                obj->anim.localPosZ = vec[2] + (objA->anim.localPosZ - dz);
            }
            obj->anim.velocityX = oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX);
            obj->anim.velocityZ = oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ);
            vec[0] = obj->anim.velocityX;
            vec[1] = 0.0f;
            vec[2] = obj->anim.velocityZ;
            objfx_spawnFlaggedTrailBurst(obj, 0.5f * state->scale, 2, 0xdf, 8, vec);
            obj->anim.rotX = 256.0f * timeDelta + (f32)obj->anim.rotX;
            obj->anim.rotY = 192.0f * timeDelta + (f32)obj->anim.rotY;
            if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0) {
                modelLightStruct_updateGlowAlpha(state->light);
            }
        }
        break;
    case WORLDOBJ_ARROW_OBJ:
        ObjAnim_AdvanceCurrentMove(obj, 0.017f, timeDelta, NULL);
        obj->anim.rotX = 256.0f * timeDelta + (f32)obj->anim.rotX;
        break;
    case WORLDOBJ_CLOUDL_OBJ:
        if (obj->userData1 == 0) {
            obj->userData1 = (int)ObjList_FindObjectById(0x431dc);
            ObjLink_AttachChild(obj, (GameObject*)obj->userData1, 0);
        }
        if (obj->userData2 == 0) {
            obj->userData2 = (int)ObjList_FindObjectById(0x4325b);
            ObjLink_AttachChild(obj, (GameObject*)obj->userData2, 0);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL) {
            tmp = (s16)-tex->offsetS;
            tmp -= 2;
            if ((s16)tmp < 0) {
                tmp += 0x2710;
            }
            tex->offsetS = (s16)-tmp;
        }
        break;
    case WORLDOBJ_PATH1_OBJ:
    case WORLDOBJ_PATH2_OBJ:
    case WORLDOBJ_PATH3_OBJ:
    case WORLDOBJ_PATH4_OBJ:
    case WORLDOBJ_PATH5_OBJ:
    case WORLDOBJ_PATH6_OBJ:
    case WORLDOBJ_PATH7_OBJ:
    case WORLDOBJ_PATH8_OBJ:
        if (state->effectState == 2) {
            for (i = 0; i < 0x16; i++) {
                WorldObjPathSegmentWork* pathSegment = WorldObj_GetPathSegmentWork(state, i);
                ObjPath_GetPointWorldPosition(obj, i, &pathSegment->start.x, &pathSegment->start.y,
                                              &pathSegment->start.z, 0);
            }
        }
        break;
    case WORLDOBJ_SUN_OBJ:
        switch (setup->variant) {
        case 0:
            obj->anim.rotX += 0x64;
            break;
        case 1:
            obj->anim.rotY += 0x64;
            break;
        case 2:
            obj->anim.rotZ += 0x64;
            break;
        }
        break;
    case WORLDOBJ_SUNRAY_OBJ:
        obj->anim.rotX += state->spinXStep;
        obj->anim.rotY += state->spinYStep;
        obj->anim.rotZ += state->spinZStep;
        state->controlByte += 2;
        sv = mathCosf(3.1415927f * (f32)(s16)(state->controlByte << 8) / 32768.0f);
        obj->anim.rootMotionScale = 10.0f + 25.0f * (1.0f + sv);
        break;
    case WORLDOBJ_SUNFLARE_OBJ:
        obj->anim.rotX = 0x21a8;
        obj->anim.rootMotionScale = 200.0f;
        break;
    case WORLDOBJ_SKYSCAPE_OBJ:
        obj->anim.rotX += 1;
        break;
    case WORLDOBJ_COMM_OBJ:
        ObjAnim_AdvanceCurrentMove(obj, 0.005f, timeDelta, (ObjAnimEventList*)&vec[3]);
        break;
    case WORLDOBJ_PEPPER_OBJ:
        if (state->controlByte != obj->anim.bankIndex) {
            Obj_SetActiveModelIndex(obj, state->controlByte);
        }
        if (state->spinZStep != (gAudioStreamCurrentId != 0)) {
            if (gAudioStreamCurrentId != 0) {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
            }
        }
        state->spinZStep = gAudioStreamCurrentId != 0;
        ObjAnim_AdvanceCurrentMove(obj, gWorldObjAdvanceMoveTable[state->controlByte], timeDelta,
                                   (ObjAnimEventList*)&vec[3]);
        if (state->effectState == 0 && state->light != NULL) {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
        break;
    case WORLDOBJ_GREATFOX_OBJ:
        worldobj_spawnGreatFoxEffects(obj);
        /* Fall through to the shared world-map model update. */
    case WORLDOBJ_CLOUDRUNNER_OBJ:
    case WORLDOBJ_DRAGONROCK_OBJ:
    case WORLDOBJ_WALLEDCITY_OBJ:
    case WORLDOBJ_DARKICE_OBJ:
        if (obj->userData2 == 0) {
            child = ObjList_FindObjectById(state->attachChildObjectId);
            if (child != NULL) {
                child->anim.rootMotionScale *= 0.5f;
                child->anim.alpha = 0x96;
                child->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjLink_AttachChild(obj, child, 0);
                obj->userData2 = 1;
            }
        }
        if (obj->userData1 != 0 && (void*)state->lookAtTargetRef != NULL) {
            view = Camera_GetCurrent();
            dx = view->x - obj->anim.localPosX;
            dy = view->y - obj->anim.localPosY;
            dz = view->z - obj->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (dist > 0.0f) {
                dx /= dist;
                dy /= dist;
                dz /= dist;
            }
            sv = 5.0f;
            ((GameObject*)state->lookAtTargetRef)->anim.localPosX = sv * dx + obj->anim.localPosX;
            ((GameObject*)state->lookAtTargetRef)->anim.localPosY = sv * dy + obj->anim.localPosY;
            ((GameObject*)state->lookAtTargetRef)->anim.localPosZ = sv * dz + obj->anim.localPosZ;
        }
        if (state->effectState != 0) {
            if (getWorldMapVoiceoverTimer() == 0 && (*gScreenTransitionInterface)->isFinished() != 0 &&
                gWorldObjEffectRenderDelay == 0) {
                if (state->light == NULL) {
                    state->light = objCreateLight(obj, 1);
                    if (state->light != NULL) {
                        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                        modelLightStruct_setPosition(state->light, 0.0f, 50.0f, 0.0f);
                        modelLightStruct_setDiffuseColor(state->light, 0xff, 0, 0, 0xff);
                        modelLightStruct_setDiffuseTargetColor(state->light, 0, 0, 0, 0xff);
                        modelLightStruct_setEnabled(state->light, 1, 0.0f);
                        modelLightStruct_setDistanceAttenuation(state->light, 80.0f, 100.0f);
                        modelLightStruct_startColorFade(state->light, 2, 0x3c);
                        modelLightStruct_setDirection(state->light, 0.0f, -1.0f, 0.0f);
                    }
                }
            } else if (state->light != NULL) {
                ModelLightStruct_free(state->light);
                state->light = NULL;
            }
            ((WorldObjState*)gWorldObjEffectTargetObj->extra)->effectState = 1;
            gWorldObjEffectTargetObj->anim.localPosX = obj->anim.localPosX;
            gWorldObjEffectTargetObj->anim.localPosY = 20.0f + obj->anim.localPosY;
            gWorldObjEffectTargetObj->anim.localPosZ = obj->anim.localPosZ;
            objA = ObjList_FindObjectById(0x4300c);
            if (objA != NULL && (objA->anim.flags & OBJANIM_FLAG_HIDDEN)) {
                Obj_SetActiveModelIndex(gWorldObjEffectTargetObj, 1);
            } else {
                Obj_SetActiveModelIndex(gWorldObjEffectTargetObj, 0);
            }
        } else if (state->light != NULL) {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
        break;
    case WORLDOBJ_ASTEROIDGEN_OBJ:
        obj->anim.rotY = 0x3448;
        obj->anim.rotX = 0x4000;
        switch (setup->variant) {
        case 0:
            obj->anim.rotZ -= 0xe;
            break;
        case 1:
            obj->anim.rotZ -= 0x10;
            break;
        case 2:
            obj->anim.rotZ -= 0x13;
            break;
        }
        if (state->controlByte == 0) {
            switch (setup->variant) {
            case 0:
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x4b, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x32, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x32, 0x6f8);
                break;
            case 1:
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x4b, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x32, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x32, 0x6f8);
                break;
            case 2:
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x32, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x19, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x19, 0x6f8);
                break;
            }
            state->controlByte = 1;
        }
        break;
    }
}

void worldobj_init(GameObject* obj, const WorldObjSetup* setup) {
    WorldObjState* state = obj->extra;
    GameObject* objA;
    GameObject* objB;
    ObjPlacement* placement;
    int idx;
    u8 i;
    f32 base;
    f32 dist;

    switch (setup->base.objectId) {
    case WORLDOBJ_PATH1_OBJ:
    case WORLDOBJ_PATH2_OBJ:
    case WORLDOBJ_PATH3_OBJ:
    case WORLDOBJ_PATH4_OBJ:
    case WORLDOBJ_PATH5_OBJ:
    case WORLDOBJ_PATH6_OBJ:
    case WORLDOBJ_PATH7_OBJ:
    case WORLDOBJ_PATH8_OBJ:
        state->effectState = 0;
        break;
    case WORLDOBJ_COMET_OBJ:
        objA = ObjList_FindObjectById(0x42fe7);
        objB = ObjList_FindObjectById(0x4305a);
        base = objB->anim.localPosY - objA->anim.localPosY;
        state->orbitStartY = (objA->anim.localPosY - base) + (f32)randomGetRange(-0x3e8, 0x3e8);
        state->orbitEndY = objB->anim.localPosY + (f32)randomGetRange(-5, 5);
        state->scale = 0.5f * ((f32)randomGetRange(0, 0x64) / 100.0f) + 0.5f;
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * state->scale;
        state->spinXStep = randomGetRange(0xa, 0x19);
        if (randomGetRange(0, 1) != 0) {
            state->spinXStep = -state->spinXStep;
            state->orbitAngle = 0x8000;
        }
        base = (f32)randomGetRange(0xc8, 0x190);
        dist = Vec_distance(&objB->anim.worldPosX, &objA->anim.worldPosX);
        state->orbitRadiusZ = 2.0f * dist + base;
        state->orbitRadiusX = state->orbitRadiusZ * (0.3f * ((f32)randomGetRange(0, 0x64) / 100.0f) + 0.3f);
        state->light = objCreateLight(obj, 1);
        if (state->light != NULL) {
            modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0xff, 0xff, 0);
            modelLightStruct_setDistanceAttenuation(state->light, 50.0f, 70.0f);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0xff, 0xff, 0x82, 40.0f * state->scale);
            modelLightStruct_setGlowProjectionRadius(state->light, 200.0f);
        }
        break;
    case WORLDOBJ_SKYSCAPE_OBJ:
        obj->anim.rootMotionScale = 1000.0f;
        break;
    case WORLDOBJ_PEPPER_OBJ:
        state->controlByte = 0;
        state->spinZStep = 0;
        break;
    case WORLDOBJ_CLOUDL_OBJ:
        break;
    case WORLDOBJ_ASTEROID_OBJ:
        break;
    case WORLDOBJ_SUN_OBJ:
        idx = setup->variant;
        Obj_SetActiveModelIndex(obj, idx);
        obj->anim.alpha = gWorldObjVariantAlphaTable[idx];
        for (i = 0; i < 0xb; i++) {
            placement = (ObjPlacement*)obj->anim.placementData;
            if ((u8)Obj_CanSetupObject() != 0) {
                ObjPlacement* childPlacement = Obj_AllocObjectSetup(0x20, WORLDOBJ_SUNRAY_OBJ);
                childPlacement->color[0] = placement->color[0];
                childPlacement->color[2] = placement->color[2];
                childPlacement->color[1] = placement->color[1];
                childPlacement->color[3] = placement->color[3];
                childPlacement->posX = obj->anim.localPosX;
                childPlacement->posY = obj->anim.localPosY;
                childPlacement->posZ = obj->anim.localPosZ;
                objSetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1, NULL);
            }
        }
        break;
    case WORLDOBJ_SUNRAY_OBJ:
        obj->anim.rotZ = randomGetRange(0, 0xffff);
        obj->anim.rotY = randomGetRange(0, 0xffff);
        obj->anim.rotX = randomGetRange(0, 0xffff);
        state->controlByte = randomGetRange(0, 0xff);
        state->spinZStep = randomGetRange(-0xa, 0xa);
        state->spinYStep = randomGetRange(-0xa, 0xa);
        state->spinXStep = randomGetRange(-0xa, 0xa);
        break;
    case WORLDOBJ_ASTEROIDGEN_OBJ:
        state->controlByte = 0;
        break;
    case WORLDOBJ_ARROW_OBJ:
        state->effectState = 0;
        gWorldObjEffectTargetObj = obj;
        break;
    case WORLDOBJ_CLOUDRUNNER_OBJ:
        state->lookAtTargetRef = 0x4aaf7;
        state->attachChildObjectId = 0x4ab08;
        break;
    case WORLDOBJ_DRAGONROCK_OBJ:
        state->lookAtTargetRef = 0x4ab03;
        state->attachChildObjectId = 0x4ab09;
        break;
    case WORLDOBJ_DARKICE_OBJ:
        state->lookAtTargetRef = 0x4ab04;
        state->attachChildObjectId = 0x4ab0a;
        break;
    case WORLDOBJ_WALLEDCITY_OBJ:
        state->lookAtTargetRef = 0x4ab05;
        state->attachChildObjectId = 0x4ab0b;
        break;
    }
}

void worldobj_release(void) {
}

void worldobj_initialise(void) {
}

f32 gWorldObjAdvanceMoveTable[4] = {0.02f, 0.01f, 0.01f, 0.02f};

GreatFoxFxEntry gGreatFoxEffects[GREAT_FOX_EFFECT_COUNT] = {
    {0.0f, 1.669f, -2.582f, 0.01f, 0x06, 0x10, {0x00, 0x00}},
    {2.738f, 0.793f, -1.954f, 0.01f, 0x09, 0x20, {0x00, 0x00}},
    {2.73f, 0.779f, -0.952f, 0.01f, 0x07, 0x20, {0x00, 0x00}},
    {2.795f, -0.974f, -1.945f, 0.01f, 0x09, 0x20, {0x00, 0x00}},
    {2.812f, -1.008f, -0.955f, 0.01f, 0x07, 0x20, {0x00, 0x00}},
    {-2.738f, 0.793f, -1.97f, 0.01f, 0x09, 0x20, {0x00, 0x00}},
    {-2.73f, 0.779f, -0.952f, 0.01f, 0x07, 0x20, {0x00, 0x00}},
    {-2.795f, -0.974f, -1.971f, 0.01f, 0x09, 0x20, {0x00, 0x00}},
    {-2.812f, -1.008f, -0.955f, 0.01f, 0x07, 0x20, {0x00, 0x00}},
    {0.0f, 0.405f, 2.952f, 0.01f, 0x08, 0x40, {0x00, 0x00}},
};

ObjectDescriptor gWorldObjObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)worldobj_initialise,
    (ObjectDescriptorCallback)worldobj_release,
    0,
    (ObjectDescriptorCallback)worldobj_init,
    (ObjectDescriptorCallback)worldobj_update,
    (ObjectDescriptorCallback)worldobj_hitDetect,
    (ObjectDescriptorCallback)worldobj_render,
    (ObjectDescriptorCallback)worldobj_free,
    (ObjectDescriptorCallback)worldobj_getObjectTypeId,
    worldobj_getExtraSize,
};
