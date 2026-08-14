/*
 * DIM2SnowBal (DLL 0x1D7) - rolling snowball projectile for Snowhorn Wastes 2.
 * It follows a Hermite spline supplied by DIM2PathGen, then enters ballistic
 * physics at the path's launch node. Floor impacts fade and eventually free
 * the object; the first impact also notifies the active SharpClaw.
 */
#include "dlls/objects/471_DIM2SnowBal.h"
#include "dlls/objects/472_DIM2PathGen.h"

#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/curve.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIM2_SNOWBALL_SHARPCLAW_SEQUENCE_ID 214
#define DIM2_SNOWBALL_IMPACT_PARTFX_ID      518
#define DIM2_SNOWBALL_LAUNCH_GAME_BIT       0x288

#define DIM2_SNOWBALL_FLAG_PATH_INITIALIZED 0x01
#define DIM2_SNOWBALL_FLAG_BALLISTIC        0x02
#define DIM2_SNOWBALL_FLAG_FADING_IN        0x04
#define DIM2_SNOWBALL_FLAG_FADING_OUT       0x08
#define DIM2_SNOWBALL_FLAG_IMPACTED         0x10

static inline GameObject* dim2snowball_findSharpClaw(GameObject** objects, int* objectIndex, int* objectCount) {
    GameObject** object = &objects[*objectIndex];

    for (; *objectIndex < *objectCount; object++, (*objectIndex)++) {
        if ((*object)->anim.romDefNo == DIM2_SNOWBALL_SHARPCLAW_SEQUENCE_ID) {
            return objects[*objectIndex];
        }
    }

    return NULL;
}

int dim2snowball_getExtraSize(void) {
    return sizeof(Dim2SnowBallState);
}

int dim2snowball_getObjectTypeId(void) {
    return 0;
}

void dim2snowball_free(void) {
}

void dim2snowball_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim2snowball_hitDetect(void) {
}

void dim2snowball_update(GameObject* obj) {
    Dim2SnowBallState* state = obj->extra;
    TrackGroundHit** groundHits;
    int objectCount;
    int objectIndex;
    PartFxSpawnParams particleParams;
    f32 damping;

    if ((state->flags & DIM2_SNOWBALL_FLAG_FADING_IN) != 0) {
        int alpha = obj->anim.alpha + framesThisStep * 2;

        if (alpha > 255) {
            alpha = 255;
            state->flags &= ~DIM2_SNOWBALL_FLAG_FADING_IN;
        }
        obj->anim.alpha = alpha;
    } else if ((state->flags & DIM2_SNOWBALL_FLAG_FADING_OUT) != 0) {
        int alpha = obj->anim.alpha - framesThisStep * 2;

        if (alpha < 0) {
            alpha = 0;
            state->flags &= ~DIM2_SNOWBALL_FLAG_FADING_OUT;
        }
        obj->anim.alpha = alpha;
    }

    if ((state->flags & DIM2_SNOWBALL_FLAG_PATH_INITIALIZED) == 0) {
        GameObject* pathGenerator = (GameObject*)state->pathGenerator;

        state->path.count = DIM2_PATH_GENERATOR_INTERFACE(pathGenerator)
                                ->getCurveVals(pathGenerator, &state->path.px, &state->path.py, &state->path.pz,
                                               &state->pathNodeData);
        state->path.dir = 0;
        state->path.eval = Curve_EvalHermite;
        state->path.coeffFn = Curve_BuildHermiteCoeffs;
        curvesMove(&state->path);
        state->flags |= DIM2_SNOWBALL_FLAG_PATH_INITIALIZED;
    }

    if ((state->flags & DIM2_SNOWBALL_FLAG_BALLISTIC) != 0) {
        if (obj->anim.localPosY < state->floorHeight) {
            obj->anim.velocityX = obj->anim.velocityX * (damping = 0.9f);
            obj->anim.velocityY = -0.1f;
            obj->anim.velocityZ = obj->anim.velocityZ * damping;

            if ((state->flags & DIM2_SNOWBALL_FLAG_IMPACTED) == 0) {
                GameObject** objects;
                GameObject* sharpClaw;

                obj->anim.velocityX = obj->anim.velocityX * (damping = 0.05f);
                obj->anim.velocityZ = obj->anim.velocityZ * damping;
                state->flags |= DIM2_SNOWBALL_FLAG_FADING_OUT | DIM2_SNOWBALL_FLAG_IMPACTED;
                objects = ObjList_GetObjects(&objectIndex, &objectCount);
                sharpClaw = dim2snowball_findSharpClaw(objects, &objectIndex, &objectCount);
                if (sharpClaw != NULL) {
                    (*(void (**)(GameObject*))(*(int*)sharpClaw->anim.dll + 0x20))(sharpClaw);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_nlite1_c);
            }

            particleParams.posX = obj->anim.localPosX;
            particleParams.posY = obj->anim.localPosY;
            particleParams.posZ = obj->anim.localPosZ;
            (*gPartfxInterface)->spawnObject(obj, DIM2_SNOWBALL_IMPACT_PARTFX_ID, &particleParams, 4, -1, NULL);
            if (obj->anim.alpha == 0) {
                Obj_FreeObject(obj);
                return;
            }
            objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                    obj->anim.velocityZ * timeDelta);
        } else {
            int collided;

            obj->anim.velocityX = obj->anim.velocityX * (damping = 0.98f);
            obj->anim.velocityY = obj->anim.velocityY - 0.1f * timeDelta;
            obj->anim.velocityZ = obj->anim.velocityZ * damping;
            objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                    obj->anim.velocityZ * timeDelta);
            collided = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 36.0f, 0, NULL, obj,
                                          8, -1, 0, 0);
            if (collided != 0) {
                obj->anim.velocityX = -obj->anim.velocityX;
                obj->anim.velocityZ = -obj->anim.velocityZ;
                obj->anim.velocityX = obj->anim.velocityX * (damping = 0.75f);
                obj->anim.velocityZ = obj->anim.velocityZ * damping;
            }
        }
    } else {
        int pathComplete = Curve_AdvanceAlongPath(&state->path, 2.1f);

        obj->anim.localPosX = state->path.sample[0];
        obj->anim.localPosY = (f32)(23.0 + state->path.sample[1]);
        obj->anim.localPosZ = state->path.sample[2];
        *(s16*)obj = getAngle(state->path.tangent[0], state->path.tangent[2]);
        obj->anim.rotY = obj->anim.rotY + framesThisStep * 800;
        obj->anim.velocityX = oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX);
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ);
        if (pathComplete != 0) {
            Obj_FreeObject(obj);
            return;
        }

        if (*(u8*)((char*)(int*)state->pathNodeData + (state->path.idx >> 2)) == 32) {
            if (mainGetBit(DIM2_SNOWBALL_LAUNCH_GAME_BIT) != 0) {
                int hitCount;

                state->flags |= DIM2_SNOWBALL_FLAG_BALLISTIC;
                hitCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                                &groundHits, 0, 0);
                state->floorHeight = obj->anim.localPosY;
                while (hitCount > 0) {
                    TrackGroundHit* groundHit;

                    hitCount--;
                    groundHit = groundHits[hitCount];
                    if (groundHit->height < obj->anim.localPosY) {
                        s8 surfaceType = (s8)groundHit->surfaceType;

                        if (surfaceType == 26 || surfaceType == 8) {
                            state->floorHeight = groundHit->height;
                            hitCount = 0;
                        }
                    }
                }
                obj->anim.velocityX = obj->anim.velocityX * (damping = 0.75f);
                obj->anim.velocityZ = obj->anim.velocityZ * damping;
            }
        }
    }

    if (obj->anim.alpha == 255) {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;

        if (hitState != NULL) {
            hitState->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            hitState->hitVolumePriority = 4;
            hitState->hitVolumeId = 2;
            hitState->objectHitMask = 16;
            hitState->skeletonHitMask = 16;
        }
    }
    Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_firlp6);
}

void dim2snowball_init(GameObject* obj, Dim2SnowBallPlacement* placement) {
    Dim2SnowBallState* state = obj->extra;

    state->targetObjectId = placement->targetObjectId;
    state->flags = (u8)(state->flags | DIM2_SNOWBALL_FLAG_FADING_IN);
    placement->targetObjectId = -1;
    *(s16*)obj = (s16)((s32)placement->rotationXByte << 8);
    obj->anim.alpha = 0;
    {
        ObjModelState* modelState = obj->anim.modelState;

        if (modelState != NULL) {
            modelState->flags |= 0xA10;
        }
    }
    state->pathGenerator = ObjList_FindObjectById(state->targetObjectId);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dim2snowball_release(void) {
}

void dim2snowball_initialise(void) {
}

ObjectDescriptor gDIM2SnowBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dim2snowball_initialise,
    (ObjectDescriptorCallback)dim2snowball_release,
    0,
    (ObjectDescriptorCallback)dim2snowball_init,
    (ObjectDescriptorCallback)dim2snowball_update,
    (ObjectDescriptorCallback)dim2snowball_hitDetect,
    (ObjectDescriptorCallback)dim2snowball_render,
    (ObjectDescriptorCallback)dim2snowball_free,
    (ObjectDescriptorCallback)dim2snowball_getObjectTypeId,
    dim2snowball_getExtraSize,
};
