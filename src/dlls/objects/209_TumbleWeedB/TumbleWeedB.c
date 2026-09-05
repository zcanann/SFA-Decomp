/*
 * Tumbleweed bush (DLL slot 209) and tumbleweed object (DLL slot 210).
 *
 * One translation unit for both: the bush manages its detachable pieces and
 * the shared motion helpers; the tumbleweed handles growth, rolling,
 * targeting, pickup, homing, effects, and detached-piece motion. The pieces
 * dedup their float pool into the bush groups and share its conversion bias.
 */
#include "dlls/objects/209_TumbleWeedB.h"
#include "dlls/objects/210.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/sky_interface.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/obj_message.h"

#define TUMBLEWEED_BUSH_SEQUENCE_A           0x28d
#define TUMBLEWEED_BUSH_SEQUENCE_B           0x3fd
#define TUMBLEWEED_BUSH_SEQUENCE_C           0x4b9
#define TUMBLEWEED_BUSH_SEQUENCE_D           0x4be
#define TUMBLEWEED_BUSH_SIBLING_A            0x39d
#define TUMBLEWEED_BUSH_SIBLING_C            0x4ba
#define TUMBLEWEED_BUSH_SIBLING_D            0x4c1
#define TUMBLEWEED_BUSH_OBJECT_GROUP         0x31
#define TUMBLEWEED_BUSH_MAX_SIBLINGS         7
#define TUMBLEWEED_BUSH_SIBLING_SETUP_SIZE   0x20
#define TUMBLEWEED_BUSH_SIBLING_SETUP_FLAGS  5
#define TUMBLEWEED_BUSH_ACTIVE_PIECE_PHASE   7
#define TUMBLEWEED_BUSH_HIT_EFFECT_ID        8
#define TUMBLEWEED_BUSH_HIT_COLOR_R          0xff
#define TUMBLEWEED_BUSH_HIT_COLOR_G          0xff
#define TUMBLEWEED_BUSH_HIT_COLOR_B          0x78
#define TUMBLEWEED_BUSH_ROTATION_CENTER      0x7f
#define TUMBLEWEED_BUSH_ROTATION_X_SHIFT     8
#define TUMBLEWEED_BUSH_ROTATION_YZ_SHIFT    7
#define TUMBLEWEED_BUSH_PIECE_SCALE          64.0f
#define TUMBLEWEED_BUSH_HIT_Y_MIN            -5.0f
#define TUMBLEWEED_BUSH_HIT_Y_MAX            100.0f
#define TUMBLEWEED_BUSH_NEAREST_INITIAL_DIST 3.4028235e38f
#define TUMBLEWEED_PIECE_HORIZONTAL_DAMPING  10.0f
#define TUMBLEWEED_PIECE_GROUND_CLEARANCE    7.0f
#define TUMBLEWEED_PIECE_GRAVITY             -0.17f
#define TUMBLEWEED_PIECE_ROTATION_DAMPING    100

f32 gTumbleweedBushHitCooldown;

s8 tumbleweedbush_spawnSibling(GameObject* obj) {
    TumbleweedBushState* state;
    TumbleweedBushPlacement* placement;
    int siblingSeqId;
    int objectIndex;
    int objectCount;
    f32 sunTime;
    int freePieceIndex;
    GameObject** objects;
    int siblingCount;
    TumbleweedBushPlacement* newPlacement;
    u8 canSetupObject;

    state = obj->extra;
    placement = (TumbleweedBushPlacement*)obj->anim.placementData;
    switch (obj->anim.romDefNo) {
    case TUMBLEWEED_BUSH_SEQUENCE_A:
        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0) {
            return -1;
        }
        siblingSeqId = TUMBLEWEED_BUSH_SIBLING_A;
        break;
    case TUMBLEWEED_BUSH_SEQUENCE_B:
        siblingSeqId = TUMBLEWEED_BUSH_SIBLING_B;
        break;
    case TUMBLEWEED_BUSH_SEQUENCE_C:
        siblingSeqId = TUMBLEWEED_BUSH_SIBLING_C;
        break;
    case TUMBLEWEED_BUSH_SEQUENCE_D:
        siblingSeqId = TUMBLEWEED_BUSH_SIBLING_D;
        break;
    }

    objectIndex = 0;
    freePieceIndex = -1;
    while (objectIndex < (int)state->pieceCount && freePieceIndex == -1) {
        if (state->pieceObjects[objectIndex] == NULL) {
            freePieceIndex = objectIndex;
        }
        objectIndex++;
    }
    if (freePieceIndex == -1) {
        return -1;
    }

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    siblingCount = 0;
    while (objectIndex < objectCount) {
        int currentIndex = *(int*)&objectIndex;

        objectIndex = currentIndex + 1;
        if (siblingSeqId == objects[currentIndex]->anim.romDefNo) {
            siblingCount++;
        }
    }
    if (siblingCount >= TUMBLEWEED_BUSH_MAX_SIBLINGS) {
        return -1;
    }
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return -1;
    }

    newPlacement = (TumbleweedBushPlacement*)Obj_AllocObjectSetup(TUMBLEWEED_BUSH_SIBLING_SETUP_SIZE, siblingSeqId);
    ((ObjPlacement*)newPlacement)->posX = obj->anim.localPosX + state->pieceOffsets[freePieceIndex][0];
    ((ObjPlacement*)newPlacement)->posY = obj->anim.localPosY + state->pieceOffsets[freePieceIndex][1];
    ((ObjPlacement*)newPlacement)->posZ = obj->anim.localPosZ + state->pieceOffsets[freePieceIndex][2];
    newPlacement->base.color[0] = placement->base.color[0];
    newPlacement->base.color[1] = placement->base.color[1];
    newPlacement->base.color[2] = placement->base.color[2];
    newPlacement->base.color[3] = placement->base.color[3];
    newPlacement->scale = TUMBLEWEED_BUSH_PIECE_SCALE;

    if ((state->variant & 1) != 0) {
        switch (((ObjPlacement*)obj->anim.placementData)->ident) {
        case 0x292c:
            if (state->spawnedCount == 6) {
                newPlacement->radiusByte = 1;
                objects = ObjList_GetObjects(&objectIndex, &objectCount);
                while (objectIndex < objectCount) {
                    GameObject* markerObj = objects[objectIndex];

                    if (markerObj->anim.romDefNo == 0x27f) {
                        ((ObjPlacement*)newPlacement)->posX = markerObj->anim.localPosX;
                        ((ObjPlacement*)newPlacement)->posY = objects[objectIndex]->anim.localPosY;
                        ((ObjPlacement*)newPlacement)->posZ = objects[objectIndex]->anim.localPosZ;
                        objectIndex = objectCount;
                    }
                    objectIndex++;
                }
            }
            break;
        }
    }

    {
        GameObject* spawnedObj = objSetupObject((ObjPlacement*)newPlacement, TUMBLEWEED_BUSH_SIBLING_SETUP_FLAGS,
                                                obj->anim.mapEventSlot, -1, obj->anim.parent);

        state->pieceObjects[freePieceIndex] = spawnedObj;
        {
            GameObject* spawnedPiece = state->pieceObjects[freePieceIndex];

            TUMBLEWEED_INTERFACE(spawnedPiece)->setHome(spawnedPiece, obj->anim.localPosX, obj->anim.localPosZ);
        }
    }
    state->spawnedCount++;
    return freePieceIndex;
}

void tumbleweedbush_removePieceReference(GameObject* obj, GameObject* piece) {
    TumbleweedBushState* state;
    int pieceIndex;

    state = obj->extra;
    pieceIndex = 0;
    while (pieceIndex < state->pieceCount) {
        if (state->pieceObjects[pieceIndex] == piece) {
            state->pieceObjects[pieceIndex] = NULL;
        }
        pieceIndex++;
    }
}

int TumbleWeedBush_getExtraSize(void) {
    return sizeof(TumbleweedBushState);
}

int TumbleWeedBush_getObjectTypeId(void) {
    return 0;
}

void TumbleWeedBush_free(GameObject* obj) {
    (void)obj;
}

const f32 gTumbleweedBushRenderScale[] = {1.0f};

void TumbleWeedBush_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visibleInt = visible;

    if (visibleInt != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, gTumbleweedBushRenderScale[0]);
    }
}

void TumbleWeedBush_hitDetect(GameObject* obj) {
    (void)obj;
}

void TumbleWeedBush_update(GameObject* obj) {
    TumbleweedBushState* state;
    GameObject* player;
    f32 hitPos[3];
    f32 sunTime;
    GameObject* hitObject;
    f32 deltaX, deltaZ, distance;
    int pieceIndex;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (ObjHits_PollPriorityHitWithCooldown(obj, &gTumbleweedBushHitCooldown, &hitObject, hitPos) != 0) {
        if (hitObject->anim.romDefNo != TUMBLEWEED_BUSH_SIBLING_C) {
            objfx_spawnHitEmitterAtPos(hitPos, TUMBLEWEED_BUSH_HIT_EFFECT_ID, TUMBLEWEED_BUSH_HIT_COLOR_R,
                                       TUMBLEWEED_BUSH_HIT_COLOR_G, TUMBLEWEED_BUSH_HIT_COLOR_B);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_swdtest222_280);
            for (pieceIndex = 0; (u8)pieceIndex < state->pieceCount; pieceIndex++) {
                if (state->pieceObjects[(u8)pieceIndex] != NULL) {
                    if (obj->anim.romDefNo == TUMBLEWEED_BUSH_SEQUENCE_A) {
                        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0) {
                            continue;
                        }
                    }
                    TUMBLEWEED_INTERFACE(state->pieceObjects[(u8)pieceIndex])
                        ->fall(state->pieceObjects[(u8)pieceIndex]);
                }
            }
        }
    }
    deltaX = obj->anim.localPosX - player->anim.localPosX;
    deltaZ = obj->anim.localPosZ - player->anim.localPosZ;
    distance = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
    if ((u16)(s32)distance < state->triggerRadius) {
        while (tumbleweedbush_spawnSibling(obj) != -1) {
        }
    }
    pieceIndex = 0;
    for (; (u8)pieceIndex < state->pieceCount; pieceIndex++) {
        if (state->pieceObjects[(u8)pieceIndex] != NULL) {
            if (TUMBLEWEED_INTERFACE(state->pieceObjects[(u8)pieceIndex])
                    ->getPhase(state->pieceObjects[(u8)pieceIndex]) > 1) {
                state->pieceObjects[(u8)pieceIndex] = NULL;
            }
        }
    }
}

const f32 gTumbleweedBushInitScale[] = {0.0f};
const f32 gTumbleweedBushHitRadius[] = {15.0f};

void TumbleWeedBush_init(GameObject* obj, TumbleweedBushPlacement* placement, int flags) {
    TumbleweedBushState* state;
    f32 scale;
    int offsetTableIndex;
    int pieceIndex;

    state = obj->extra;
    state->scale = gTumbleweedBushInitScale[0];
    state->triggerRadius = (u16)(placement->radiusByte * 2);
    state->variant = placement->variant;
    obj->anim.rotZ =
        (s16)((placement->rotZByte - TUMBLEWEED_BUSH_ROTATION_CENTER) << TUMBLEWEED_BUSH_ROTATION_YZ_SHIFT);
    obj->anim.rotY =
        (s16)((placement->rotYByte - TUMBLEWEED_BUSH_ROTATION_CENTER) << TUMBLEWEED_BUSH_ROTATION_YZ_SHIFT);
    obj->anim.rotX = (s16)(placement->rotXByte << TUMBLEWEED_BUSH_ROTATION_X_SHIFT);
    obj->anim.rootMotionScale = placement->scale;
    scale = obj->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, (s32)(gTumbleweedBushHitRadius[0] * scale),
                               (s32)(TUMBLEWEED_BUSH_HIT_Y_MIN * scale), (s32)(TUMBLEWEED_BUSH_HIT_Y_MAX * scale));
    switch (obj->anim.romDefNo) {
    case TUMBLEWEED_BUSH_SEQUENCE_A:
    case TUMBLEWEED_BUSH_SEQUENCE_C:
    case TUMBLEWEED_BUSH_SEQUENCE_D:
        state->pieceCount = TUMBLEWEED_BUSH_PIECE_CAPACITY;
        offsetTableIndex = 0;
        break;
    case TUMBLEWEED_BUSH_SEQUENCE_B:
        state->pieceCount = TUMBLEWEED_BUSH_PIECE_CAPACITY;
        offsetTableIndex = 1;
        break;
    }
    if (flags == 0) {
        pieceIndex = 0;
        for (; pieceIndex < state->pieceCount; pieceIndex++) {
            state->pieceObjects[pieceIndex] = NULL;
            memcpy(state->pieceOffsets[pieceIndex], gTumbleweedBushPieceOffsetTable[offsetTableIndex][pieceIndex],
                   sizeof(state->pieceOffsets[pieceIndex]));
            state->pieceOffsets[pieceIndex][0] *= obj->anim.rootMotionScale;
            state->pieceOffsets[pieceIndex][1] *= obj->anim.rootMotionScale;
            state->pieceOffsets[pieceIndex][2] *= obj->anim.rootMotionScale;
            vecRotateZXY((s16*)obj, state->pieceOffsets[pieceIndex]);
        }
    }
}

void TumbleWeedBush_release(void) {
}

void TumbleWeedBush_initialise(void) {
}

GameObject* tumbleweedbush_findNearestActive(f32* position) {
    int objectCount;
    GameObject** objects;
    f32 nearestDistance;
    int objectIndex;
    GameObject* nearestObj;

    nearestDistance = TUMBLEWEED_BUSH_NEAREST_INITIAL_DIST;
    nearestObj = NULL;
    {
        GameObject** objectList = (GameObject**)objGetAllOfType(TUMBLEWEED_BUSH_OBJECT_GROUP, &objectCount);

        objectIndex = 0;
        objects = objectList;
    }
    while (objectIndex < objectCount) {
        if (objects[objectIndex]->anim.romDefNo == TUMBLEWEED_BUSH_SIBLING_B) {
            if (((TumbleweedState*)objects[objectIndex]->extra)->phase > TUMBLEWEED_PHASE_ARMED) {
                f32 distance = vec3f_distanceSquared(&objects[objectIndex]->anim.worldPosX, position);

                if (distance < nearestDistance) {
                    nearestDistance = distance;
                    nearestObj = objects[objectIndex];
                }
            }
        }
        objectIndex++;
    }
    return nearestObj;
}

void tumbleweedbush_activatePiece(GameObject* obj) {
    TumbleweedState* state = obj->extra;

    state->phase = TUMBLEWEED_BUSH_ACTIVE_PIECE_PHASE;
}

void tumbleweedbush_updateDetachedPiece(GameObject* piece, TumbleweedState* state) {
    f32 groundDistance;

    piece->anim.velocityX /= TUMBLEWEED_PIECE_HORIZONTAL_DAMPING;
    if (trackGetHeightAboveGround(piece, piece->anim.localPosX, piece->anim.localPosY, piece->anim.localPosZ,
                                  &groundDistance, 0) != 0) {
        if (groundDistance > TUMBLEWEED_PIECE_GROUND_CLEARANCE) {
            piece->anim.velocityY += TUMBLEWEED_PIECE_GRAVITY * timeDelta;
        } else {
            piece->anim.localPosY -= groundDistance - TUMBLEWEED_PIECE_GROUND_CLEARANCE;
            piece->anim.velocityY = 0.0f;
        }
    }
    piece->anim.velocityZ /= TUMBLEWEED_PIECE_HORIZONTAL_DAMPING;

    state->rotVelocityZ /= TUMBLEWEED_PIECE_ROTATION_DAMPING;
    state->rotVelocityY /= TUMBLEWEED_PIECE_ROTATION_DAMPING;
    state->rotVelocityX /= TUMBLEWEED_PIECE_ROTATION_DAMPING;

    piece->anim.localPosX += piece->anim.velocityX * timeDelta;
    piece->anim.localPosY += piece->anim.velocityY * timeDelta;
    piece->anim.localPosZ += piece->anim.velocityZ * timeDelta;

    piece->anim.rotZ += (f32)(int)state->rotVelocityZ * timeDelta;
    piece->anim.rotY += (f32)(int)state->rotVelocityY * timeDelta;
    piece->anim.rotX += (f32)(int)state->rotVelocityX * timeDelta;
}

f32 gTumbleweedBushPieceOffsetTable[2][4][3] = {
    {
        {-22.0f, 56.0f, 0.0f},
        {0.0f, 95.0f, 54.0f},
        {18.0f, 90.0f, -12.0f},
        {0.0f, 0.0f, 0.0f},
    },
    {
        {-22.0f, 56.0f, 0.0f},
        {0.0f, 80.0f, 54.0f},
        {18.0f, 90.0f, -12.0f},
        {-60.0f, 88.0f, 0.0f},
    },
};

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)TumbleWeedBush_initialise,
        (ObjectDescriptorCallback)TumbleWeedBush_release,
        0,
        (ObjectDescriptorCallback)TumbleWeedBush_init,
        (ObjectDescriptorCallback)TumbleWeedBush_update,
        (ObjectDescriptorCallback)TumbleWeedBush_hitDetect,
        (ObjectDescriptorCallback)TumbleWeedBush_render,
        (ObjectDescriptorCallback)TumbleWeedBush_free,
        (ObjectDescriptorCallback)TumbleWeedBush_getObjectTypeId,
        TumbleWeedBush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_removePieceReference,
    },
    0,
};

#define TRICKY_SEQ_ID                     0x24    /* retail "Tricky" (DLL 0xC4) */
#define TUMBLEWEED_MESSAGE_IN_RANGE       0x7000a /* sent to player when grab is offered */
#define TUMBLEWEED_MESSAGE_PICKUP         0x7000b /* player collected: award and burst */
#define TUMBLEWEED_OBJECT_GROUP           3
#define TUMBLEWEED_SECONDARY_OBJECT_GROUP 0x31
f32 gTumbleweedCollisionPointData[2] = {25.0f, 0.0f};

void tumbleweed_updateRollingMotion(GameObject* obj, TumbleweedState* state) {
    int hitCount;
    u32 randomValue;
    TrackGroundHit** hitEntry;
    int hitIndex;
    int nearestHitIndex;
    f32 heightDelta;
    f32 nearestHeightDelta;
    f32 bounceVelocity;
    TrackGroundHit** groundHits[2];

    groundHits[0] = NULL;
    nearestHeightDelta = 10000.0f;
    hitCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, groundHits, 0, 0);
    for (hitIndex = 0, nearestHitIndex = 0, hitEntry = groundHits[0]; hitIndex < hitCount; hitIndex++) {
        heightDelta = obj->anim.localPosY - (*hitEntry)->height;
        if (heightDelta < 0.0f) {
            heightDelta = -1.0f * heightDelta + 10.0f;
        }
        if (heightDelta < nearestHeightDelta) {
            nearestHitIndex = hitIndex;
            nearestHeightDelta = heightDelta;
        }
        hitEntry++;
    }
    if (obj->anim.velocityX > 1.0f) {
        obj->anim.velocityX = 1.0f;
    } else if (obj->anim.velocityX < -1.0f) {
        obj->anim.velocityX = -1.0f;
    }
    if (obj->anim.velocityY > 1.0f) {
        obj->anim.velocityY = 1.0f;
    } else if (obj->anim.velocityY < -1.0f) {
        obj->anim.velocityY = -1.0f;
    }
    if (obj->anim.velocityZ > 1.0f) {
        obj->anim.velocityZ = 1.0f;
    } else if (obj->anim.velocityZ < -1.0f) {
        obj->anim.velocityZ = -1.0f;
    }
    obj->anim.localPosX += obj->anim.velocityX * timeDelta;
    obj->anim.localPosY += obj->anim.velocityY * timeDelta;
    obj->anim.localPosZ += obj->anim.velocityZ * timeDelta;
    obj->anim.rotZ = (s16)((f32)(int)state->rotVelocityZ * timeDelta + (f32)(int)obj->anim.rotZ);
    obj->anim.rotY = (s16)((f32)(int)state->rotVelocityY * timeDelta + (f32)(int)obj->anim.rotY);
    obj->anim.rotX = (s16)((f32)(int)state->rotVelocityX * timeDelta + (f32)(int)obj->anim.rotX);
    if (groundHits[0] != NULL) {
        if (obj->anim.localPosY > 7.0f + groundHits[0][nearestHitIndex]->height) {
            obj->anim.velocityY += -0.17f;
        } else {
            obj->anim.localPosY = 7.0f + groundHits[0][nearestHitIndex]->height;
            if (obj->anim.romDefNo == TUMBLEWEED_TYPE_2) {
                heightDelta = (f32)(int)(randomValue = randomGetRange(0x8c, 0xb4));
                heightDelta = (f32)state->distToTarget / heightDelta;
                bounceVelocity = 0.8f * obj->anim.velocityY;
                obj->anim.velocityY = -(bounceVelocity * heightDelta);
            } else {
                heightDelta = (f32)(int)(randomValue = randomGetRange(0x14, 0x28));
                heightDelta = (f32)state->distToTarget / heightDelta;
                bounceVelocity = 0.8f * obj->anim.velocityY;
                obj->anim.velocityY = -(bounceVelocity * heightDelta);
            }
            nearestHitIndex = (int)(32.0f * obj->anim.velocityY);
            if (nearestHitIndex > 0x7f) {
                nearestHitIndex = 0x7f;
            }
            if (nearestHitIndex > 0x10) {
                Sfx_PlayFromObject(obj, SFXTRIG_mv_roothack16);
                randomValue = randomGetRange(0, 5);
                if (((int)randomValue == 0) && ((state->flags & TUMBLEWEED_EFFECT_FLAG_IMPACT_SFX) != 0)) {
                    Sfx_PlayFromObject(obj, SFXTRIG_id_27f);
                }
            }
        }
    }
}

void tumbleweed_setPlayer(GameObject* obj, GameObject* target) {
    TumbleweedState* state = obj->extra;

    state->targetObj = target;
}

int tumbleweed_isGravitating(GameObject* obj) {
    TumbleweedState* state = obj->extra;

    return state->phase == TUMBLEWEED_PHASE_HOMING;
}

void tumbleweed_gravitateToPoint(GameObject* obj, f32* targetPos) {
    TumbleweedState* state = obj->extra;
    f32 speedScale;

    state->phase = TUMBLEWEED_PHASE_HOMING;
    state->targetPos = targetPos;
    speedScale = 0.5f;
    state->speed = timeDelta * speedScale;
    ObjHits_DisableObject(obj);
}

void tumbleweed_fall(GameObject* obj) {
    TumbleweedState* state = obj->extra;

    if (state->phase == TUMBLEWEED_PHASE_ARMED) {
        ObjHits_EnableObject(obj);
        state->phase = TUMBLEWEED_PHASE_ROLLING;
        state->flags |= TUMBLEWEED_EFFECT_FLAGS_BURST_PUFF;
        if (obj->anim.romDefNo == TUMBLEWEED_TYPE_4) {
            state->phaseTimer = 30.0f;
        }
    }
}

void tumbleweed_setHome(GameObject* obj, f32 x, f32 z) {
    TumbleweedState* state = obj->extra;

    state->anchorPosX = x;
    state->anchorPosZ = z;
}

int tumbleweed_getPhase(GameObject* obj) {
    TumbleweedState* state = obj->extra;

    return state->phase;
}

int tumbleweed_getExtraSize(void) {
    return sizeof(TumbleweedState);
}

void tumbleweed_free(GameObject* obj) {
    GameObject** objects;
    int objectIndex;
    int objectCount;
    int bushSeqId;

    switch (obj->anim.romDefNo) {
    case TUMBLEWEED_TYPE_1:
        bushSeqId = TUMBLEWEED_BUSH_SEQUENCE_A;
        break;
    case TUMBLEWEED_TYPE_2:
        bushSeqId = TUMBLEWEED_BUSH_SEQUENCE_B;
        break;
    case TUMBLEWEED_TYPE_3:
        bushSeqId = TUMBLEWEED_BUSH_SEQUENCE_C;
        break;
    case TUMBLEWEED_TYPE_4:
        bushSeqId = TUMBLEWEED_BUSH_SEQUENCE_D;
        break;
    }

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    while (objectIndex < objectCount) {
        GameObject* bush = objects[objectIndex];

        if (bushSeqId == bush->anim.romDefNo) {
            TUMBLEWEED_BUSH_INTERFACE(bush)->removePieceReference(bush, obj);
        }
        objectIndex++;
    }
    objFreeObjectType(obj, TUMBLEWEED_OBJECT_GROUP);
    objFreeObjectType(obj, TUMBLEWEED_SECONDARY_OBJECT_GROUP);
}

void tumbleweed_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if ((s32)visible >= 1) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void tumbleweed_updateStateMachine(GameObject* obj) {
    TumbleweedState* state;
    int sphereIndex;
    u32 hitVolume;
    GameObject* hitObject;
    u32 messageId;
    GameObject* player;
    GameObject* tricky;

    state = obj->extra;
    {
        u32 phase = state->phase;

        if (phase == TUMBLEWEED_PHASE_GROWING) {
            if (obj->anim.rootMotionScale < state->targetScale) {
                obj->anim.rootMotionScale += state->growRate * timeDelta;
            } else {
                state->phase = TUMBLEWEED_PHASE_ARMED;
            }
        } else if (phase == TUMBLEWEED_PHASE_ARMED) {
            if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0) {
                ObjHits_EnableObject(obj);
                state->phase = TUMBLEWEED_PHASE_ROLLING;
                state->flags |= TUMBLEWEED_EFFECT_FLAGS_BURST_PUFF;
                if (obj->anim.romDefNo == TUMBLEWEED_TYPE_4) {
                    state->phaseTimer = 30.0f;
                }
            }
        } else if (phase == TUMBLEWEED_PHASE_ROLLING) {
            f32 targetOffsetX, targetOffsetZ, targetDistanceSquared;
            f32 targetDistance;
            player = Obj_GetPlayerObject();
            targetOffsetX = obj->anim.localPosX - player->anim.localPosX;
            targetOffsetZ = obj->anim.localPosZ - player->anim.localPosZ;
            targetDistanceSquared = targetOffsetX * targetOffsetX + targetOffsetZ * targetOffsetZ;
            tricky = (GameObject*)getTrickyObject();
            if (tricky != NULL && tricky->anim.romDefNo == TRICKY_SEQ_ID) {
                f32 trickyOffsetX, trickyOffsetZ, trickyDistanceSquared;
                if (targetDistanceSquared < 30625.0f) {
                    TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_NORMAL,
                                                                TRICKY_COMMAND_TYPE_FIND_SECRET);
                }
                trickyOffsetX = obj->anim.localPosX - tricky->anim.localPosX;
                trickyOffsetZ = obj->anim.localPosZ - tricky->anim.localPosZ;
                trickyDistanceSquared = trickyOffsetX * trickyOffsetX + trickyOffsetZ * trickyOffsetZ;
                if (trickyDistanceSquared < targetDistanceSquared) {
                    targetOffsetX = trickyOffsetX;
                    targetOffsetZ = trickyOffsetZ;
                    targetDistanceSquared = trickyDistanceSquared;
                }
            }
            targetDistance = sqrtf(targetDistanceSquared);
            state->distToTarget = targetDistance;
            {
                f32 anchorOffsetX = obj->anim.localPosX - state->anchorPosX;
                f32 anchorOffsetZ = obj->anim.localPosZ - state->anchorPosZ;
                int anchorDistance = sqrtf(anchorOffsetX * anchorOffsetX + anchorOffsetZ * anchorOffsetZ);
                u32 targetDistanceInt;
                state->flags &= ~TUMBLEWEED_EFFECT_FLAG_IMPACT_SFX;
                targetDistanceInt = state->distToTarget;
                if ((f32)targetDistanceInt < 150.0f && targetDistanceInt != 0) {
                    f32 rotationScale;
                    obj->anim.velocityX -= targetOffsetX / (15.0f * ((f32)targetDistanceInt - 150.0f));
                    obj->anim.velocityZ -= targetOffsetZ / (15.0f * ((f32)(u32)state->distToTarget - 150.0f));
                    rotationScale = 728.0f;
                    state->rotVelocityZ = rotationScale * obj->anim.velocityX;
                    state->rotVelocityY = rotationScale * obj->anim.velocityZ;
                    state->flags |= TUMBLEWEED_EFFECT_FLAG_IMPACT_SFX;
                } else {
                    u32 anchorDistanceInt = (u16)anchorDistance;
                    if ((f32)anchorDistanceInt > 10.0f && anchorDistanceInt != 0) {
                        f32 velocityDivisor;
                        obj->anim.velocityX -= anchorOffsetX / (velocityDivisor = 10.0f * anchorDistanceInt);
                        obj->anim.velocityZ -= anchorOffsetZ / velocityDivisor;
                    }
                }
            }
            tumbleweed_updateRollingMotion(obj, state);
            (*gPathControlInterface)->advance(obj, state, timeDelta);
            state->phaseTimer -= timeDelta;
            if (state->phaseTimer < 0.0f) {
                state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
            } else if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                       hitObject->anim.romDefNo != obj->anim.romDefNo) {
                if (obj->anim.romDefNo == TUMBLEWEED_TYPE_3) {
                    state->flags |= TUMBLEWEED_EFFECT_FLAGS_BURST_PUFF;
                    state->flags &= ~TUMBLEWEED_EFFECT_FLAG_HIT_PULSE;
                    state->phase = TUMBLEWEED_PHASE_PICKUP_APPROACH;
                    state->growRate = 300.0f;
                    state->phaseTimer = 1200.0f;
                    Obj_SetActiveModelIndex(obj, 1);
                } else {
                    state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
                }
            }
        } else if (phase == TUMBLEWEED_PHASE_PICKUP_APPROACH) {
            f32 playerDistance;
            player = Obj_GetPlayerObject();
            playerDistance = getXZDistanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX);
            if (playerDistance < 625.0f) {
                state->triggerGameBit = 0x195;
                state->pickupMsgValue = 0;
                state->unk29C = 0.5f;
                ObjMsg_SendToObject(player, TUMBLEWEED_MESSAGE_IN_RANGE, obj, (u32)&state->triggerGameBit);
                state->phase = TUMBLEWEED_PHASE_PICKUP_WAIT;
            } else {
                state->growRate -= timeDelta;
                state->phaseTimer -= timeDelta;
                if (state->phaseTimer < 0.0f) {
                    state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
                } else if (state->growRate <= 0.0f) {
                    state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
                } else if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                           hitObject->anim.romDefNo != obj->anim.romDefNo) {
                    state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
                }
            }
            tumbleweedbush_updateDetachedPiece(obj, state);
            (*gPathControlInterface)->advance(obj, state, timeDelta);
        } else if (phase == TUMBLEWEED_PHASE_PICKUP_WAIT) {
            while (ObjMsg_Pop(obj, &messageId, 0, 0) != 0) {
                if (messageId == TUMBLEWEED_MESSAGE_PICKUP) {
                    gameBitIncrement(GAMEBIT_ITEM_FireWeed_Count);
                    Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                    state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
                }
            }
        } else if (phase == TUMBLEWEED_PHASE_HOMING) {
            f32* target = state->targetPos;
            f32 targetOffsetX, targetOffsetY, targetOffsetZ, targetDistance;
            targetOffsetX = target[0] - obj->anim.localPosX;
            targetOffsetY = target[1] - obj->anim.localPosY;
            targetOffsetZ = target[2] - obj->anim.localPosZ;
            targetDistance =
                sqrtf(targetOffsetX * targetOffsetX + targetOffsetY * targetOffsetY + targetOffsetZ * targetOffsetZ);
            targetOffsetX /= targetDistance;
            targetOffsetY /= targetDistance;
            targetOffsetZ /= targetDistance;
            {
                f32 speedScale;
                speedScale = 0.5f;
                state->speed += timeDelta * speedScale;
            }
            {
                f32 velocityScale = 0.1f;
                f32 scaledOffset;
                scaledOffset = velocityScale * targetOffsetX;
                obj->anim.velocityX = scaledOffset * state->speed;
                scaledOffset = velocityScale * targetOffsetY;
                obj->anim.velocityY = scaledOffset * state->speed;
                scaledOffset = velocityScale * targetOffsetZ;
                obj->anim.velocityZ = scaledOffset * state->speed;
            }
            targetDistance = getXZDistanceSquared((f32*)&obj->anim.localPosX, state->targetPos);
            objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                    obj->anim.velocityZ * timeDelta);
            if (getXZDistanceSquared((f32*)&obj->anim.localPosX, state->targetPos) > targetDistance) {
                f32 snapOffsetX, snapOffsetY, snapOffsetZ;
                f32 interpolationFactor;
                snapOffsetX = state->targetPos[0] - obj->anim.localPosX;
                interpolationFactor = 0.5f;
                obj->anim.localPosX += snapOffsetX * interpolationFactor;
                snapOffsetY = state->targetPos[1] - obj->anim.localPosY;
                obj->anim.localPosY += snapOffsetY * interpolationFactor;
                snapOffsetZ = state->targetPos[2] - obj->anim.localPosZ;
                obj->anim.localPosZ += snapOffsetZ * interpolationFactor;
            }
        } else if (phase == TUMBLEWEED_PHASE_ACTIVE) {
            u32 dampingStep = 0;
            f32 damping = 0.95f;
            for (; (s32)(dampingStep & 0xffff) < (s32)timeDelta; dampingStep++) {
                obj->anim.rootMotionScale *= damping;
            }
            obj->anim.localPosX = state->targetPos[0];
            obj->anim.localPosY = state->targetPos[1];
            obj->anim.localPosZ = state->targetPos[2];
        } else if (state->growRate <= 0.0f) {
            Obj_FreeObject(obj);
        } else {
            state->growRate -= timeDelta;
        }
    }
}

void tumbleweed_updateTargetedStateMachine(GameObject* obj) {
    int sphereIndex;
    u32 hitVolume;
    GameObject* hitObject;
    f32 sunPosition;
    TumbleweedState* state;
    GameObject* player;
    u32 phase;

    state = obj->extra;
    phase = state->phase;
    if (phase == TUMBLEWEED_PHASE_GROWING) {
        if ((*gSkyInterface)->getSunPosition(&sunPosition) != 0) {
            if (obj->anim.rootMotionScale < state->targetScale) {
                obj->anim.rootMotionScale += state->growRate * timeDelta;
            } else {
                state->phase = TUMBLEWEED_PHASE_ARMED;
            }
        }
    } else if (phase == TUMBLEWEED_PHASE_ARMED) {
        if ((*gSkyInterface)->getSunPosition(&sunPosition) != 0) {
            f32 targetOffsetX, targetOffsetZ, targetDistance;
            player = state->targetObj != NULL ? state->targetObj : Obj_GetPlayerObject();
            targetOffsetX = obj->anim.localPosX - player->anim.localPosX;
            targetOffsetZ = obj->anim.localPosZ - player->anim.localPosZ;
            targetDistance = sqrtf(targetOffsetX * targetOffsetX + targetOffsetZ * targetOffsetZ);
            state->distToTarget = targetDistance;
            if (state->distToTarget < state->triggerRange) {
                state->phase = TUMBLEWEED_PHASE_ROLLING;
                obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
                ObjHits_EnableObject(obj);
            }
        }
    } else if (phase == TUMBLEWEED_PHASE_ROLLING) {
        f32 targetOffsetX, targetOffsetZ, targetDistance;
        u32 targetDistanceInt;
        player = state->targetObj != NULL ? state->targetObj : Obj_GetPlayerObject();
        targetOffsetX = obj->anim.localPosX - player->anim.localPosX;
        targetOffsetZ = obj->anim.localPosZ - player->anim.localPosZ;
        targetDistance = sqrtf(targetOffsetX * targetOffsetX + targetOffsetZ * targetOffsetZ);
        state->distToTarget = targetDistance;
        targetDistanceInt = state->distToTarget;
        if ((f32)targetDistanceInt > 20.0f) {
            f32 rotationScale;
            obj->anim.velocityX -= targetOffsetX / (20.0f * targetDistanceInt);
            obj->anim.velocityZ -= targetOffsetZ / (20.0f * (f32)(u32)state->distToTarget);
            rotationScale = 728.0f;
            state->rotVelocityZ = rotationScale * obj->anim.velocityX;
            state->rotVelocityY = rotationScale * obj->anim.velocityZ;
        } else {
            f32 bounceScale = 0.8f;
            obj->anim.velocityX = -(bounceScale * obj->anim.velocityX);
            obj->anim.velocityZ = -(bounceScale * obj->anim.velocityZ);
        }
        tumbleweed_updateRollingMotion(obj, state);
        (*gPathControlInterface)->advance(obj, state, timeDelta);
        if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0) {
            mainSetBits(GAMEBIT_TumbleweedRelated642, 1);
            state->flags |= TUMBLEWEED_EFFECT_FLAGS_ALL;
        }
    } else if (state->growRate <= 0.0f) {
        Obj_FreeObject(obj);
    } else {
        state->growRate -= timeDelta;
    }
}

void tumbleweed_updateEffects(GameObject* obj) {
    TumbleweedState* state = obj->extra;
    int spawnCount;

    if ((state->flags & TUMBLEWEED_EFFECT_FLAG_BURST) != 0) {
        switch (obj->anim.romDefNo) {
        case TUMBLEWEED_TYPE_3:
        case TUMBLEWEED_TYPE_1:
        case TUMBLEWEED_TYPE_4:
            spawnCount = TUMBLEWEED_EFFECT_SPAWN_COUNT;
            do {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, TUMBLEWEED_EFFECT_BURST_SPECIAL, NULL, TUMBLEWEED_PARTFX_MODE_ACTIVE, -1,
                                  NULL);
                --spawnCount;
            } while (spawnCount != 0);
            break;
        default:
            spawnCount = TUMBLEWEED_EFFECT_SPAWN_COUNT;
            do {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, TUMBLEWEED_EFFECT_BURST_DEFAULT, NULL, TUMBLEWEED_PARTFX_MODE_ACTIVE, -1,
                                  NULL);
                --spawnCount;
            } while (spawnCount != 0);
            break;
        }
        Sfx_PlayFromObject(obj, TUMBLEWEED_SFX_BURST);
        state->flags &= ~TUMBLEWEED_EFFECT_FLAG_BURST;
    }

    if ((state->flags & TUMBLEWEED_EFFECT_FLAG_PUFF) != 0) {
        switch (obj->anim.romDefNo) {
        case TUMBLEWEED_TYPE_3:
        case TUMBLEWEED_TYPE_1:
        case TUMBLEWEED_TYPE_4:
            (*gPartfxInterface)
                ->spawnObject((void*)obj, TUMBLEWEED_EFFECT_PUFF_SPECIAL, NULL, TUMBLEWEED_PARTFX_MODE_ACTIVE, -1,
                              NULL);
            break;
        default:
            (*gPartfxInterface)
                ->spawnObject((void*)obj, TUMBLEWEED_EFFECT_PUFF_DEFAULT, NULL, TUMBLEWEED_PARTFX_MODE_ACTIVE, -1,
                              NULL);
            break;
        }
        state->flags &= ~TUMBLEWEED_EFFECT_FLAG_PUFF;
    }

    if ((state->flags & TUMBLEWEED_EFFECT_FLAG_DESPAWN) != 0) {
        obj->anim.alpha = 0;
        state->phase = TUMBLEWEED_PHASE_DESPAWNING;
        state->despawnTimer = 120.0f;
        ObjHits_DisableObject(obj);
        state->flags &= ~TUMBLEWEED_EFFECT_FLAG_DESPAWN;
    }

    if ((state->flags & TUMBLEWEED_EFFECT_FLAG_HIT_PULSE) != 0 && (obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, TUMBLEWEED_HIT_PULSE_VOLUME_SLOT, 1, 0);
        if ((int)(u8)(++state->hitPulseCounter) % TUMBLEWEED_HIT_PULSE_PERIOD != 0) {
            objfx_spawnPulseBurst(obj, obj->anim.rootMotionScale, 1, 0, 0, NULL);
        } else {
            objfx_spawnPulseBurst(obj, obj->anim.rootMotionScale, 1, TUMBLEWEED_HIT_PULSE_ALT_STYLE, 0, NULL);
        }
        Sfx_KeepAliveLoopedObjectSound(obj, TUMBLEWEED_SFX_HIT_LOOP);
    }
}

void tumbleweed_update(GameObject* obj) {
    if (obj->anim.romDefNo == TUMBLEWEED_TYPE_1) {
        tumbleweed_updateTargetedStateMachine(obj);
    } else {
        tumbleweed_updateStateMachine(obj);
    }
    tumbleweed_updateEffects(obj);
}

void tumbleweed_init(GameObject* obj, TumbleweedPlacement* placement) {
    TumbleweedState* state = obj->extra;

    state->anchorPosX = obj->anim.localPosX;
    state->anchorPosZ = obj->anim.localPosZ;
    state->triggerRange = (u16)(2.0f * placement->scale);
    state->variant = placement->variant;
    state->targetScale = obj->anim.rootMotionScale;
    state->growRate = state->targetScale / (f32)(s32)randomGetRange(0xc8, 0x1f4);
    state->targetObj = NULL;
    obj->anim.rootMotionScale = 0.001f;
    (*gPathControlInterface)->init(state, 0, 0x40000, 1);
    (*gPathControlInterface)
        ->setLocalPointCollision(state, 1, gTumbleweedCollisionPoint, gTumbleweedCollisionPointData, 8);
    (*gPathControlInterface)->attachObject(obj, state);
    state->phase = TUMBLEWEED_PHASE_GROWING;
    state->phaseTimer = 1200.0f + (f32)(s32)randomGetRange(-0x12c, 0x12c);
    objAddObjectType(obj, TUMBLEWEED_OBJECT_GROUP);
    objAddObjectType(obj, TUMBLEWEED_SECONDARY_OBJECT_GROUP);
    ObjHits_DisableObject(obj);
    ObjMsg_AllocQueue(obj, 1);
    if (obj->anim.romDefNo == TUMBLEWEED_TYPE_3) {
        state->flags |= TUMBLEWEED_EFFECT_FLAG_HIT_PULSE;
    }
}

f32 gTumbleweedCollisionPoint[3] = {0.0f, 0.0f, 0.0f};

ObjectDescriptor16WithPadding gTumbleweedObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_16_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)tumbleweed_init,
        (ObjectDescriptorCallback)tumbleweed_update,
        0,
        (ObjectDescriptorCallback)tumbleweed_render,
        (ObjectDescriptorCallback)tumbleweed_free,
        0,
        tumbleweed_getExtraSize,
        (ObjectDescriptorCallback)tumbleweed_getPhase,
        (ObjectDescriptorCallback)tumbleweed_setHome,
        (ObjectDescriptorCallback)tumbleweed_fall,
        (ObjectDescriptorCallback)tumbleweed_gravitateToPoint,
        (ObjectDescriptorCallback)tumbleweed_isGravitating,
        (ObjectDescriptorCallback)tumbleweed_setPlayer,
    },
    0,
};
