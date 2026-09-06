/*
 * DLL 625 - a rideable hover-pad object in the
 * Drakor (DR) levels that follows a ROM spline/curve network.
 *
 * initMain seeds the pad onto its curve and selects a behaviour mode
 * from its placement subtype; updateMain advances the pad along the
 * active curve each step, applying a sinusoidal vertical bob, banking
 * the model toward its travel direction, and steering the object
 * toward the curve sample point. update() advances the walker's node
 * chain, picks the next path point in the network (masked vs unmasked
 * branch by walk direction) and rebuilds the staged hermite endpoint
 * and tangent sets for that segment. handlePathPointEvent dispatches the per-node
 * event ids: speed flips, state changes, camera shake / view offset
 * while the player is riding, and the game bits that gate the ride.
 * render emits the trailing particle spray on a frame cadence.
 *
 * Curve/velocity state lives in the object's extra block
 * (DrakorHoverpadState, 0x17c bytes), whose flags / pathFlags members
 * carry the ride and path-event bits.
 */
#include "dlls/objects/625_DrakorHoverpad.h"
#include "dlls/objects/common/vehicle.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/curve.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/objprint_api.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/rom_curve_def.h"
#include "game/objects/object.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/object_descriptor.h"
#include "main/dll/dll_024D_bossdrakor.h"
#include "main/camera_shake_api.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/objhits.h"

/* placement subtype id (desc[0]) selecting the pad behaviour mode */
#define DRAKORHOVERPAD_SUBTYPE_TRACKING   1812 /* tracks/yaws toward a nearby object */
#define DRAKORHOVERPAD_SUBTYPE_FREE       1048 /* free curve-follow, no tracking */
#define DRAKORHOVERPAD_HIT_VOLUME_SLOT    8

#define ABS_EXPR(value) ((value) >= 0.0f ? value : -value)

f32 gDrakorHoverpadMtx[16];

#define DRAKORHOVERPAD_SPEED_STEP 2.0f

f32 gDrakorHoverpadSteerMaxSpeed = 5.0f;
s16 lbl_803DC2FC = 3;
f32 lbl_803DC300 = 5.0f;
f32 lbl_803DC304 = -40.0f;

void drakorhoverpad_resetPendingMotion(GameObject* obj) {
    DrakorHoverpadState* p = obj->extra;
    DrakorHoverpadPathFlags* g = &p->pathFlags;
    if (g->p6 != 0) {
        g->p6 = 0;
        p->commandSpeed = DRAKORHOVERPAD_SPEED_STEP;
    }
}

void drakorhoverpad_func17(GameObject* obj, int sel, int* out) {
    switch (sel) {
    case 2:
        *out = obj->anim.rotX;
        break;
    case 3:
        *out = 0x1000;
        break;
    case 4:
        *out = 1;
        break;
    }
}

void drakorhoverpad_handleRiderScale(GameObject* obj, f32 scale) {
    f32* mtx;
    MatrixTransform pos;
    mtx = (f32*)ObjPath_GetPointModelMtx(obj, 0);
    pos.x = 0.0f;
    pos.y = 10.0f;
    pos.z = 0.0f;
    pos.rotX = 0;
    pos.rotY = 0;
    pos.rotZ = 0;
    pos.scale = scale / (obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(gDrakorHoverpadMtx, &pos);
    mtx44_mult(gDrakorHoverpadMtx, mtx, gDrakorHoverpadMtx);
    objSetModelMatrixOverride(gDrakorHoverpadMtx);
}

void drakorhoverpad_func15(void) {
}

int drakorhoverpad_getRacePosition(void) {
    return 0x0;
}

f32 drakorhoverpad_func13(int obj, f32* out) {
    *out = 5.0f;
    return 0.0f;
}

void drakorhoverpad_getPlayerAnim(int obj, f32* outFloat, int* outFlag) {
    *outFloat = 0.0f;
    *outFlag = 0;
}

void drakorhoverpad_setMountState(void) {
}

int drakorhoverpad_getMountState(void) {
    return 0x0;
}

void drakorhoverpad_getCameraPosition(GameObject* obj, f32* ox, f32* oy, f32* oz) {
    MatrixTransform pos;
    f32 mtx[16];
    GameObject* src = Obj_GetPlayerObject();
    if (src == NULL) {
        src = obj;
    }
    pos.x = src->anim.localPosX;
    pos.y = src->anim.localPosY;
    pos.z = src->anim.localPosZ;
    pos.rotX = src->anim.rotX;
    pos.rotY = src->anim.rotY;
    pos.rotZ = src->anim.rotZ;
    pos.scale = 1.0f;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, 0.0f, lbl_803DC300, lbl_803DC304, ox, oy, oz);
}

static void drakorhoverpad_initPathCurve(GameObject* obj, DrakorHoverpadState* p) {
    int curveArg = 0x2a;

    (*gRomCurveInterface)->initCurve(&p->curve, (void*)obj, 300.0f, &curveArg, -1);
    Curve_AdvanceAlongPath(&p->curve.curve, 0.01f);
}

static f32 drakorhoverpad_nodeWobbleSin(RomCurveDef** slot, int angle) {
    return DRAKORHOVERPAD_SPEED_STEP * ((f32)(u32)(*slot)->tangentMag * mathSinf(3.1415927f * (f32)angle / 32768.0f));
}

static f32 drakorhoverpad_nodeWobbleCos(RomCurveDef** slot, int angle) {
    return DRAKORHOVERPAD_SPEED_STEP * ((f32)(u32)(*slot)->tangentMag * mathCosf(3.1415927f * (f32)angle / 32768.0f));
}

int drakorhoverpad_getDismountSide(void) {
    return 0x1;
}

int drakorhoverpad_canDismount(GameObject* obj) {
    DrakorHoverpadState* p = obj->extra;
    return p->pathFlags.f04 == 0;
}

void drakorhoverpad_getRiderPosition(GameObject* obj, f32* ox, f32* oy, f32* oz) {
    *ox = obj->anim.localPosX;
    *oy = 10.0f + obj->anim.localPosY;
    *oz = obj->anim.localPosZ;
}

int drakorhoverpad_getMountSide(void) {
    return 0x1;
}

int drakorhoverpad_canMount(GameObject* obj) {
    DrakorHoverpadState* p = obj->extra;
    return p->pathFlags.f04;
}

int drakorhoverpad_pickMaskedNextPoint(RomCurveDef* pad, int exclude, int maxIndex) {
    int collected[4];
    int pt;
    int count;
    u32 bit;
    int i;

    count = 0;
    bit = 1;
    for (i = 0; i < 4; i++) {
        pt = pad->linkIds[i];
        if (pt > -1 && (pad->backwardLinkMask & bit) != 0 && pt != exclude) {
            collected[count++] = pt;
        }
        bit <<= 1;
    }
    if (count != 0) {
        if (maxIndex != -1 && maxIndex > count - 1) {
            maxIndex = count - 1;
        }
        if (maxIndex == -1) {
            maxIndex = randomGetRange(0, count - 1);
        }
        return collected[maxIndex];
    }
    return -1;
}

int drakorhoverpad_pickUnmaskedNextPoint(RomCurveDef* pad, int exclude, int maxIndex) {
    int collected[4];
    int pt;
    int count;
    u32 bit;
    int i;

    count = 0;
    bit = 1;
    for (i = 0; i < 4; i++) {
        pt = pad->linkIds[i];
        if (pt > -1 && (pad->backwardLinkMask & bit) == 0 && pt != exclude) {
            collected[count++] = pt;
        }
        bit <<= 1;
    }
    if (count != 0) {
        if (maxIndex != -1 && maxIndex > count - 1) {
            maxIndex = count - 1;
        }
        if (maxIndex == -1) {
            maxIndex = randomGetRange(0, count - 1);
        }
        return collected[maxIndex];
    }
    return -1;
}

int drakorhoverpad_update(RomCurveWalker* curve, int maxIndex) {
    void* cur;
    int result;

    if (curve == NULL) {
        return 1;
    }
    cur = curve->currentNode;
    if (cur == NULL || curve->nextNode == NULL) {
        return 1;
    }
    curve->previousNode = cur;
    curve->currentNode = curve->nextNode;
    memcpy(curve->hermX, curve->hermX2, 16);
    memcpy(curve->hermY, curve->hermY2, 16);
    memcpy(curve->hermZ, curve->hermZ2, 16);
    if (curve->reverse != 0) {
        result = drakorhoverpad_pickMaskedNextPoint((RomCurveDef*)curve->currentNode, -1, maxIndex);
    } else {
        result = drakorhoverpad_pickUnmaskedNextPoint((RomCurveDef*)curve->currentNode, -1, maxIndex);
    }
    if (result != -1) {
        curve->nextNode = (*gRomCurveInterface)->getById(result);
        if (curve->nextNode != NULL) {
#define CM_SLOT  (&curve->currentNode)
#define AMP_SLOT (&curve->previousNode)
#define TGT_SLOT (&curve->nextNode)
#define CM_NODE  (*CM_SLOT)
#define AMP_NODE (*AMP_SLOT)
#define TGT_NODE (*TGT_SLOT)
            if (curve->reverse != 0) {
                curve->hermX2[0] = CM_NODE->x;
                curve->hermX2[1] = AMP_NODE->x;
                curve->hermX2[2] = drakorhoverpad_nodeWobbleSin(CM_SLOT, CM_NODE->yaw << 8);
                curve->hermX2[3] = drakorhoverpad_nodeWobbleSin(AMP_SLOT, AMP_NODE->yaw << 8);
                curve->hermY2[0] = CM_NODE->y;
                curve->hermY2[1] = AMP_NODE->y;
                curve->hermY2[2] = drakorhoverpad_nodeWobbleSin(CM_SLOT, CM_NODE->pitch << 8);
                curve->hermY2[3] = drakorhoverpad_nodeWobbleSin(AMP_SLOT, AMP_NODE->pitch << 8);
                curve->hermZ2[0] = CM_NODE->z;
                curve->hermZ2[1] = AMP_NODE->z;
                curve->hermZ2[2] = drakorhoverpad_nodeWobbleCos(CM_SLOT, CM_NODE->yaw << 8);
                curve->hermZ2[3] = drakorhoverpad_nodeWobbleCos(AMP_SLOT, AMP_NODE->yaw << 8);
            } else {
                curve->hermX2[0] = CM_NODE->x;
                curve->hermX2[1] = TGT_NODE->x;
                curve->hermX2[2] = drakorhoverpad_nodeWobbleSin(CM_SLOT, CM_NODE->yaw << 8);
                curve->hermX2[3] = drakorhoverpad_nodeWobbleSin(TGT_SLOT, TGT_NODE->yaw << 8);
                curve->hermY2[0] = CM_NODE->y;
                curve->hermY2[1] = TGT_NODE->y;
                curve->hermY2[2] = drakorhoverpad_nodeWobbleSin(CM_SLOT, CM_NODE->pitch << 8);
                curve->hermY2[3] = drakorhoverpad_nodeWobbleSin(TGT_SLOT, TGT_NODE->pitch << 8);
                curve->hermZ2[0] = CM_NODE->z;
                curve->hermZ2[1] = TGT_NODE->z;
                curve->hermZ2[2] = drakorhoverpad_nodeWobbleCos(CM_SLOT, CM_NODE->yaw << 8);
                curve->hermZ2[3] = drakorhoverpad_nodeWobbleCos(TGT_SLOT, TGT_NODE->yaw << 8);
            }
#undef CM_NODE
#undef AMP_NODE
#undef TGT_NODE
#undef CM_SLOT
#undef AMP_SLOT
#undef TGT_SLOT
            if (curve->moveNetwork != 0) {
                curvesSetupMoveNetworkCurve(&curve->curve);
            }
            if (curve->reverse != 0) {
                Curve_AdvanceAlongPath(&curve->curve, -1.0f);
            } else {
                Curve_AdvanceAlongPath(&curve->curve, 1.0f);
            }
            return 0;
        }
    } else {
        curve->nextNode = NULL;
    }
    return 1;
}

ObjectDescriptor24 gDrakorHoverPadObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)drakorhoverpad_initialise,
    (ObjectDescriptorCallback)drakorhoverpad_release,
    0,
    (ObjectDescriptorCallback)drakorhoverpad_initMain,
    (ObjectDescriptorCallback)drakorhoverpad_updateMain,
    (ObjectDescriptorCallback)drakorhoverpad_hitDetect,
    (ObjectDescriptorCallback)drakorhoverpad_render,
    (ObjectDescriptorCallback)drakorhoverpad_free,
    (ObjectDescriptorCallback)drakorhoverpad_getObjectTypeId,
    drakorhoverpad_getExtraSize,
    (ObjectDescriptorCallback)drakorhoverpad_canMount,
    (ObjectDescriptorCallback)drakorhoverpad_getMountSide,
    (ObjectDescriptorCallback)drakorhoverpad_getRiderPosition,
    (ObjectDescriptorCallback)drakorhoverpad_canDismount,
    (ObjectDescriptorCallback)drakorhoverpad_getDismountSide,
    (ObjectDescriptorCallback)drakorhoverpad_getCameraPosition,
    (ObjectDescriptorCallback)drakorhoverpad_getMountState,
    (ObjectDescriptorCallback)drakorhoverpad_setMountState,
    (ObjectDescriptorCallback)drakorhoverpad_getPlayerAnim,
    (ObjectDescriptorCallback)drakorhoverpad_func13,
    (ObjectDescriptorCallback)drakorhoverpad_getRacePosition,
    (ObjectDescriptorCallback)drakorhoverpad_func15,
    (ObjectDescriptorCallback)drakorhoverpad_handleRiderScale,
    (ObjectDescriptorCallback)drakorhoverpad_func17,
};
int drakorhoverpad_init(GameObject* obj) {
    DrakorHoverpadState* p = obj->extra;
    DrakorHoverpadFlags* f = &p->flags;

    if (f->b40 == 0) {
        if (f->state > 3) {
            if (p->speed == 0.0f) {
                f->state = 0;
            }
        }
    }
    if (f->b01 != mainGetBit(1654)) {
        f->b01 ^= 1;
        p->commandSpeed = -p->commandSpeed;
        if (f->state == 3) {
            f->state = 0;
            p->commandSpeed = DRAKORHOVERPAD_SPEED_STEP;
        }
        if (f->state == 4) {
            f->state = 0;
            p->commandSpeed = -2.0f;
        }
        if (f->b40 != 0) {
            if (p->commandSpeed == 0.0f) {
                p->commandSpeed = (f->b01 != 0) ? -2.0f : DRAKORHOVERPAD_SPEED_STEP;
            }
        }
        Sfx_PlayFromObject(obj, SFXTRIG_id_309);
    }
    return 0;
}

int drakorhoverpad_handlePathPointEvent(GameObject* obj, u8 eventCode, u8 subCode, int* out) {
    DrakorHoverpadState* p = obj->extra;
    DrakorHoverpadFlags* f = &p->flags;
    DrakorHoverpadPathFlags* g = &p->pathFlags;
    GameObject* player;
    f32 shakeMag;
    f32 absP;
    f32 cur;
    f32 half;

    half = 0.5f;
    player = Obj_GetPlayerObject();
    *out = -1;
    switch (eventCode) {
    case 1:
        player = Obj_GetPlayerObject();
        p->speed = 0.8f * -p->speed;
        p->commandSpeed = 0.0f;
        if (player->anim.parent == (void*)obj) {
            CameraShake_Enable();
            if (p->speed >= 0.0f) {
                shakeMag = p->speed;
            } else {
                shakeMag = -p->speed;
            }
            CameraShake_SetOffset(shakeMag);
        }
        break;
    case 3:
        if (f->b40 != 0) {
            break;
        }
        if (p->speed <= 0.0f) {
            break;
        }
        if (f->bit80 != 0) {
            break;
        }
        player = Obj_GetPlayerObject();
        p->speed = 0.8f * -p->speed;
        p->commandSpeed = 0.0f;
        if (player->anim.parent == (void*)obj) {
            CameraShake_Enable();
            if (p->speed >= 0.0f) {
                shakeMag = p->speed;
            } else {
                shakeMag = -p->speed;
            }
            CameraShake_SetOffset(shakeMag);
        }
        return 1;
    case 4:
        if (p->speed <= 0.0f) {
            break;
        }
        if (f->b40 != 0) {
            mainSetBits(0x660, 1);
        } else if (mainGetBit(0x661) == 0) {
            mainSetBits(0x788, 1);
            f->state = 1;
            p->commandSpeed = 0.0f;
        } else {
            p->targetSpeed += (p->commandSpeed < 0.0f) ? -2.0f : DRAKORHOVERPAD_SPEED_STEP;
        }
        break;
    case 9:
        if (p->speed >= 0.0f) {
            break;
        }
        if (mainGetBit(0x661) == 0) {
            f->state = 1;
            p->commandSpeed = 0.0f;
        } else {
            p->targetSpeed += (p->commandSpeed < 0.0f) ? -2.0f : DRAKORHOVERPAD_SPEED_STEP;
        }
        break;
    case 5:
        if (f->b40 != 0) {
            break;
        }
        f->state = 2;
        break;
    case 6:
        if (f->b40 != 0) {
            break;
        }
        p->targetSpeed += (p->commandSpeed < 0.0f) ? -3.0f : 3.0f;
        break;
    case 7:
        if (p->commandSpeed <= 0.0f) {
            f->state = 3;
            p->commandSpeed = 0.0f;
            Sfx_PlayFromObject(obj, SFXTRIG_id_30b);
        }
        break;
    case 17:
        if (p->commandSpeed >= 0.0f) {
            f->state = 4;
            p->commandSpeed = 0.0f;
            Sfx_PlayFromObject(obj, SFXTRIG_id_30b);
        }
        break;
    case 10:
        if (g->p1 == 0) {
            break;
        }
        if (mainGetBit(0x689) != 0) {
            break;
        }
        mainSetBits(0x689, 1);
        break;
    case 11:
        if (g->p1 == 0) {
            break;
        }
        if (player->anim.parent != (void*)obj) {
            break;
        }
        mainSetBits(0x68a, 1);
        break;
    case 12:
        if (g->p1 == 0) {
            break;
        }
        if (player->anim.parent != (void*)obj) {
            break;
        }
        mainSetBits(0x68b, 1);
        break;
    case 13:
        if (mainGetBit(0x68a) == 0) {
            break;
        }
        if (p->commandSpeed >= 0.0f) {
            player = Obj_GetPlayerObject();
            p->speed = 0.8f * -p->speed;
            p->commandSpeed = 0.0f;
            if (player->anim.parent == (void*)obj) {
                CameraShake_Enable();
                if (p->speed >= 0.0f) {
                    shakeMag = p->speed;
                } else {
                    shakeMag = -p->speed;
                }
                CameraShake_SetOffset(shakeMag);
            }
        }
        break;
    case 14:
        if (g->p1 == 0) {
            break;
        }
        if (p->commandSpeed <= 0.0f) {
            player = Obj_GetPlayerObject();
            p->speed = 0.8f * -p->speed;
            p->commandSpeed = 0.0f;
            if (player->anim.parent == (void*)obj) {
                CameraShake_Enable();
                if (p->speed >= 0.0f) {
                    shakeMag = p->speed;
                } else {
                    shakeMag = -p->speed;
                }
                CameraShake_SetOffset(shakeMag);
            }
        }
        break;
    case 15:
        if (f->b40 != 0) {
            break;
        }
        mainSetBits(0x788, 1);
        break;
    case 16:
        absP = ABS_EXPR(p->commandSpeed);
        cur = p->commandSpeed;
        if (DRAKORHOVERPAD_SPEED_STEP == absP) {
            p->commandSpeed = cur * half;
        } else {
            p->commandSpeed = DRAKORHOVERPAD_SPEED_STEP * cur;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_id_309);
        break;
    case 20:
        g->f10 = !g->f10;
        break;
    case 21:
        g->p6 = 1;
        p->commandSpeed = 0.0f;
        break;
    }
    switch (subCode) {
    case 8:
        if (mainGetBit(0x67f) != 0) {
            *out = 1;
        } else {
            *out = 0;
        }
        break;
    case 2:
        mainSetBits(0x7ba, 1);
        break;
    case 18:
        *out = 0;
        break;
    case 19:
        *out = 1;
        break;
    }
    return 1;
}

int drakorhoverpad_getExtraSize(void) {
    return sizeof(DrakorHoverpadState);
}

int drakorhoverpad_getObjectTypeId(void) {
    return 0x0;
}

void drakorhoverpad_free(GameObject* obj) {
    objFreeObjectType(obj, DRAKORHOVERPAD_OBJGROUP);
    objFreeObjectType(obj, VEHICLE_OBJECT_GROUP);
}

void drakorhoverpad_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible) {
    DrakorHoverpadState* p = obj->extra;
    if (visible) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        p->frameCounter += framesThisStep;
        if (p->frameCounter == 0 || p->frameCounter > 10) {
            p->frameCounter = 0;
            p->particleEmitAX = (obj)->anim.localPosX + (f32)randomGetRange(-30, 30);
            p->particleEmitAY = (obj)->anim.localPosY;
            p->particleEmitAZ = (obj)->anim.localPosZ + (f32)randomGetRange(-30, 30);
            p->particleEmitBX = (obj)->anim.localPosX + (f32)randomGetRange(-120, 120);
            p->particleEmitBY = (obj)->anim.localPosY - 40.0f;
            p->particleEmitBZ = (obj)->anim.localPosZ + (f32)randomGetRange(-120, 120);
        }
    }
}

void drakorhoverpad_hitDetect(void) {
}

void drakorhoverpad_updateMain(GameObject* obj) {
    DrakorHoverpadState* p = (obj)->extra;
    RomCurveWalker* curve;
    DrakorHoverpadUpdateMainPlacement* q = (DrakorHoverpadUpdateMainPlacement*)(obj)->anim.placementData;
    DrakorHoverpadFlags* f = &p->flags;
    DrakorHoverpadPathFlags* g = &p->pathFlags;
    int evOut;
    Vec diff;
    f32 curvePos[3];
    f32 phase;
    GameObject* nearest;
    int c;
    int clamped;
    f32 spd;

    Obj_GetPlayerObject();
    if (drakorhoverpad_init(obj) != 0) {
        return;
    }
    if (f->bit20 == 0) {
        f->bit20 = mainGetBit(q->activateGameBit);
        p->targetSpeed = 0.0f;
        if (f->bit20 != 0) {
            drakorhoverpad_initPathCurve(obj, p);
            (obj)->anim.localPosX = p->curve.posX;
            (obj)->anim.localPosY = p->curve.posY;
            (obj)->anim.localPosZ = p->curve.posZ;
            p->commandSpeed = 2.0f;
            Sfx_PlayFromObject(obj, SFXTRIG_id_308);
            Sfx_PlayFromObject(obj, SFXTRIG_id_30a);
        }
        return;
    }
    curve = &p->curve;
    if (g->f08 != 0) {
        int angle = (s16)getAngle(sqrtf(curve->tangentX * curve->tangentX + curve->tangentZ * curve->tangentZ),
                                  curve->tangentY);
        f32 wobbleY;
        f32 limit;

        phase = 3.1415927f * (f32)angle / 32768.0f;
        wobbleY = -0.7f * mathCosf(phase);
        limit = 0.1f * (0.7f * mathSinf(phase));
        if (f->b40 != 0) {
            f32 absH = ABS_EXPR(p->commandSpeed);
            f32 absV = ABS_EXPR(p->speed);

            if (absV > absH + 2.0f) {
                limit += 2.0f;
            }
        }
        if (f->state != 0) {
            limit += 2.0f;
        }
        p->speed = p->targetSpeed + (p->speed + wobbleY);

        if (ABS_EXPR(p->speed) < limit) {
            p->speed = p->commandSpeed;
        } else {
            p->speed += p->speed > p->commandSpeed ? -limit : limit;
        }
        ObjHits_SetHitVolumeSlot(&obj->anim, DRAKORHOVERPAD_HIT_VOLUME_SLOT, 1, 0);
    } else {
        ObjHits_DisableObject(obj);
        p->speed = p->commandSpeed;
        gDrakorHoverpadSteerMaxSpeed = 2.0f * p->commandSpeed;
    }
    if (p->speed < 0.0f) {
        (*gRomCurveInterface)->setClosed(&p->curve, 1);
    } else {
        (*gRomCurveInterface)->setClosed(&p->curve, 0);
    }
    p->targetSpeed = 0.0f;
    if (p->speed != 0.0f) {
        Curve_AdvanceAlongPath(&curve->curve, p->speed);
        c = curve->reverse;
        if ((c == 0 && curve->atSegmentEnd != 0) || (c != 0 && curve->atSegmentEnd == 0)) {
            if (drakorhoverpad_handlePathPointEvent(obj, (u8)((RomCurveDef*)curve->currentNode)->action,
                                                    (u8)((RomCurveDef*)curve->nextNode)->action, &evOut) != 0) {
                drakorhoverpad_update(curve, evOut);
            }
        }
    }
    curvePos[0] = curve->posX;
    curvePos[1] = curve->posY;
    curvePos[2] = curve->posZ;
    curvePos[1] = curvePos[1] + (1.0f + mathSinf(3.1415927f * (f32)(int)p->anglePhase / 32768.0f));
    p->anglePhase = (s16)(p->anglePhase + framesThisStep * 0x320);
    if (g->f10 != 0) {
        nearest = objGetNearestTypeTo(BOSSDRAKOR_OBJGROUP, obj, 0);
        if (nearest != NULL) {
            s16 yawDelta = Obj_GetYawDeltaToObject(obj, nearest, 0);
            yawDelta = (yawDelta < -0x200) ? -0x200 : ((yawDelta > 0x200) ? 0x200 : yawDelta);
            c = yawDelta;
            (obj)->anim.rotX += (s16)c;
            if ((obj)->anim.rotY != 0) {
                yawDelta = (obj)->anim.rotY;
                if (yawDelta < -0x100) {
                    yawDelta = -0x100;
                } else if (yawDelta > 0x100) {
                    yawDelta = 0x100;
                }
                (obj)->anim.rotY -= (s16)yawDelta;
            }
            (obj)->anim.rotZ = (s16)(c * lbl_803DC2FC);
        }
    } else {
        s16 yawDelta;

        phase = sqrtf(curve->tangentX * curve->tangentX + curve->tangentZ * curve->tangentZ);
        yawDelta = (s16)(getAngle(curve->tangentX, curve->tangentZ) + 0x8000) - obj->anim.rotX;
        obj->anim.rotY = (s16)getAngle(curve->tangentY, phase);
        if (yawDelta < -0x800) {
            clamped = -0x800;
        } else if (yawDelta > 0x800) {
            clamped = 0x800;
        } else {
            clamped = yawDelta;
        }
        c = (s16)clamped;
        obj->anim.rotZ = (s16)(p->speed < 0.0f ? c : -c);
        obj->anim.rotX += (s16)(c < -0x100 ? -0x100 : c > 0x100 ? 0x100 : c);
        c = obj->anim.rotY;
        if (c < -0x64) {
            c = -0x64;
        } else if (c > 0x64) {
            c = 0x64;
        }
        obj->anim.rotY = c;
    }
    PSVECSubtract((Vec*)curvePos, &obj->anim.localPos, &diff);
    spd = gDrakorHoverpadSteerMaxSpeed;
    Obj_SteerVelocityTowardVector(obj, &obj->anim.velocity, &diff, spd, spd / 30.0f, 0.3f);
    PSVECAdd(&obj->anim.localPos, &obj->anim.velocity, &obj->anim.localPos);
}

void drakorhoverpad_initMain(GameObject* obj, void* desc) {
    DrakorHoverpadState* p = obj->extra;
    DrakorHoverpadFlags* f = &p->flags;
    DrakorHoverpadPathFlags* g = &p->pathFlags;
    DrakorHoverpadUpdateMainPlacement* d = (DrakorHoverpadUpdateMainPlacement*)desc;
    f32 initialSpeed;

    (obj)->anim.rotX = (s16)(d->rotXByte << 8);
    p->unk118 = (f32)d->unk1a;
    initialSpeed = 0.0f;
    p->speed = initialSpeed;
    f->bit20 = 0;
    f->b40 = 1;
    p->unk170 = 0;
    p->unk11C = initialSpeed;
    p->unk120 = initialSpeed;
    p->frameCounter = 0;
    switch (d->base.objectId) {
    case DRAKORHOVERPAD_SUBTYPE_TRACKING:
        g->f10 = 1;
        g->f04 = 1;
        g->f08 = 0;
        break;
    case DRAKORHOVERPAD_SUBTYPE_FREE:
        g->f10 = 0;
        g->f04 = 0;
        g->f08 = 1;
        break;
    }
    objAddObjectType(obj, DRAKORHOVERPAD_OBJGROUP);
    objAddObjectType(obj, VEHICLE_OBJECT_GROUP);
}

void drakorhoverpad_release(void) {
}

void drakorhoverpad_initialise(void) {
}
