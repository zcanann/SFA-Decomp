#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/baddie_state.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/pad_api.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/baddie_frozen.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_api.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "dlls/objects/225_WispBaddie.h"
#include "main/trig_float_helpers.h"
#include "main/obj_link.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dolphin/mtx.h"
#include "main/dll/mikaladon.h"
#include "main/dll/magicPlant.h"
#include "main/dll/kooshy.h"
#include "main/dll/weevil.h"
#include "main/trig.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster_api.h"
#include "main/track_bbox_api.h"
#include "main/sky_interface.h"
#include "main/dll/duster.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "main/dll/duster_wb.h"
#include "main/obj_query.h"
#include "main/dll/hoodedzyck.h"
#include "main/camera_interface.h"
#include "main/model_light.h"
#include "main/dll/firecrawler.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/snowworm.h"
#include "main/dll/baddiewhirlpool.h"
#include "dolphin/mtx/vec.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

/* object-type id of the pollen-spit projectile spawned by spittingEbaSpawnPollen
 * (see file docblock). */

#define DUSTER_CHILD_OBJ_POLLEN_SPIT 0x47b
#define DUSTER_HIT_VOLUME_SLOT       10

extern f32 gDusterWallProbeOffsets[];

void rachnopFindWallPlane(GameObject* obj, void* state);

static inline int hoodedZyck_getAngleDelta(GameObject* obj, GameObject* target) {
    f32 d = (f32)(int)((u16)getAngle(obj->anim.localPosX - target->anim.localPosX,
                                     obj->anim.localPosZ - target->anim.localPosZ) -
                       (u16)obj->anim.rotX);
    if (d > 32768.0f) {
        d = -65535.0f + d;
    }
    if (d < -32768.0f) {
        d = 65535.0f + d;
    }
    return d;
}

void fireflyLanternGetTargetAngleAndDistance(GameObject* obj, void* state, u16* outAngle, float* outDistance) {
    Vec targetPos;
    Vec tmpA;
    Vec vecA;
    Vec crossA;
    Vec tmpB;
    Vec vecB;
    Vec crossB;
    Vec axisA;
    Vec axisB;
    f32 objY;
    f32 dxDiff;
    f32 dy;
    f32 d;
    GameObject* targetObj;
    int delta;
    u32 angle;
    EnemyState* fs = (EnemyState*)state;

    vecA.x = fs->wallPlane.anchorX;
    vecA.y = fs->wallPlane.anchorY;
    vecA.z = fs->wallPlane.anchorZ;
    PSVECSubtract(&vecA, &obj->anim.localPos, &tmpA);
    d = PSVECDotProduct(&tmpA, (Vec*)fs->wallPlane.normal);
    vecA.x = fs->wallPlane.normal[0] * d + obj->anim.localPosX;
    vecA.y = fs->wallPlane.normal[1] * d + (objY = obj->anim.localPosY);
    vecA.z = fs->wallPlane.normal[2] * d + obj->anim.localPosZ;
    axisA.x = 0.0f;
    axisA.y = 1.0f;
    axisA.z = 0.0f;
    PSVECCrossProduct(&axisA, (Vec*)fs->wallPlane.normal, &crossA);
    PSVECNormalize(&crossA, &crossA);
    if (crossA.x != 0.0f) {
        dxDiff = (obj->anim.localPosX - fs->wallPlane.anchorX) / crossA.x;
    } else {
        dxDiff = (obj->anim.localPosZ - fs->wallPlane.anchorZ) / crossA.z;
    }
    targetObj = fs->trackedObj;
    targetPos.x = targetObj->anim.localPosX;
    targetPos.y = 10.0f + targetObj->anim.localPosY;
    targetPos.z = targetObj->anim.localPosZ;
    vecB.x = fs->wallPlane.anchorX;
    vecB.y = fs->wallPlane.anchorY;
    vecB.z = fs->wallPlane.anchorZ;
    PSVECSubtract(&vecB, &targetPos, &tmpB);
    d = PSVECDotProduct(&tmpB, (Vec*)fs->wallPlane.normal);
    vecB.x = fs->wallPlane.normal[0] * d + targetPos.x;
    vecB.y = fs->wallPlane.normal[1] * d + (dy = targetPos.y);
    vecB.z = fs->wallPlane.normal[2] * d + targetPos.z;
    axisB.x = 0.0f;
    axisB.y = 1.0f;
    axisB.z = 0.0f;
    PSVECCrossProduct(&axisB, (Vec*)fs->wallPlane.normal, &crossB);
    PSVECNormalize(&crossB, &crossB);
    if (crossB.x != 0.0f) {
        d = (targetPos.x - fs->wallPlane.anchorX) / crossB.x;
    } else {
        d = (targetPos.z - fs->wallPlane.anchorZ) / crossB.z;
    }
    dxDiff = dxDiff - d;
    dy = objY - dy;
    angle = getAngle(-dy, dxDiff) & 0xffff;
    delta = angle - (obj->anim.rotY & 0xffff);
    if (delta > 0x8000) {
        delta = delta - 0xffff;
    }
    if (delta < -0x8000) {
        delta = delta + 0xffff;
    }
    if (delta < 0) {
        delta = -delta;
    }
    *outAngle = delta & 0xffff;
    *outDistance = sqrtf(dxDiff * dxDiff + dy * dy);
}

u32 fireflyLanternSteerTowardTarget(short* obj, void* state, u32 turnTime, f32 maxDistance) {
    Vec moveTarget;
    Vec moveDelta;
    Vec targetPos;
    Vec tmpA;
    Vec vecA;
    Vec crossA;
    Vec tmpB;
    Vec vecB;
    Vec crossB;
    Vec axisA;
    Vec axisB;
    f32 objY;
    f32 targetY;
    f32 dy;
    f32 dxA;
    f32 dxDiff;
    f32 d;
    f32 turnStep;
    s16 rot;
    GameObject* targetObj;
    int delta;
    int angleStep;
    u32 angle;
    GameObject* o = (GameObject*)obj;
    EnemyState* fs = (EnemyState*)state;

    vecA.x = fs->wallPlane.anchorX;
    vecA.y = fs->wallPlane.anchorY;
    vecA.z = fs->wallPlane.anchorZ;
    PSVECSubtract(&vecA, &o->anim.localPos, &tmpA);
    d = PSVECDotProduct(&tmpA, (Vec*)fs->wallPlane.normal);
    vecA.x = fs->wallPlane.normal[0] * d + o->anim.localPosX;
    vecA.y = fs->wallPlane.normal[1] * d + (objY = o->anim.localPosY);
    vecA.z = fs->wallPlane.normal[2] * d + o->anim.localPosZ;
    axisA.x = 0.0f;
    axisA.y = 1.0f;
    axisA.z = 0.0f;
    PSVECCrossProduct(&axisA, (Vec*)fs->wallPlane.normal, &crossA);
    PSVECNormalize(&crossA, &crossA);
    if (crossA.x != 0.0f) {
        dxA = (o->anim.localPosX - fs->wallPlane.anchorX) / crossA.x;
    } else {
        dxA = (o->anim.localPosZ - fs->wallPlane.anchorZ) / crossA.z;
    }
    targetObj = fs->trackedObj;
    targetPos.x = targetObj->anim.localPosX;
    targetPos.y = 10.0f + targetObj->anim.localPosY;
    targetPos.z = targetObj->anim.localPosZ;
    vecB.x = fs->wallPlane.anchorX;
    vecB.y = fs->wallPlane.anchorY;
    vecB.z = fs->wallPlane.anchorZ;
    PSVECSubtract(&vecB, &targetPos, &tmpB);
    d = PSVECDotProduct(&tmpB, (Vec*)fs->wallPlane.normal);
    vecB.x = fs->wallPlane.normal[0] * d + targetPos.x;
    vecB.y = fs->wallPlane.normal[1] * d + (targetY = targetPos.y);
    vecB.z = fs->wallPlane.normal[2] * d + targetPos.z;
    axisB.x = 0.0f;
    axisB.y = 1.0f;
    axisB.z = 0.0f;
    PSVECCrossProduct(&axisB, (Vec*)fs->wallPlane.normal, &crossB);
    PSVECNormalize(&crossB, &crossB);
    if (crossB.x != 0.0f) {
        d = (targetPos.x - fs->wallPlane.anchorX) / crossB.x;
    } else {
        d = (targetPos.z - fs->wallPlane.anchorZ) / crossB.z;
    }
    dxDiff = dxA - d;
    dy = objY - targetY;
    angle = getAngle(-dy, dxDiff) & 0xffff;
    rot = o->anim.rotY;
    delta = angle - (rot & 0xffff);
    if (delta > 0x8000) {
        delta = delta - 0xffff;
    }
    if (delta < -0x8000) {
        delta = delta + 0xffff;
    }
    turnStep = timeDelta / (f32)(turnTime & 0xffff);
    if (turnStep > 1.0f) {
        turnStep = 1.0f;
    }
    angleStep = (int)((f32)delta * turnStep);
    o->anim.rotX = (s16)(rot + angleStep);
    o->anim.rotZ = 0x4000;
    o->anim.rotY = o->anim.rotX;
    o->anim.rotX = getAngle(fs->wallPlane.normal[2], -fs->wallPlane.normal[0]);
    turnStep = sqrtf(dxDiff * dxDiff + dy * dy);
    if (turnStep > maxDistance) {
        f32 ratio = 1.0f / turnStep;
        dxDiff = maxDistance * (dxDiff * ratio);
        dy = maxDistance * (dy * ratio);
    }
    dxA -= dxDiff;
    dy = objY - dy;
    wallPlaneClampMoveTarget(&moveTarget.x, &fs->wallPlane, dxA, dy);
    PSVECSubtract(&moveTarget, &o->anim.localPos, &moveDelta);
    objMove((GameObject*)obj, moveDelta.x, moveDelta.y, moveDelta.z);
    turnStep = 0.0f;
    o->anim.velocityX = turnStep;
    o->anim.velocityY = turnStep;
    o->anim.velocityZ = turnStep;
    if (angleStep < 0) {
        angleStep = -angleStep;
    }
    return angleStep & 0xffff;
}

void wallPlaneClampMoveTarget(float* outPos, WallPlaneState* plane, float lateral, float height) {
    float hi;
    float lo;
    Vec sideAxis;
    Vec up;
    float upConst;
    float scale;

    hi = plane->boundMin - 15.0f;
    if (height > hi) {
        height = hi;
    } else {
        lo = (50.0f) + plane->anchorY;
        if (height < lo) {
            height = lo;
        }
    }
    if (plane->axisLimit > 0.0f) {
        hi = plane->axisLimit - 15.0f;
        lo = 15.0f;
    } else {
        hi = -15.0f;
        lo = 15.0f + plane->axisLimit;
    }
    if (lateral > hi) {
        lateral = hi;
    } else {
        if (lateral < lo) {
            lateral = lo;
        }
    }
    outPos[1] = height;
    upConst = 0.0f;
    up.x = upConst;
    up.y = 1.0f;
    up.z = upConst;
    PSVECCrossProduct(&up, (Vec*)plane->normal, &sideAxis);
    PSVECNormalize(&sideAxis, &sideAxis);
    outPos[0] = lateral * sideAxis.x + plane->anchorX;
    outPos[2] = lateral * sideAxis.z + plane->anchorZ;
    scale = (2.0f);
    outPos[0] = scale * plane->normal[0] + outPos[0];
    outPos[1] = scale * plane->normal[1] + outPos[1];
    outPos[2] = scale * plane->normal[2] + outPos[2];
}

void rachnopFindWallPlane(GameObject* obj, void* state) {
    u8 didHit;
    float* probeOffsets;
    int i;
    f32 dot;
    float maxv[3];
    float minv[3];
    float sideAxis0[3];
    float cv[3];
    float av[3];
    float toAnchor[3];
    float bv[3];
    float sideAxis[3];
    float dv[3];
    float hit[18];
    EnemyState* fs = (EnemyState*)state;

    didHit = 0;
    probeOffsets = gDusterWallProbeOffsets;
    for (i = 0; didHit == 0 && i < 4; i++) {
        maxv[0] = obj->anim.localPosX + probeOffsets[i * 2 + 0];
        maxv[1] = obj->anim.localPosY;
        maxv[2] = obj->anim.localPosZ + probeOffsets[i * 2 + 1];
        minv[0] = obj->anim.localPosX - probeOffsets[i * 2 + 0];
        minv[1] = obj->anim.localPosY;
        minv[2] = obj->anim.localPosZ - probeOffsets[i * 2 + 1];
        didHit = trackGetLineIntersect(maxv, minv, 0.0f, 3, (TrackLineIntersectResult*)hit, obj, 5, 3, 0xff, 0);
    }
    if (didHit != 0) {
        obj->anim.localPosX = (hit[17] - (15.0f)) * ((minv[0] - maxv[0]) / (50.0f)) + maxv[0];
        obj->anim.localPosZ = (hit[17] - (15.0f)) * ((minv[2] - maxv[2]) / (50.0f)) + maxv[2];
        fs->wallPlane.normal[0] = hit[7];
        fs->wallPlane.normal[1] = hit[8];
        fs->wallPlane.normal[2] = hit[9];
        fs->wallPlane.normalW = hit[10];
        fs->wallPlane.anchorY = (hit[3] > hit[4]) ? hit[3] : hit[4];
        fs->wallPlane.boundMin = (hit[15] < hit[16]) ? hit[15] : hit[16];
        av[0] = 0.0f;
        av[1] = 1.0f;
        av[2] = 0.0f;
        PSVECCrossProduct((Vec*)av, (Vec*)fs->wallPlane.normal, (Vec*)sideAxis0);
        PSVECNormalize((Vec*)sideAxis0, (Vec*)sideAxis0);
        fs->wallPlane.anchorX = hit[1];
        fs->wallPlane.anchorZ = hit[5];
        cv[0] = hit[2];
        cv[2] = hit[6];
        bv[0] = fs->wallPlane.anchorX;
        bv[1] = fs->wallPlane.anchorY;
        bv[2] = fs->wallPlane.anchorZ;
        PSVECSubtract((Vec*)bv, (Vec*)cv, (Vec*)toAnchor);
        dot = PSVECDotProduct((Vec*)toAnchor, (Vec*)fs->wallPlane.normal);
        bv[0] = fs->wallPlane.normal[0] * dot + cv[0];
        bv[1] = fs->wallPlane.normal[1] * dot + cv[1];
        bv[2] = fs->wallPlane.normal[2] * dot + cv[2];
        dv[0] = 0.0f;
        dv[1] = 1.0f;
        dv[2] = 0.0f;
        PSVECCrossProduct((Vec*)dv, (Vec*)fs->wallPlane.normal, (Vec*)sideAxis);
        PSVECNormalize((Vec*)sideAxis, (Vec*)sideAxis);
        if (sideAxis[0] != 0.0f) {
            fs->wallPlane.axisLimit = (cv[0] - fs->wallPlane.anchorX) / sideAxis[0];
        } else {
            fs->wallPlane.axisLimit = (cv[2] - fs->wallPlane.anchorZ) / sideAxis[2];
        }
        fs->userData1 = 1;
    }
}

f32 gDusterWallProbeOffsets[] = {
    50.0f, 0.0f, -50.0f, 0.0f, 0.0f, 50.0f, 0.0f, -50.0f,
};

void rachnopUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int eventKind, int wpad0, int wpad1,
                              Vec* wpad2, int wpad3) {
    EnemyState* enemyState = (EnemyState*)state;
    if (eventKind == 0x10) {
        enemyState->flags2E8 |= 0x20;
    } else if (eventKind != 0x11) {
        enemyState->flags2E8 |= 8;
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_lash_254);
        enemyState->current = 0;
    }
    return;
}

void rachnopUpdateIdle(GameObject* obj, void* state) {
    EnemyState* enemyState = (EnemyState*)state;

    if (enemyState->userData1 == 0) {
        rachnopFindWallPlane(obj, state);
    } else {
        if ((enemyState->trackedObj->anim.classId == 1) && playerIsClimbingWall(enemyState->trackedObj) != 0) {
            enemyState->flags2E4 &= ~0x10000;
        }
        if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_id_253);
            Baddie_SetMove(obj, state, 2, 1.0f, 0, 0);
        }
    }
    return;
}

void rachnopUpdateApproach(GameObject* obj, void* state) {
    EnemyState* enemyState = (EnemyState*)state;

    if (enemyState->userData1 == 0) {
        rachnopFindWallPlane(obj, state);
    } else if ((enemyState->trackedObj->anim.classId == 1) && playerIsClimbingWall(enemyState->trackedObj) != 0) {
        fireflyLanternSteerTowardTarget((short*)obj, state, 0x19, 0.5f);
        if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
            Baddie_SetMove(obj, state, 0, (0.5f), 0, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_id_252);
        }
    } else {
        enemyState->flags2E4 |= 0x10000;
    }
    return;
}

void rachnopUpdateAttack(GameObject* obj, void* state) {
    EnemyState* enemyState = (EnemyState*)state;
    short move;
    u16 outIds[2];
    float outVec[3];

    if (enemyState->userData1 == 0) {
        rachnopFindWallPlane(obj, state);
    } else if ((enemyState->trackedObj->anim.classId == 1) && playerIsClimbingWall(enemyState->trackedObj) != 0) {
        ObjHits_SetHitVolumeSlot(&obj->anim, DUSTER_HIT_VOLUME_SLOT, 1, 0);
        move = obj->anim.currentMove;
        if (move == 3) {
            fireflyLanternSteerTowardTarget((short*)obj, state, 0x19, 0.0f);
        } else if ((move == 0) || (move == 1)) {
            fireflyLanternSteerTowardTarget((short*)obj, state, 0x19, 0.5f);
        }
        fireflyLanternGetTargetAngleAndDistance(obj, state, outIds, outVec);
        if (((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) ||
            ((outIds[0] < 0x5dc && (obj->anim.currentMove != 1)))) {
            if (outIds[0] < 0x5dc) {
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_251);
                Baddie_SetMove(obj, state, 1, 0.5f, 0, 0);
            } else {
                Baddie_SetMove(obj, state, 3, 0.5f, 0, 0);
            }
        }
    } else {
        enemyState->flags2E4 |= 0x10000;
    }
    return;
}

void rachnopInit(GameObject* unused, void* state) {
    EnemyState* enemyState = (EnemyState*)state;
    float fa;
    float fb;

    enemyState->sightRange = (25.0f);
    enemyState->flags2E4 = 1;
    fa = (0.1f);
    enemyState->animPlaySpeed = (0.1f);
    enemyState->gravity = fa;
    enemyState->drag = (0.97f);
    enemyState->moveId0 = 0;
    fb = 1.5f;
    enemyState->moveSpeedScale0 = 1.5f;
    enemyState->moveId1 = 4;
    fa = 1.0f;
    enemyState->moveSpeedScale1 = 1.0f;
    enemyState->moveId2 = 0;
    enemyState->moveSpeedScale2 = fb;
    enemyState->duster.phaseTimer = 0.0f;
    enemyState->userData1 = 0;
    enemyState->userData2 = 0;
    enemyState->pathStep = fa;
    return;
}
