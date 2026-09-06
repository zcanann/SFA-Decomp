/*
 * SB_ShipHead (DLL 0x1EA) - the figurehead/prow of General Scales' galleon
 * in the ShipBattle prologue (SB = the retail "ShipBattle" map). While the
 * parent Galleon's camera/cutscene state allows it the head plays its hiss
 * loop near the player, accepts hits (4 HP), spits homing fireballs
 * (SB_FireBall) along its rigging path and lobs projectiles at the
 * Cloudrunner on cue, advancing its animation each frame. State lives in the
 * SBShipHeadState extra block. The Galleon is queried through its anim.dll
 * vtable (slots 0x20/0x28/0x2c) and through SB_Galleon_getCameraState.
 */
#include "dlls/objects/490_SB_ShipHead.h"

#include "dlls/objects/488_SB_Galleon.h"
#include "dlls/objects/493_SB_FireBall.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/obj_list.h"
#include "main/obj_path.h"
#include "main/objhits.h"
#include "main/object_transform.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

u8 gSbShipHeadHasFiredFireball = 1;

#define SB_SHIP_HEAD_OBJECT_GROUP     3
#define SB_SHIP_HEAD_PARTICLE_EFFECT  0x7AA
#define SB_SHIP_HEAD_HISS_SFX_CHANNEL 0x40

/* parent Galleon anim.romDefNo variants */
#define SB_GALLEON_FIRING_SEQUENCE_ID 0x8E
/* object type id (anim.romDefNo) of the galleon-side target object the head tracks */
#define SB_SHIP_HEAD_TARGET_SEQUENCE_ID 0x8C
/* object type id of the head's own homing-fireball projectile */
#define SB_FIREBALL_OBJECT_ID 0x114
/* object type id of the lobbed projectile spawned on the firing cue */
#define SB_PROJECTILE_OBJECT_ID 0x138

int gSbShipHeadPrevGalleonPhase;

static const f32 gSbShipHeadHissSfxDistance = 400.0f;
static const f32 gSbShipHeadFireballSpeed = 30.0f;
static const f32 gSbShipHeadAnimAdvanceRate = 0.005f;

int SB_ShipHead_getExtraSize(void) {
    return sizeof(SBShipHeadState);
}

int SB_ShipHead_getObjectTypeId(void) {
    return 0x1;
}

void SB_ShipHead_free(GameObject* obj) {
    objFreeObjectType(obj, SB_SHIP_HEAD_OBJECT_GROUP);
}

void SB_ShipHead_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    int damagePhase;
    GameObject* parentObj;
    SBShipHeadState* state;
    GameObject* object;
    u8 particleIndex;
    PartFxSpawnParams effectParams;

    object = obj;
    if (visible != 0) {
        state = object->extra;
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        parentObj = object->anim.parent;
        if ((((void*)parentObj != NULL && (parentObj->anim.romDefNo == SB_GALLEON_FIRING_SEQUENCE_ID)) &&
             (damagePhase = SB_GALLEON_VTBL(parentObj)->getDamagePhase(parentObj), damagePhase != 0)) &&
            (damagePhase != 2)) {
            state->swayA = state->swayA - timeDelta;
            if (state->swayA <= 0.0f) {
                state->swayA += 10.0f;
            }
            state->swayB = state->swayB - timeDelta;
            if (state->swayB <= 0.0f) {
                state->swayB += 1.0f;
            }
            effectParams.scale = 3.0f;
            effectParams.arg3 = 0xC0A;
            ObjPath_GetPointWorldPosition(obj, 0xD, &effectParams.posX, &effectParams.posY, &effectParams.posZ, 0);
            effectParams.posX = effectParams.posX - object->anim.worldPosX;
            effectParams.posY = effectParams.posY - object->anim.worldPosY;
            effectParams.posZ = effectParams.posZ - object->anim.worldPosZ;
            for (particleIndex = 0; particleIndex < framesThisStep; particleIndex++) {
                (*gPartfxInterface)->spawnObject((void*)obj, SB_SHIP_HEAD_PARTICLE_EFFECT, &effectParams, 2, -1, NULL);
            }
        }
    }
    return;
}

void SB_ShipHead_update(GameObject* obj) {
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 speedScale;
    GameObject* player;
    u8 firingCue;
    GameObject* galleon;
    SBShipHeadState* state;
    int galleonPhase;
    int cameraState;
    int objectIndex;
    int result;
    ObjPlacement* placementBytes;
    GameObject* hit;
    int messageParam;
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
    int objectStart;
    int objectEnd;
    int message;
    int messageSender[2];
    GameObject* object;

    object = obj;
    firingCue = 0;
    player = Obj_GetPlayerObject();
    galleon = object->anim.parent;
    if (galleon == 0) {
        return;
    }
    cameraState = SB_Galleon_getCameraState(getSbGalleon());
    if (cameraState == 2) {
        if (Vec_distance(&player->anim.worldPosX, &object->anim.worldPosX) < gSbShipHeadHissSfxDistance) {
            Sfx_PlayFromObject(obj, SFXTRIG_en_trpopn_c_312);
        } else {
            Sfx_StopObjectChannel(obj, SB_SHIP_HEAD_HISS_SFX_CHANNEL);
        }
    }
    galleonPhase = galleon->userData1;
    state = object->extra;
    if ((void*)state->target == 0) {
        GameObject** objects = ObjList_GetObjects(&objectStart, &objectEnd);
        for (objectIndex = objectStart; objectIndex < objectEnd; objectIndex++) {
            if ((objects[objectIndex])->anim.romDefNo == SB_SHIP_HEAD_TARGET_SEQUENCE_ID) {
                state->target = objects[objectIndex];
                objectIndex = objectEnd;
            }
        }
    }
    if ((int)ObjMsg_Pop(obj, (u32*)&message, (u32*)messageSender, (u32*)&messageParam) != 0) {
        switch (message) {
        case 0x130001:
            break;
        case 0x130002:
            firingCue = 1;
            break;
        case 0x130003:
            firingCue = 2;
            break;
        }
    }
    if ((SB_GALLEON_VTBL(galleon)->getPhase(galleon) >= 2) && (object->userData2 <= 0) &&
        (((u32)(galleonPhase - 3) <= 1 || (galleonPhase == 5))) &&
        (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0) && (hit->anim.romDefNo != SB_FIREBALL_OBJECT_ID)) {
        Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_wp_gcfir1_c_37);
        state->health -= 1;
        if (state->health <= 0) {
            SB_GALLEON_VTBL(galleon)->onPartDestroyed(galleon);
            object->userData2 = 300;
            ObjHits_DisableObject(obj);
        }
    }
    if (object->userData2 > 0) {
        object->userData2 = object->userData2 - framesThisStep;
    }
    if (galleonPhase == 8) {
        object->userData1 = object->userData1 + 1;
        if (object->userData1 > 10) {
            object->userData1 = 0;
        }
    }
    if ((galleonPhase == 5) && (gSbShipHeadPrevGalleonPhase != 5)) {
        ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
        gSbShipHeadHasFiredFireball = 0;
    }
    if ((((object->anim.currentMove == 1) && (object->anim.currentMoveProgress >= 0.5f)) &&
         (gSbShipHeadHasFiredFireball == 0)) &&
        ((u8)Obj_CanSetupObject() != 0)) {
        gSbShipHeadHasFiredFireball = 1;
        object->userData1 = object->userData1 + framesThisStep;
        Sfx_PlayFromObject(obj, SFXTRIG_gcexp1_c);
        object->anim.localPosY += 50.0f;
        object->anim.localPosZ = object->anim.localPosZ - 300.0f;
        Obj_GetWorldPosition(obj, &spawnX, &spawnY, &spawnZ);
        object->anim.localPosY = object->anim.localPosY - 50.0f;
        object->anim.localPosZ += 300.0f;
        placementBytes = (ObjPlacement*)Obj_AllocObjectSetup(0x18, SB_FIREBALL_OBJECT_ID);
        placementBytes->color[2] = 0xff;
        placementBytes->color[3] = 0xff;
        placementBytes->color[0] = 2;
        placementBytes->color[1] = 1;
        placementBytes->posX = spawnX;
        placementBytes->posY = spawnY;
        placementBytes->posZ = spawnZ;
        result = (int)objSetupObject(placementBytes, 5, -1, -1, 0);
        deltaX = player->anim.worldPosX - ((GameObject*)result)->anim.localPosX;
        deltaY = (player->anim.worldPosY - gSbShipHeadFireballSpeed) - ((GameObject*)result)->anim.localPosY;
        deltaZ = player->anim.worldPosZ - ((GameObject*)result)->anim.localPosZ;
        speedScale = gSbShipHeadFireballSpeed / sqrtf(deltaZ * deltaZ + (deltaX * deltaX + deltaY * deltaY));
        ((GameObject*)result)->anim.velocityX = deltaX * speedScale;
        ((GameObject*)result)->anim.velocityY = deltaY * speedScale;
        ((GameObject*)result)->anim.velocityZ = deltaZ * speedScale;
        ((GameObject*)result)->userData1 = 0x78;
        ((GameObject*)result)->userData2 = (int)state->target;
    }
    if ((firingCue == 1) && ((u8)Obj_CanSetupObject() != 0)) {
        Sfx_PlayFromObject(obj, SFXTRIG_gcexp1_c);
        player = Obj_GetPlayerObject();
        placementBytes = (ObjPlacement*)Obj_AllocObjectSetup(0x18, SB_PROJECTILE_OBJECT_ID);
        placementBytes->posX = 100.0f + player->anim.worldPosX;
        placementBytes->posY = 50.0f + (player->anim.worldPosY + randomGetRange(-6, 6));
        placementBytes->posZ = 45.0f + (player->anim.worldPosZ + randomGetRange(-6, 6));
        placementBytes->color[0] = 2;
        placementBytes->color[1] = 1;
        placementBytes->color[2] = 0xff;
        placementBytes->color[3] = 0xff;
        objSetupObject(placementBytes, 5, -1, -1, 0);
    }
    result = ObjAnim_AdvanceCurrentMove(obj, gSbShipHeadAnimAdvanceRate, timeDelta, NULL);
    if ((object->anim.currentMove == 1) && (result != 0)) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    }
    gSbShipHeadPrevGalleonPhase = galleonPhase;
}

void SB_ShipHead_init(GameObject* obj) {
    SBShipHeadState* state = obj->extra;

    objAddObjectType(obj, SB_SHIP_HEAD_OBJECT_GROUP);
    ObjMsg_AllocQueue(obj, 10);
    state->health = 4;
    state->swayB += 1.0f;
    state->swayA += 10.0f;
}

ObjectDescriptor gSB_ShipHeadObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SB_ShipHead_init,
    (ObjectDescriptorCallback)SB_ShipHead_update,
    0,
    (ObjectDescriptorCallback)SB_ShipHead_render,
    (ObjectDescriptorCallback)SB_ShipHead_free,
    (ObjectDescriptorCallback)SB_ShipHead_getObjectTypeId,
    SB_ShipHead_getExtraSize,
};
