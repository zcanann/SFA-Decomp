/*
 * SB_CageKyte (DLL 0x01F2) - Kyte, the captive baby Cloudrunner held in the
 * deck cage (SB_KyteCage) during the ShipBattle prologue (SB = the retail
 * "ShipBattle" map). This is the objType-0x121 child Krystal walks up to and
 * talks to after landing on the galleon.
 *
 * Its extra state is a single s16 chirp timer. Each update tick it counts
 * the timer down by framesThisStep, keeps interaction disabled, and measures
 * its distance to the player. When the timer expires it plays a chirp sound
 * unless suppressed by a GameBit, then re-arms with a random 400-600 frame
 * delay.
 */
#include "dlls/objects/498_SB_CageKyte.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"

#define SB_CAGE_KYTE_CHIRP_TIMER_MIN 400
#define SB_CAGE_KYTE_CHIRP_TIMER_MAX 600

int SB_CageKyte_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    if (obj->userData1 > 0) {
        obj->userData1--;
    }

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    animUpdate->flags = -2;
    animUpdate->movementState = 0;
    return 0;
}

int SB_CageKyte_getExtraSize(void) {
    return sizeof(SBCageKyteState);
}

int SB_CageKyte_getObjectTypeId(void) {
    return 1;
}

void SB_CageKyte_free(void) {
}

void SB_CageKyte_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    (void)obj;
    (void)renderArg2;
    (void)renderArg3;
    (void)renderArg4;
    (void)renderArg5;

    if (visible == 0) {
        return;
    }
}

void SB_CageKyte_hitDetect(void) {
}

void SB_CageKyte_update(GameObject* obj) {
    SBCageKyteState* state = obj->extra;
    GameObject* player;

    if (obj->userData1 > 0) {
        obj->userData1 -= 1;
    }

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    state->chirpTimer -= framesThisStep;
    player = Obj_GetPlayerObject();
    (void)Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);

    if (state->chirpTimer <= 0) {
        (void)randomGetRange(0, 10);
        if (mainGetBit(GAMEBIT_SBRelated0A71) == 0u) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_ice_freeze_316);
        }
        state->chirpTimer = randomGetRange(SB_CAGE_KYTE_CHIRP_TIMER_MIN, SB_CAGE_KYTE_CHIRP_TIMER_MAX);
    }
}

void SB_CageKyte_init(GameObject* obj) {
    obj->animEventCallback = SB_CageKyte_SeqFn;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void SB_CageKyte_release(void) {
}

void SB_CageKyte_initialise(void) {
}

ObjectDescriptor gSB_CageKyteObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_CageKyte_initialise,
    SB_CageKyte_release,
    0,
    (ObjectDescriptorCallback)SB_CageKyte_init,
    (ObjectDescriptorCallback)SB_CageKyte_update,
    SB_CageKyte_hitDetect,
    (ObjectDescriptorCallback)SB_CageKyte_render,
    SB_CageKyte_free,
    (ObjectDescriptorCallback)SB_CageKyte_getObjectTypeId,
    SB_CageKyte_getExtraSize,
};
