/*
 * CNThitObjec (DLL 694) consumes selected priority hits while armed by a game
 * bit. The hit-volume byte is subtracted from health. Depletion sets the done
 * bit; update subsequently latches disabled. Mode 2 renders the object, while
 * other modes hide it and use a placement radius for the sphere hitbox.
 * Sequence event bytes supply explosion scales, not effect IDs.
 *
 * The following MCUpgrade object's dialogue callback remains in this TU.
 */
#include "dlls/objects/694_CNThitObjec.h"
#include "game/objects/object.h"
#include "main/dll/mcupgrade_state.h"
#include "main/audio/sfx_play_api.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/maketex_api.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "sys/objects.h"

#define CNTHIT_MODE_VISIBLE_OBJECT 2
#define CNTHIT_PROFILE_COUNT 3
#define CNTHIT_DEFAULT_VISIBLE_EXPLOSION_SCALE 80

/* These are placement identities, not model IDs. */
#define CNTHIT_NO_EXPLOSION_IDENT_A 0x470EA
#define CNTHIT_NO_EXPLOSION_IDENT_B 0x480F5
#define CNTHIT_NO_EXPLOSION_IDENT_C 0x46710
#define CNTHIT_NO_EXPLOSION_IDENT_D 0x49B43

/* Entries are engine hit priorities. Profile 2 points at profile 0 but has
 * zero entries; the fourth count byte is outside the three-profile table. */
static int sCntHitSourcesProfile0[2] = {0xf, 0xe};
static int sCntHitSourceProfile1 = 5;
static CntHitObjectProfileCounts sCntHitSourceCounts = {{2, 1, 0}, 0};
static int* sCntHitSourcesByProfile[3] = {
    sCntHitSourcesProfile0,
    &sCntHitSourceProfile1,
    sCntHitSourcesProfile0,
};

int cnthitobjec_SeqFn(GameObject* obj, int unused, ObjSeqState* event) {
    int i;
    for (i = 0; i < event->eventCount; i++) {
        spawnExplosion(obj, (f32)(u32)event->eventIds[i], 1, 1, 1, 1, 0, 1, 0);
    }
    return 0;
}

int cnthitobjec_getExtraSize(void) {
    return sizeof(CntHitObjectState);
}

int cnthitobjec_getObjectTypeId(void) {
    return 0;
}

void cnthitobjec_free(void) {
}

void cnthitobjec_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale) {
    CntHitObjectState* state = obj->extra;
    CntHitObjectPlacementPrefix* setup = (CntHitObjectPlacementPrefix*)obj->anim.placementData;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT && state->flags.disabled == 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void cnthitobjec_hitDetect(GameObject* obj) {
    CntHitObjectState* state;
    CntHitObjectPlacementPrefix* setup = (CntHitObjectPlacementPrefix*)obj->anim.placementData;
    int hit;
    u32 hitVolume;
    int amount;
    int placementIdent;

    state = obj->extra;
    if (state->remainingHealth == 0) {
        return;
    }
    hit = ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume);
    if (hit == 0) {
        return;
    }
    if (state->allowedHitPriorityCount == 0) {
        return;
    }
    if (arrayIndexOf(state->allowedHitPriorities, state->allowedHitPriorityCount, hit) == -1) {
        return;
    }
    /* The hit-volume ID is used as the health decrement. */
    state->remainingHealth -= hitVolume;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
        Obj_SetModelColorFadeRecursive(obj, 30, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff_496); /* hit */
    }
    if (state->remainingHealth <= 0) {
        CntHitObjectPlacementPrefix* s = (CntHitObjectPlacementPrefix*)obj->anim.placementData;
        state->remainingHealth = 0;
        mainSetBits(s->doneGameBit, 1);
        if (s->mode != 0) {
            if (s->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
                amount = CNTHIT_DEFAULT_VISIBLE_EXPLOSION_SCALE;
            } else {
                amount = s->modeParam.hidden.radiusAndExplosionScale;
            }
            placementIdent = ((CntHitObjectPlacementPrefix*)obj->anim.placementData)->base.ident;
            if (placementIdent != CNTHIT_NO_EXPLOSION_IDENT_A && placementIdent != CNTHIT_NO_EXPLOSION_IDENT_B &&
                placementIdent != CNTHIT_NO_EXPLOSION_IDENT_C && placementIdent != CNTHIT_NO_EXPLOSION_IDENT_D) {
                spawnExplosion(obj, amount, 1, 1, 1, 1, 0, 1, 0);
            }
            if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_sexpl2_c); /* destroy */
            }
        }
    } else {
        Sfx_PlayFromObject(obj, SFXTRIG_sc_snort03);
    }
}

void cnthitobjec_update(GameObject* obj) {
    CntHitObjectPlacementPrefix* setup;
    CntHitObjectState* state = obj->extra;
    setup = (CntHitObjectPlacementPrefix*)obj->anim.placementData;

    if (state->flags.disabled == 0) {
        if (mainGetBit(setup->doneGameBit) != 0) {
            state->flags.disabled = 1;
            ObjHits_DisableObject(obj);
        }
    }

    if (state->flags.disabled == 0 && state->remainingHealth == 0 && mainGetBit(setup->startGameBit) != 0) {
        ObjHits_EnableObject(obj);
        state->remainingHealth = setup->startHealth;
        if (setup->mode != CNTHIT_MODE_VISIBLE_OBJECT) {
            ObjHitbox_SetSphereRadius(&obj->anim, setup->modeParam.hidden.radiusAndExplosionScale);
        }
    }
}

void cnthitobjec_init(GameObject* obj, CntHitObjectPlacementPrefix* setup) {
    CntHitObjectState* state = obj->extra;
    CntHitObjectPlacementPrefix* setupData = setup;

    state->remainingHealth = 0;
    /* Sign-extend the placement byte before unsigned modulo, then store it. */
    setupData->hitPriorityProfile = (u32)setupData->hitPriorityProfile % CNTHIT_PROFILE_COUNT;
    state->allowedHitPriorities = sCntHitSourcesByProfile[setupData->hitPriorityProfile];
    state->allowedHitPriorityCount = sCntHitSourceCounts.counts[setupData->hitPriorityProfile];
    if (state->allowedHitPriorities == &sCntHitSourceProfile1) {
        ObjHits_ClearSourceMask(&obj->anim, 8);
    }
    if (setupData->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
        obj->anim.rotX = setupData->modeParam.visible.rotationX;
    } else {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if (mainGetBit(setupData->doneGameBit) != 0) {
        state->flags.disabled = 1;
        ObjHits_DisableObject(obj);
    }
    obj->animEventCallback = cnthitobjec_SeqFn;
}

void cnthitobjec_release(void) {
}

void cnthitobjec_initialise(void) {
}

int mcupgrade_SeqFn(GameObject* obj, int unused, ObjSeqState* event) {
    if (event->eventCount != 0) {
        (*gGameUIInterface)->showNpcDialogue(((McUpgradeSetup*)obj->anim.placementData)->dialogueTextId, 0x14, 0x8c, 0);
    }
    return 0;
}

CntHitObjectDescriptor gCNThitObjecObjDescriptor = { {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    cnthitobjec_initialise,
    cnthitobjec_release,
    0,
    (ObjectDescriptorCallback)cnthitobjec_init,
    (ObjectDescriptorCallback)cnthitobjec_update,
    (ObjectDescriptorCallback)cnthitobjec_hitDetect,
    (ObjectDescriptorCallback)cnthitobjec_render,
    cnthitobjec_free,
    (ObjectDescriptorCallback)cnthitobjec_getObjectTypeId,
    cnthitobjec_getExtraSize,
    },
    0,
};
