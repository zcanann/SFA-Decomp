#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/cnthitobjec_state.h"
#include "main/obj_placement.h"

#include "main/audio/sfx_ids.h"

#define CNTHIT_MODE_VISIBLE_OBJECT 2
#define CNTHIT_PROFILE_COUNT 3
#define CNTHIT_DEFAULT_VISIBLE_EXPLOSION_SIZE 80

#define CNTHIT_MODEL_NO_EXPLOSION_A 0x470EA
#define CNTHIT_MODEL_NO_EXPLOSION_B 0x480F5
#define CNTHIT_MODEL_NO_EXPLOSION_C 0x46710
#define CNTHIT_MODEL_NO_EXPLOSION_D 0x49B43

typedef struct CntHitObjectSetup {
    ObjPlacement base;
    s8 hitSourceProfile;
    u8 mode;
    s16 startHealth;
    s16 explosionSize;
    s16 doneGameBit;
    s16 startGameBit;
} CntHitObjectSetup;

typedef struct CntHitObjectAnimEvent {
    u8 pad0[0x81];
    u8 explosionIds[10];
    u8 explosionCount;
} CntHitObjectAnimEvent;

STATIC_ASSERT(offsetof(CntHitObjectSetup, hitSourceProfile) == 0x18);
STATIC_ASSERT(offsetof(CntHitObjectSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(CntHitObjectSetup, startHealth) == 0x1A);
STATIC_ASSERT(offsetof(CntHitObjectSetup, explosionSize) == 0x1C);
STATIC_ASSERT(offsetof(CntHitObjectSetup, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CntHitObjectSetup, startGameBit) == 0x20);
STATIC_ASSERT(sizeof(CntHitObjectSetup) == 0x24);
STATIC_ASSERT(offsetof(CntHitObjectAnimEvent, explosionIds) == 0x81);
STATIC_ASSERT(offsetof(CntHitObjectAnimEvent, explosionCount) == 0x8B);

int cnthitobjec_getExtraSize(void) { return 0xc; }

int cnthitobjec_getObjectTypeId(void) { return 0; }

void cnthitobjec_free(void) {}

void cnthitobjec_release(void) {}

void cnthitobjec_initialise(void) {}

void cnthitobjec_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    CntHitObjectState *state = ((GameObject *)obj)->extra;
    CntHitObjectSetup *setup = (CntHitObjectSetup *)((GameObject *)obj)->anim.placementData;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT && state->flags.disabled == 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7430);
    }
}

int cnthitobjec_emitHitEvents(int obj, int p2, int p3)
{
    int i;
    CntHitObjectAnimEvent *event = (CntHitObjectAnimEvent *)p3;
    for (i = 0; i < event->explosionCount; i++) {
        spawnExplosion(obj, (f32)(u32)event->explosionIds[i], 1, 1, 1, 1, 0, 1, 0);
    }
    return 0;
}

void cnthitobjec_hitDetect(int obj)
{
    CntHitObjectSetup *setup = (CntHitObjectSetup *)((GameObject *)obj)->anim.placementData;
    CntHitObjectState *state = ((GameObject *)obj)->extra;
    int hit;
    int dmg;
    int amount;
    int model;

    if (state->remainingHealth == 0) {
        return;
    }
    hit = ObjHits_GetPriorityHit(obj, 0, 0, &dmg);
    if (hit == 0) {
        return;
    }
    if (state->allowedHitSourceCount == 0) {
        return;
    }
    if (arrayIndexOf(state->allowedHitSources, state->allowedHitSourceCount, hit) == -1) {
        return;
    }
    state->remainingHealth = state->remainingHealth - dmg;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
        Obj_SetModelColorFadeRecursive(obj, 30, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, 1174);
    }
    if (state->remainingHealth <= 0) {
        CntHitObjectSetup *s = (CntHitObjectSetup *)((GameObject *)obj)->anim.placementData;
        state->remainingHealth = 0;
        GameBit_Set(s->doneGameBit, 1);
        if (s->mode != 0) {
            if (s->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
                amount = CNTHIT_DEFAULT_VISIBLE_EXPLOSION_SIZE;
            } else {
                amount = s->explosionSize;
            }
            model = s->base.mapId;
            if (model != CNTHIT_MODEL_NO_EXPLOSION_A && model != CNTHIT_MODEL_NO_EXPLOSION_B && model != CNTHIT_MODEL_NO_EXPLOSION_C &&
                model != CNTHIT_MODEL_NO_EXPLOSION_D) {
                spawnExplosion(obj, (f32)amount, 1, 1, 1, 1, 0, 1, 0);
            }
            if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
                Sfx_PlayFromObject(obj, 1175);
            }
        }
    } else {
        Sfx_PlayFromObject(obj, SFXdn_hightop_ambi1);
    }
}

void cnthitobjec_init(int obj, int setup)
{
    CntHitObjectState *state = ((GameObject *)obj)->extra;
    CntHitObjectSetup *setupData = (CntHitObjectSetup *)setup;

    state->remainingHealth = 0;
    setupData->hitSourceProfile = (s8)((u32)setupData->hitSourceProfile % CNTHIT_PROFILE_COUNT);
    state->allowedHitSources = lbl_8032BEF8[setupData->hitSourceProfile];
    state->allowedHitSourceCount = lbl_803DC42C[setupData->hitSourceProfile];
    if ((void *)state->allowedHitSources == (void *)&lbl_803DC428) {
        ObjHits_ClearSourceMask(8);
    }
    if (setupData->mode == CNTHIT_MODE_VISIBLE_OBJECT) {
        *(s16 *)obj = setupData->explosionSize;
    } else {
        ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if ((u32)GameBit_Get(setupData->doneGameBit) != 0) {
        state->flags.disabled = 1;
        ObjHits_DisableObject(obj);
    }
    ((GameObject *)obj)->animEventCallback = (void *)cnthitobjec_emitHitEvents;
}

void cnthitobjec_update(int obj)
{
    CntHitObjectState *state = ((GameObject *)obj)->extra;
    CntHitObjectSetup *setup;
    setup = (CntHitObjectSetup *)((GameObject *)obj)->anim.placementData;

    if (state->flags.disabled == 0) {
        if ((u32)GameBit_Get(setup->doneGameBit) != 0) {
            state->flags.disabled = 1;
            ObjHits_DisableObject(obj);
        }
    }

    if (state->flags.disabled == 0 && state->remainingHealth == 0 &&
        (u32)GameBit_Get(setup->startGameBit) != 0) {
        ObjHits_EnableObject(obj);
        state->remainingHealth = setup->startHealth;
        if (setup->mode != CNTHIT_MODE_VISIBLE_OBJECT) {
            ObjHitbox_SetSphereRadius(obj, setup->explosionSize);
        }
    }
}

int mcupgrade_SeqFn(int obj, int p2, int setup)
{
    CntHitObjectAnimEvent *event = (CntHitObjectAnimEvent *)setup;
    if (event->explosionCount != 0) {
        (*gGameUIInterface)->showNpcDialogue(
            ((CntHitObjectSetup *)((GameObject *)obj)->anim.placementData)->startHealth, 0x14, 0x8c, 0);
    }
    return 0;
}
