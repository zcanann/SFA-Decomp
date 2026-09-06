/*
 * CNThitObjec (DLL 0x2B6) - a destructible "counted-hit" object.
 *
 * The object starts inert and is armed when its startGameBit is set: it
 * gains startHealth and (in the hidden-collider mode) a sphere hitbox.
 * Each frame hitDetect polls the priority hit; a hit is only counted if
 * its source matches one of the object's allowed hit-source profiles.
 * Counted damage is
 * subtracted from remainingHealth; in CNTHIT_MODE_VISIBLE_OBJECT the
 * object flashes and plays a hit sfx. On depletion it sets its
 * doneGameBit, spawns an explosion (size depends on mode/explosionSize,
 * suppressed for the CNTHIT_MODEL_NO_EXPLOSION_* models) and is disabled.
 * doneGameBit also re-disables the object on init/update so it stays
 * destroyed across reloads. The anim-event callback spawns the
 * per-event explosion list.
 *
 * mcupgrade_SeqFn is part of this DOL-confirmed TU and is installed as an
 * anim-event callback by the following MCUpgrade DLL.
 */
#include "main/audio/sfx_play_api.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/maketex_api.h"
#include "main/objfx.h"
#include "main/dll/dll_02B6_cnthitobjec.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "sys/objects.h"

static int sCntHitSourcesProfile0[2] = {0xf, 0xe};
static int sCntHitSourceProfile1 = 5;
static u8 sCntHitSourceCounts[4] = {2, 1, 0, 0};
static int* sCntHitSourcesByProfile[3] = {
    sCntHitSourcesProfile0,
    &sCntHitSourceProfile1,
    sCntHitSourcesProfile0,
};

int cnthitobjec_SeqFn(GameObject* obj, int unused, CntHitObjectAnimEvent* event)
{
    int i;
    for (i = 0; i < event->explosionCount; i++)
    {
        spawnExplosion(obj, (f32)(u32)event->explosionIds[i], 1, 1, 1, 1, 0, 1, 0);
    }
    return 0;
}

int cnthitobjec_getExtraSize(void)
{
    return sizeof(CntHitObjectState);
}

int cnthitobjec_getObjectTypeId(void)
{
    return 0;
}

void cnthitobjec_free(void)
{
}

void cnthitobjec_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    CntHitObjectState* state = obj->extra;
    CntHitObjectSetup* setup = (CntHitObjectSetup*)obj->anim.placementData;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT && state->flags.disabled == 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void cnthitobjec_hitDetect(GameObject* obj)
{
    CntHitObjectState* state;
    CntHitObjectSetup* setup = (CntHitObjectSetup*)obj->anim.placementData;
    int hit;
    u32 dmg;
    int amount;
    int model;

    state = obj->extra;
    if (state->remainingHealth == 0)
    {
        return;
    }
    hit = ObjHits_GetPriorityHit(obj, 0, 0, &dmg);
    if (hit == 0)
    {
        return;
    }
    if (state->allowedHitSourceCount == 0)
    {
        return;
    }
    if (arrayIndexOf(state->allowedHitSources, state->allowedHitSourceCount, hit) == -1)
    {
        return;
    }
    state->remainingHealth -= dmg;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT)
    {
        Obj_SetModelColorFadeRecursive(obj, 30, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff_496); /* hit */
    }
    if (state->remainingHealth <= 0)
    {
        CntHitObjectSetup* s = (CntHitObjectSetup*)obj->anim.placementData;
        state->remainingHealth = 0;
        mainSetBits(s->doneGameBit, 1);
        if (s->mode != 0)
        {
            if (s->mode == CNTHIT_MODE_VISIBLE_OBJECT)
            {
                amount = CNTHIT_DEFAULT_VISIBLE_EXPLOSION_SIZE;
            }
            else
            {
                amount = s->explosionSize;
            }
            model = ((CntHitObjectSetup*)obj->anim.placementData)->base.ident;
            if (model != CNTHIT_MODEL_NO_EXPLOSION_A && model != CNTHIT_MODEL_NO_EXPLOSION_B &&
                model != CNTHIT_MODEL_NO_EXPLOSION_C && model != CNTHIT_MODEL_NO_EXPLOSION_D)
            {
                spawnExplosion(obj, amount, 1, 1, 1, 1, 0, 1, 0);
            }
            if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_sexpl2_c); /* destroy */
            }
        }
    }
    else
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sc_snort03);
    }
}

void cnthitobjec_update(GameObject* obj)
{
    CntHitObjectSetup* setup;
    CntHitObjectState* state = obj->extra;
    setup = (CntHitObjectSetup*)obj->anim.placementData;

    if (state->flags.disabled == 0)
    {
        if (mainGetBit(setup->doneGameBit) != 0)
        {
            state->flags.disabled = 1;
            ObjHits_DisableObject(obj);
        }
    }

    if (state->flags.disabled == 0 && state->remainingHealth == 0 && mainGetBit(setup->startGameBit) != 0)
    {
        ObjHits_EnableObject(obj);
        state->remainingHealth = setup->startHealth;
        if (setup->mode != CNTHIT_MODE_VISIBLE_OBJECT)
        {
            ObjHitbox_SetSphereRadius(&obj->anim, setup->explosionSize);
        }
    }
}

void cnthitobjec_init(GameObject* obj, CntHitObjectSetup* setup)
{
    CntHitObjectState* state = obj->extra;
    CntHitObjectSetup* setupData = setup;

    state->remainingHealth = 0;
    setupData->hitSourceProfile = (u32)setupData->hitSourceProfile % CNTHIT_PROFILE_COUNT;
    state->allowedHitSources = sCntHitSourcesByProfile[setupData->hitSourceProfile];
    state->allowedHitSourceCount = sCntHitSourceCounts[setupData->hitSourceProfile];
    if (state->allowedHitSources == &sCntHitSourceProfile1)
    {
        ObjHits_ClearSourceMask(&obj->anim, 8);
    }
    if (setupData->mode == CNTHIT_MODE_VISIBLE_OBJECT)
    {
        obj->anim.rotX = setupData->explosionSize;
    }
    else
    {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if (mainGetBit(setupData->doneGameBit) != 0)
    {
        state->flags.disabled = 1;
        ObjHits_DisableObject(obj);
    }
    obj->animEventCallback = cnthitobjec_SeqFn;
}

void cnthitobjec_release(void)
{
}

void cnthitobjec_initialise(void)
{
}

int mcupgrade_SeqFn(GameObject* obj, int unused, CntHitObjectAnimEvent* event)
{
    if (event->explosionCount != 0)
    {
        (*gGameUIInterface)->showNpcDialogue(((CntHitObjectSetup*)obj->anim.placementData)->startHealth, 0x14, 0x8c, 0);
    }
    return 0;
}

ObjectDescriptor11ExtraSize gCNThitObjecObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cnthitobjec_initialise,
    (ObjectDescriptorCallback)cnthitobjec_release,
    0,
    (ObjectDescriptorCallback)cnthitobjec_init,
    (ObjectDescriptorCallback)cnthitobjec_update,
    (ObjectDescriptorCallback)cnthitobjec_hitDetect,
    (ObjectDescriptorCallback)cnthitobjec_render,
    (ObjectDescriptorCallback)cnthitobjec_free,
    (ObjectDescriptorCallback)cnthitobjec_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)cnthitobjec_getExtraSize,
    0,
};
