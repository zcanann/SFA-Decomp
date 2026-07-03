/*
 * cnthitobjec (DLL 0x2B6) - a destructible "counted-hit" object.
 *
 * The object starts inert and is armed when its startGameBit is set: it
 * gains startHealth and (in the hidden-collider mode) a sphere hitbox.
 * Each frame hitDetect polls the priority hit; a hit is only counted if
 * its source matches one of the object's allowed hit-source profiles
 * (CNTHIT_PROFILE_* tables lbl_8032BEF8/lbl_803DC42C). Counted damage is
 * subtracted from remainingHealth; in CNTHIT_MODE_VISIBLE_OBJECT the
 * object flashes and plays a hit sfx. On depletion it sets its
 * doneGameBit, spawns an explosion (size depends on mode/explosionSize,
 * suppressed for the CNTHIT_MODEL_NO_EXPLOSION_* models) and is disabled.
 * doneGameBit also re-disables the object on init/update so it stays
 * destroyed across reloads. The anim-event callback spawns the
 * per-event explosion list.
 *
 * mcupgrade_SeqFn lives here but belongs to the sibling mcupgrade DLL
 * (0x2B7), which installs it as its anim-event callback.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

int cnthitobjec_getExtraSize(void) { return sizeof(CntHitObjectState); }

int cnthitobjec_getObjectTypeId(void) { return 0; }

void cnthitobjec_free(void)
{
}

void cnthitobjec_release(void)
{
}

void cnthitobjec_initialise(void)
{
}

void cnthitobjec_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    CntHitObjectState* state = ((GameObject*)obj)->extra;
    CntHitObjectSetup* setup = (CntHitObjectSetup*)((GameObject*)obj)->anim.placementData;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT && state->flags.disabled == 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7430);
    }
}

int cnthitobjec_emitHitEvents(int obj, int p2, int p3)
{
    int i;
    CntHitObjectAnimEvent* event = (CntHitObjectAnimEvent*)p3;
    for (i = 0; i < event->explosionCount; i++)
    {
        spawnExplosion(obj, (f32)(u32)event->explosionIds[i], 1, 1, 1, 1, 0, 1, 0);
    }
    return 0;
}

void cnthitobjec_hitDetect(int obj)
{
    CntHitObjectState* state;
    CntHitObjectSetup* setup = (CntHitObjectSetup*)((GameObject*)obj)->anim.placementData;
    int hit;
    u32 dmg;
    int amount;
    int model;

    state = ((GameObject*)obj)->extra;
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
    state->remainingHealth = state->remainingHealth - dmg;
    if (setup->mode == CNTHIT_MODE_VISIBLE_OBJECT)
    {
        Obj_SetModelColorFadeRecursive(obj, 30, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff_496); /* hit */
    }
    if (state->remainingHealth <= 0)
    {
        CntHitObjectSetup* s = (CntHitObjectSetup*)((GameObject*)obj)->anim.placementData;
        state->remainingHealth = 0;
        GameBit_Set(s->doneGameBit, 1);
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
            model = ((CntHitObjectSetup*)((GameObject*)obj)->anim.placementData)->base.mapId;
            if (model != CNTHIT_MODEL_NO_EXPLOSION_A && model != CNTHIT_MODEL_NO_EXPLOSION_B && model !=
                CNTHIT_MODEL_NO_EXPLOSION_C &&
                model != CNTHIT_MODEL_NO_EXPLOSION_D)
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
        Sfx_PlayFromObject(obj, SFXdn_hightop_ambi1);
    }
}

void cnthitobjec_init(int obj, int setup)
{
    CntHitObjectState* state = ((GameObject*)obj)->extra;
    CntHitObjectSetup* setupData = (CntHitObjectSetup*)setup;

    state->remainingHealth = 0;
    setupData->hitSourceProfile = (s8)((u32)setupData->hitSourceProfile % CNTHIT_PROFILE_COUNT);
    state->allowedHitSources = lbl_8032BEF8[setupData->hitSourceProfile];
    state->allowedHitSourceCount = (&lbl_803DC42C)[setupData->hitSourceProfile];
    if ((void*)state->allowedHitSources == &lbl_803DC428)
    {
        ObjHits_ClearSourceMask(obj, 8);
    }
    if (setupData->mode == CNTHIT_MODE_VISIBLE_OBJECT)
    {
        ((GameObject*)obj)->anim.rotX = setupData->explosionSize;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if ((u32)GameBit_Get(setupData->doneGameBit) != 0)
    {
        state->flags.disabled = 1;
        ObjHits_DisableObject(obj);
    }
    ((GameObject*)obj)->animEventCallback = cnthitobjec_emitHitEvents;
}

void cnthitobjec_update(int obj)
{
    CntHitObjectSetup* setup;
    CntHitObjectState* state = ((GameObject*)obj)->extra;
    setup = (CntHitObjectSetup*)((GameObject*)obj)->anim.placementData;

    if (state->flags.disabled == 0)
    {
        if ((u32)GameBit_Get(setup->doneGameBit) != 0)
        {
            state->flags.disabled = 1;
            ObjHits_DisableObject(obj);
        }
    }

    if (state->flags.disabled == 0 && state->remainingHealth == 0 &&
        GameBit_Get(setup->startGameBit) != 0)
    {
        ObjHits_EnableObject(obj);
        state->remainingHealth = setup->startHealth;
        if (setup->mode != CNTHIT_MODE_VISIBLE_OBJECT)
        {
            ObjHitbox_SetSphereRadius(obj, setup->explosionSize);
        }
    }
}

int mcupgrade_SeqFn(int obj, int unused, CntHitObjectAnimEvent* event)
{
    if (event->explosionCount != 0)
    {
        (*gGameUIInterface)->showNpcDialogue(
            ((CntHitObjectSetup*)((GameObject*)obj)->anim.placementData)->startHealth, 0x14, 0x8c, 0);
    }
    return 0;
}
