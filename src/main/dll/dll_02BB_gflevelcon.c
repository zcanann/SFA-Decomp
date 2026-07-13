/*
 * gflevelcon (DLL 0x2BB) - "GalleonForce" level controller object.
 *
 * Its anim-event callback (gf_levelcon_SeqFn) reacts to
 * sequence event opcodes that drive the sky/weather presets (skyFn_*
 * + getEnvfxAct), warp/credits flow at the end of the level, and a
 * countdown-driven on-screen text prompt (gameTextShow 0x476). It also
 * finds the level's linked point-light and scroll objects (by their
 * placement def ids 0x477E3 / 0x4A946 / 0x4A947) and toggles / scrolls
 * them per frame.
 *
 * The fn_8023* helpers (referenced from dll_02BC_andross.c) spawn and
 * aim the Arwing projectile/effect objects used during the boss fight,
 * and fn_8023A3E4 is the hit-reaction handler (three breakable hit
 * zones + texture-state swaps).
 */
#include "main/effect_interfaces.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/model_engine.h"
#include "main/map_load.h"
#include "main/frame_timing.h"
#include "main/objanim_update.h"
#include "main/obj_list.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/lightmap_api.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/dll_02C0_front.h"
#include "main/render.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_02BB_gflevelcon.h"
#include "main/gametext_show_api.h"
#include "main/dll/LGT/dll_02A9_lgtpointlight.h"
#include "main/object_render_legacy.h"

/* sequence event opcodes consumed by gf_levelcon_SeqFn */
#define GFLEVELCON_SEQEV_NONE          0
#define GFLEVELCON_SEQEV_SKY_PRESET_A  1
#define GFLEVELCON_SEQEV_SKY_PRESET_B  2
#define GFLEVELCON_SEQEV_LIGHT_ON      3
#define GFLEVELCON_SEQEV_LIGHT_OFF     4
#define GFLEVELCON_SEQEV_SKY_PRESET_C  5
#define GFLEVELCON_SEQEV_LOAD_MAP      6
#define GFLEVELCON_SEQEV_UNLOCK_LEVELS 7
#define GFLEVELCON_SEQEV_START_PROMPT  8
#define GFLEVELCON_SEQEV_CREDITS       9
#define GFLEVELCON_SEQEV_SKY_PRESET_D  10
#define GFLEVELCON_SEQEV_SKY_PRESET_E  11

/* placement def ids of the linked objects gf_levelcon_findLinkedObjects
   caches into its state (point light + two scrolling textures) */
#define GFLEVELCON_LINK_LIGHT    0x477E3
#define GFLEVELCON_LINK_SCROLL_A 0x4A946
#define GFLEVELCON_LINK_SCROLL_B 0x4A947

/* Arwing-projectile child object ids; each spawn installs
 * arwprojectile_setLifetime/placeForward on the returned object and casts
 * the setup buffer to GfProjectileSetup. */
#define GFLEVELCON_CHILD_OBJ_PROJECTILE_SPREAD 0x80d
#define GFLEVELCON_CHILD_OBJ_PROJECTILE_AIMED  0x7e4
#define GFLEVELCON_CHILD_OBJ_PROJECTILE_RING   0x859
/* Object loaded at the nearest def-0x7e5 marker in fn_80239DD8, cached in
 * obj->extra+0x10 and faded in. */
#define GFLEVELCON_CHILD_OBJ_MARKER_ATTACH 0x608

/* env-effect ids activated alongside the sky presets (index-style; each id is
 * shared by two presets - A/D, B/E, C - so roles stay opaque) */
#define GFLEVELCON_ENVFX_A 0x21f
#define GFLEVELCON_ENVFX_B 0x21d
#define GFLEVELCON_ENVFX_C 0x21e

#pragma opt_strength_reduction on
#pragma opt_loop_invariants off
int gf_levelcon_SeqFn(GameObject* obj, int eventId, ObjAnimUpdateState* animUpdate)
{
    GfLevelconHandleScriptEventsState* state = obj->extra;
    int i;

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case GFLEVELCON_SEQEV_NONE:
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_A:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7460, lbl_803E7464, lbl_803E7468);
            getEnvfxActVoid((int)obj, (int)obj, GFLEVELCON_ENVFX_A, 0);
            break;
        case GFLEVELCON_SEQEV_START_PROMPT:
            state->promptTimer = lbl_803E746C;
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_B:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, lbl_803E7470, lbl_803E7474, lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7464, lbl_803E747C, *(f32*)&lbl_803E7464);
            getEnvfxActVoid((int)obj, (int)obj, GFLEVELCON_ENVFX_B, 0);
            break;
        case GFLEVELCON_SEQEV_LIGHT_ON:
            gf_levelcon_findLinkedObjects(obj);
            if (state->light != 0)
            {
                pointlight_setEffectState((GameObject*)state->light, 1);
            }
            break;
        case GFLEVELCON_SEQEV_LIGHT_OFF:
            gf_levelcon_findLinkedObjects(obj);
            if (state->light != 0)
            {
                pointlight_setEffectState((GameObject*)state->light, 0);
            }
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_C:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7480, lbl_803E747C, lbl_803E7464);
            getEnvfxActVoid((int)obj, (int)obj, GFLEVELCON_ENVFX_C, 0);
            break;
        case GFLEVELCON_SEQEV_LOAD_MAP:
            loadMapAndParent(0x29);
            break;
        case GFLEVELCON_SEQEV_UNLOCK_LEVELS:
            unlockLevel(0, 0, 1);
            unlockLevel(0, 1, 1);
            mapUnload(mapGetDirIdx(0xb), 0x20000000);
            break;
        case GFLEVELCON_SEQEV_CREDITS:
            unlockLevel(0, 0, 1);
            loadUiDll(4);
            warpToMap(0x12, 0);
            creditsStart();
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_D:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxActVoid((int)obj, (int)obj, GFLEVELCON_ENVFX_A, 0);
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_E:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, lbl_803E7470, lbl_803E7474, lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxActVoid((int)obj, (int)obj, GFLEVELCON_ENVFX_B, 0);
            break;
        }
    }

    if (state->promptTimer > lbl_803E7488)
    {
        gameTextShow(0x476);
        state->promptTimer -= timeDelta;
        if (state->promptTimer < *(f32*)&lbl_803E7488)
        {
            state->promptTimer = lbl_803E7488;
        }
    }

    {
        s16* scroll = state->scrollA;
        if (scroll != NULL)
        {
            *scroll += (s16)(lbl_803E748C * timeDelta);
        }
    }
    {
        s16* scroll = state->scrollB;
        if (scroll != NULL)
        {
            *scroll -= (s16)(lbl_803E748C * timeDelta);
        }
    }
    return 0;
}
#pragma opt_strength_reduction reset
#pragma opt_loop_invariants reset

int gf_levelcon_getExtraSize(void)
{
    return 0x10;
}

int gf_levelcon_getObjectTypeId(void)
{
    return 0;
}

void gf_levelcon_hitDetect(void)
{
}

void gf_levelcon_initialise(void)
{
}

void gf_levelcon_release(void)
{
}

void gf_levelcon_free(void)
{
    setIsOvercast(1);
}

void gf_levelcon_update(GameObject* obj)
{
    obj->animEventCallback = gf_levelcon_SeqFn;
}

void gf_levelcon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E7480);
    }
}

void gf_levelcon_init(GameObject* obj)
{
    setIsOvercast(0);
    (*gScreenTransitionInterface)->step(0x258, 1);
}

void gf_levelcon_findLinkedObjects(GameObject* obj)
{
    GfLevelconFindLinkedObjectsState* state = obj->extra;
    int* objects;
    int objectIndex;
    int objectCount;
    int linkedObj;

    state->light = 0;
    state->scrollA = 0;
    state->scrollB = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    for (; objectIndex < objectCount; objectIndex++)
    {
        linkedObj = objects[objectIndex];
        if ((GameObject*)linkedObj != obj && *(void**)(linkedObj + 0x4c) != NULL)
        {
            switch (*(int*)(*(int*)(linkedObj + 0x4c) + 0x14))
            {
            case GFLEVELCON_LINK_LIGHT:
                state->light = linkedObj;
                break;
            case GFLEVELCON_LINK_SCROLL_A:
                state->scrollA = linkedObj;
                break;
            case GFLEVELCON_LINK_SCROLL_B:
                state->scrollB = linkedObj;
                break;
            }
        }
    }
}
