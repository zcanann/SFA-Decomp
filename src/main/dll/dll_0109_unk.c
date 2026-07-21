/*
 * dll_0109 - a "carryable that breaks and respawns" placed object.
 *
 * Driven by a carryable interface (gCarryableInterface). On a priority
 * hit while being carried it plays a break fx + sfx, sets a sphere
 * hitbox, and (when object loading is locked) drops a replacement setup
 * object at its position. It then disables itself, snaps back to its
 * placement position, and runs a respawn timer; once the timer expires
 * and the object is off-screen (frustum cull) it re-enables and resets.
 * render is suppressed while broken or respawning (phase != 0), and
 * otherwise falls through to the carryable visibility test.
 */
#include "main/dll/partfx_interface.h"
#include "main/carryable_interface.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_0109_unk.h"

#define BREAKABLE_CARRYABLE_HIT_VOLUME_SLOT 5
#define BREAKABLE_CARRYABLE_OBJECT_FLAG_HITDETECT_DISABLED 0x2000

/* Replacement object dropped at break; retail OBJECTS.bin name
   "DIMExplosio..." (DLL 0x1CA). */
#define BREAKABLE_CARRYABLE_CHILD_DIM_EXPLOSION 0x253

int breakableCarryable_getExtraSize(void)
{
    return sizeof(BreakableCarryableState);
}
int breakableCarryable_getObjectTypeId(void)
{
    return 0x0;
}

void breakableCarryable_free(GameObject* obj)
{
    (*gCarryableInterface)->free(obj);
}

void breakableCarryable_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    BreakableCarryableState* state = obj->extra;
    if (state->phase == BREAKABLE_CARRYABLE_PHASE_INTACT)
    {
        if ((*gCarryableInterface)->updateRenderState(obj, visible) != 0)
        {
            objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
        }
    }
}

void breakableCarryable_hitDetect(void)
{
}

void breakableCarryable_update(GameObject* obj)
{
    BreakableCarryableState* state;
    ObjPlacement* placement;
    ObjPlacement* setup;
    u32 hitVolume;

    state = (obj)->extra;
    placement = (ObjPlacement*)(obj)->anim.placementData;
    switch (state->phase)
    {
    case BREAKABLE_CARRYABLE_PHASE_INTACT:
        (*gCarryableInterface)->updateHeld(obj, state);
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume) != 0)
        {
            (*gCarryableInterface)->stopCarrying(obj, state);
            Sfx_PlayFromObject((int)obj, SFXTRIG_crtsmsh6);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 0x28);
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, BREAKABLE_CARRYABLE_HIT_VOLUME_SLOT, 4, 0);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x24, BREAKABLE_CARRYABLE_CHILD_DIM_EXPLOSION);
                setup->posX = (obj)->anim.localPosX;
                setup->posY = (obj)->anim.localPosY;
                setup->posZ = (obj)->anim.localPosZ;
                Obj_SetupObject(setup, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
            }
            (*gPartfxInterface)->spawnObject((void*)obj, 0x355, NULL, 0, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x352, NULL, 0, -1, NULL);
            state->phase = BREAKABLE_CARRYABLE_PHASE_BREAKING;
        }
        break;
    case BREAKABLE_CARRYABLE_PHASE_BREAKING:
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        ObjHits_DisableObject(obj);
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        state->phase = BREAKABLE_CARRYABLE_PHASE_RESPAWNING;
        state->respawnTimer = 0.0f;
        (obj)->anim.localPosX = placement->posX;
        (obj)->anim.localPosY = placement->posY;
        (obj)->anim.localPosZ = placement->posZ;
        break;
    case BREAKABLE_CARRYABLE_PHASE_RESPAWNING:
        state->respawnTimer += timeDelta;
        if (state->respawnTimer > 300.0f)
        {
            if (ViewFrustum_IsSphereVisible(&(obj)->anim.localPosX,
                                            (obj)->anim.hitboxScale * (obj)->anim.rootMotionScale) == 0)
            {
                ObjHits_EnableObject(obj);
                *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                state->phase = BREAKABLE_CARRYABLE_PHASE_INTACT;
            }
        }
        break;
    }
}

void breakableCarryable_init(GameObject* obj, BreakableCarryablePlacement* placement)
{
    obj->anim.rotX = (s16)((s32)placement->rotX << 8);
    obj->objectFlags |= BREAKABLE_CARRYABLE_OBJECT_FLAG_HITDETECT_DISABLED;
    (*gCarryableInterface)->init(obj, obj->extra, 0x21);
    (*gCarryableInterface)->setSuppressPositionSave(obj->extra, 1);
}

void breakableCarryable_release(void)
{
}

void breakableCarryable_initialise(void)
{
}
