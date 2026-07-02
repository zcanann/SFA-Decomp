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
#include "main/carryable_interface.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objlib.h"
#include "main/objhits.h"
#include "main/dll/VF/vf_shared.h"
#include "main/audio/sfx.h"

#define UNK_OBJFLAG_HITDETECT_DISABLED 0x2000

/* per-object extra block; 0xA is the object phase enum
   (0=carrying/active, 1=just broke, 2=respawning) */
typedef struct Dll109State
{
    u8 pad0[0xa];
    u8 phase;
    u8 padB;
    f32 timer;
} Dll109State;

typedef enum Dll109Phase
{
    DLL109_PHASE_INTACT = 0,  /* carryable/active; waits for a priority hit */
    DLL109_PHASE_BREAKING = 1, /* just broke: spawn debris, disable, snap to placement */
    DLL109_PHASE_RESPAWNING = 2, /* respawn timer + off-screen wait, then reset */
} Dll109Phase;

typedef struct Dll109MapData
{
    ObjPlacement base;
    u8 pad18[0x1a - 0x18];
    u8 rotX; /* 0x1a: rotX in 1/256 turns */
} Dll109MapData;

STATIC_ASSERT(offsetof(Dll109MapData, rotX) == 0x1a);

extern void ObjHits_ClearHitVolumes();
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);

extern f32 lbl_803E3B44; /* respawn timer reset value */
extern f32 lbl_803E3B48; /* respawn timer threshold */
extern f32 lbl_803E3B40; /* render alpha/param */

void dll_109_hitDetect_nop(void)
{
}

void dll_109_release_nop(void)
{
}

void dll_109_initialise_nop(void)
{
}

int dll_109_getExtraSize_ret_16(void) { return 0x10; }
int dll_109_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void carryable_break_respawn_update(int obj)
{
    Dll109State* state;
    ObjPlacement* placement;
    int setup;
    u32 hitVolume;

    state = ((GameObject*)obj)->extra;
    placement = (ObjPlacement*)((GameObject*)obj)->anim.placementData;
    switch (state->phase)
    {
    case DLL109_PHASE_INTACT:
        (*gCarryableInterface)->getAnimState(obj, (int)state);
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume) != 0)
        {
            (*(void (*)(int, Dll109State*))*(int*)((u8*)*gCarryableInterface + 0x30))(obj, state);
            Sfx_PlayFromObject(obj, SFXen_rfall5_c);
            ObjHitbox_SetSphereRadius(obj, 0x28);
            ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x24, 0x253);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
            }
            (*gPartfxInterface)->spawnObject((void*)obj, 0x355, NULL, 0, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x352, NULL, 0, -1, NULL);
            state->phase = DLL109_PHASE_BREAKING;
        }
        break;
    case DLL109_PHASE_BREAKING:
        ObjHits_ClearHitVolumes();
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        state->phase = DLL109_PHASE_RESPAWNING;
        state->timer = lbl_803E3B44;
        ((GameObject*)obj)->anim.localPosX = placement->posX;
        ((GameObject*)obj)->anim.localPosY = placement->posY;
        ((GameObject*)obj)->anim.localPosZ = placement->posZ;
        break;
    case DLL109_PHASE_RESPAWNING:
        state->timer += timeDelta;
        if (state->timer > lbl_803E3B48)
        {
            if (ViewFrustum_IsSphereVisible(&((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.
                                            rootMotionScale) == 0)
            {
                ObjHits_EnableObject(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                state->phase = DLL109_PHASE_INTACT;
            }
        }
        break;
    }
}

void dll_109_init(int obj, Dll109MapData* p)
{
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p->rotX << 8);
    ((GameObject*)obj)->objectFlags |= UNK_OBJFLAG_HITDETECT_DISABLED;
    (*gCarryableInterface)->initAnim((void*)obj, *(int*)&((GameObject*)obj)->extra, 0x21);
    (*(void (**)(int*, int))((u8*)*gCarryableInterface + 0x2c))(((GameObject*)obj)->extra, 1);
}

#pragma scheduling on
#pragma peephole on
void dll_109_free(int obj)
{
    (*gCarryableInterface)->free(obj);
}

#pragma scheduling off
#pragma peephole off
void dll_109_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    Dll109State* state = ((GameObject*)obj)->extra;
    if (state->phase == DLL109_PHASE_INTACT)
    {
        if ((*gCarryableInterface)->isVisible(obj, visible) != 0)
        {
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E3B40);
        }
    }
}
