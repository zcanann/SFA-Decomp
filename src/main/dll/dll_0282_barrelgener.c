/*
 * barrelgener (DLL 0x282) - the barrel generator/dispenser object.
 *
 * Object-group member 0x3a. On init it joins that group and clears its
 * release state. When the player approaches within range it fires
 * trigger sequence 1 (once, gated by game bit 0xADB). A queued barrel
 * (barrelgener_queueObjectRelease, called from the gunpowder-barrel DLL)
 * is held until its release timer elapses: the dispense animation plays
 * with a PDA camera-off sfx, a compass beep fires partway through, and at
 * timer end the queued barrel is teleported to this object's position,
 * zeroed in velocity, and added to its own update group (25).
 *
 * The rest of the TU is a shared curve-following / steering / voxel
 * line-trace toolkit consumed by the Drakor-area and ArwingSquadron DLLs
 * (Obj_UpdateRomCurveFollowVelocity[Indexed], Obj_SteerVelocityTowardVector,
 * Obj_SmoothTurnAnglesTowardVelocity, the lightning-spawn helper, and the
 * voxmaps_trace* world-line wrappers).
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx.h"
#include "main/curve.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/model_light.h"
#include "main/objanim.h"
#include "main/obj_group.h"
#include "main/obj_query.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "main/shader_api.h"
#include "main/dll/rom_curve_interface.h"
#include "main/maketex_timer_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/barrelgener_state.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/newclouds.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

int lbl_803DC398 = 0x14;

#define BARRELGENER_OBJGROUP          0x3a
#define GAMEBIT_BARRELGENER_TRIGGERED 0xadb
/* update group a dispensed barrel is added to (GunpowderBarrel DLL 0x158) */
#define BARREL_UPDATE_OBJGROUP 25



int barrelgener_getLinkId(GameObject* obj)
{
    BarrelGeneratorSetup* setup = (BarrelGeneratorSetup*)(obj)->anim.placementData;
    return setup->linkId;
}

void barrelgener_queueObjectRelease(GameObject* obj, GameObject* queuedObj, int releaseFrame)
{
    BarrelGeneratorState* state = (obj)->extra;

    state->queuedObject = queuedObj;
    state->releaseAnimPlaying = 0;
    storeZeroToFloatParam(&state->releaseTimer);
    s16toFloat(&state->releaseTimer, (s16)(releaseFrame - lbl_803DC398));
}

int barrelgener_getExtraSize(void)
{
    return 0x10;
}

int barrelgener_getObjectTypeId(void)
{
    return 0;
}

void barrelgener_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, BARRELGENER_OBJGROUP);
}

void barrelgener_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6C20);
    }
}

void barrelgener_hitDetect(void)
{
}

void barrelgener_update(GameObject* obj)
{
    BarrelGeneratorState* state = (obj)->extra;
    GameObject* player = Obj_GetPlayerObject();

    if ((u32)mainGetBit(GAMEBIT_BARRELGENER_TRIGGERED) == 0)
    {
        if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < lbl_803E6C24)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            mainSetBits(GAMEBIT_BARRELGENER_TRIGGERED, 1);
        }
    }
    if (timerIsActive(&state->releaseTimer) != 0)
    {
        if (state->releaseTimer <= lbl_803E6C28 && state->releaseAnimPlaying == 0)
        {
            state->releaseAnimPlaying = 1;
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E6C2C, 0);
            Sfx_PlayFromObject((int)obj, SFXTRIG_barrelgen_slide);
            state->releaseBeepPlayed = 0;
        }
        if (timerCountDown((void*)&state->releaseTimer) != 0)
        {
            if (Obj_IsObjectAlive(state->queuedObject) != 0)
            {
                GameObject* releasedBarrel = state->queuedObject;
                f32 releaseVelocity;
                releasedBarrel->anim.localPosX = (obj)->anim.localPosX;
                releasedBarrel->anim.localPosY = (obj)->anim.localPosY;
                releasedBarrel->anim.localPosZ = (obj)->anim.localPosZ;
                releasedBarrel->anim.previousLocalPosX = releasedBarrel->anim.localPosX;
                releasedBarrel->anim.previousLocalPosY = releasedBarrel->anim.localPosY;
                releasedBarrel->anim.previousLocalPosZ = releasedBarrel->anim.localPosZ;
                releasedBarrel->anim.worldPosX = releasedBarrel->anim.localPosX;
                releasedBarrel->anim.worldPosY = releasedBarrel->anim.localPosY;
                releasedBarrel->anim.worldPosZ = releasedBarrel->anim.localPosZ;
                releaseVelocity = lbl_803E6C2C;
                releasedBarrel->anim.velocityZ = releaseVelocity;
                releasedBarrel->anim.velocityY = releaseVelocity;
                releasedBarrel->anim.velocityX = releaseVelocity;
                ObjGroup_AddObject((int)state->queuedObject, BARREL_UPDATE_OBJGROUP);
                state->queuedObject = NULL;
            }
        }
    }
    if (state->releaseAnimPlaying != 0)
    {
        if ((obj)->anim.currentMoveProgress > lbl_803E6C30)
        {
            if (state->releaseBeepPlayed == 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_mzap2_c);
                state->releaseBeepPlayed = 1;
            }
        }
        state->releaseAnimPlaying =
            !ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E6C34, timeDelta, 0);
    }
}

void barrelgener_init(GameObject* obj)
{
    BarrelGeneratorState* state = (obj)->extra;

    ObjGroup_AddObject((int)obj, BARRELGENER_OBJGROUP);
    state->releaseAnimPlaying = 0;
    state->queuedObject = NULL;
    storeZeroToFloatParam(&state->releaseTimer);
}

void barrelgener_release(void)
{
}

void barrelgener_initialise(void)
{
}

ObjectDescriptor gBarrelGenerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)barrelgener_initialise,
    (ObjectDescriptorCallback)barrelgener_release,
    0,
    (ObjectDescriptorCallback)barrelgener_init,
    (ObjectDescriptorCallback)barrelgener_update,
    (ObjectDescriptorCallback)barrelgener_hitDetect,
    (ObjectDescriptorCallback)barrelgener_render,
    (ObjectDescriptorCallback)barrelgener_free,
    (ObjectDescriptorCallback)barrelgener_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)barrelgener_getExtraSize,
};
