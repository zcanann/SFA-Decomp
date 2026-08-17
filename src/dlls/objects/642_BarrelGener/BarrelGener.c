/*
 * BarrelGener (DLL 642) - the barrel generator/dispenser object.
 *
 * Object-group member 0x3a. On init it joins that group and clears its
 * release state. When the player approaches within range it fires
 * trigger sequence 1 (once, gated by game bit 0xADB). A queued barrel
 * (barrelgener_queueObjectRelease, called from the gunpowder-barrel DLL)
 * is held until its release timer elapses: the dispense animation plays
 * with a PDA camera-off sfx, a compass beep fires partway through, and at
 * timer end the queued barrel is teleported to this object's position,
 * zeroed in velocity, and added to its own update group (25).
 */
#include "dlls/objects/344.h"

#include "dolphin/mtx.h"
#include "main/audio/sfx_play_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/maketex_timer_api.h"
#include "main/obj_query.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/barrelgener_state.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "main/newclouds.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"

int gBarrelGenerReleaseFrameOffset = 0x14;

#define GAMEBIT_BARRELGENER_TRIGGERED 0xadb

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
    s16toFloat(&state->releaseTimer, (s16)(releaseFrame - gBarrelGenerReleaseFrameOffset));
}

int barrelgener_getExtraSize(void)
{
    return sizeof(BarrelGeneratorState);
}

int barrelgener_getObjectTypeId(void)
{
    return 0;
}

void barrelgener_free(GameObject* obj)
{
    objFreeObjectType(obj, BARREL_GENERATOR_OBJECT_GROUP);
}

void barrelgener_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void barrelgener_hitDetect(void)
{
}

void barrelgener_update(GameObject* obj)
{
    BarrelGeneratorState* state = (obj)->extra;
    GameObject* player = Obj_GetPlayerObject();

    if (mainGetBit(GAMEBIT_BARRELGENER_TRIGGERED) == 0)
    {
        if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < 5e+01f)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            mainSetBits(GAMEBIT_BARRELGENER_TRIGGERED, 1);
        }
    }
    if (timerIsActive(&state->releaseTimer) != 0)
    {
        if (state->releaseTimer <= 5.0f && state->releaseAnimPlaying == 0)
        {
            state->releaseAnimPlaying = 1;
            ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_barrelgen_slide);
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
                releaseVelocity = 0.0f;
                releasedBarrel->anim.velocityZ = releaseVelocity;
                releasedBarrel->anim.velocityY = releaseVelocity;
                releasedBarrel->anim.velocityX = releaseVelocity;
                objAddObjectType(state->queuedObject, GUNPOWDER_BARREL_OBJECT_GROUP);
                state->queuedObject = NULL;
            }
        }
    }
    if (state->releaseAnimPlaying != 0)
    {
        if ((obj)->anim.currentMoveProgress > 0.5f)
        {
            if (state->releaseBeepPlayed == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_mzap2_c);
                state->releaseBeepPlayed = 1;
            }
        }
        state->releaseAnimPlaying =
            !ObjAnim_AdvanceCurrentMove(obj, 0.01f, timeDelta, 0);
    }
}

void barrelgener_init(GameObject* obj)
{
    BarrelGeneratorState* state = (obj)->extra;

    objAddObjectType(obj, BARREL_GENERATOR_OBJECT_GROUP);
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
