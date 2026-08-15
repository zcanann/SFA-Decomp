/*
 * MMP_gyserve (DLL 0x183) - Moon Mountain Pass geyser vent.
 *
 * While its placement gamebit is clear, the vent alternates between random
 * idle and active periods. The active period emits geyser particles and
 * keeps the vent sound alive.
 */
#include "dlls/objects/387_MMP_gyserve.h"

#include "game/objects/object.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/vecmath.h"

#define MMP_GEYSER_VENT_PARTICLE_GEYSER     0x724
#define MMP_GEYSER_VENT_PARTICLE_SPAWN_MODE 2
#define MMP_GEYSER_VENT_PARTICLE_MODEL_NONE -1

#define MMP_GEYSER_VENT_INITIAL_IDLE_MIN 10
#define MMP_GEYSER_VENT_INITIAL_IDLE_MAX 200
#define MMP_GEYSER_VENT_IDLE_MIN         70
#define MMP_GEYSER_VENT_IDLE_MAX         240
#define MMP_GEYSER_VENT_ACTIVE_MIN       30
#define MMP_GEYSER_VENT_ACTIVE_MAX       60

#define MMP_GEYSER_VENT_IDLE_TIMER(obj)   ((obj)->userData1)
#define MMP_GEYSER_VENT_ACTIVE_TIMER(obj) ((obj)->userData2)

int mmpGeyserVent_getExtraSize(void) {
    return 0;
}

int mmpGeyserVent_getObjectTypeId(void) {
    return 0;
}

void mmpGeyserVent_free(void) {
}

void mmpGeyserVent_render(void) {
}

void mmpGeyserVent_hitDetect(void) {
}

void mmpGeyserVent_update(GameObject* obj) {
    const MMPGeyserVentPlacement* placement = (const MMPGeyserVentPlacement*)obj->anim.placementData;

    if (mainGetBit(placement->disableGameBit) != 0) {
        return;
    }
    MMP_GEYSER_VENT_IDLE_TIMER(obj) -= framesThisStep;
    if (MMP_GEYSER_VENT_IDLE_TIMER(obj) < 0) {
        MMP_GEYSER_VENT_IDLE_TIMER(obj) = randomGetRange(MMP_GEYSER_VENT_IDLE_MIN, MMP_GEYSER_VENT_IDLE_MAX);
        MMP_GEYSER_VENT_ACTIVE_TIMER(obj) = randomGetRange(MMP_GEYSER_VENT_ACTIVE_MIN, MMP_GEYSER_VENT_ACTIVE_MAX);
    }
    if (MMP_GEYSER_VENT_ACTIVE_TIMER(obj) == 0) {
        return;
    }
    MMP_GEYSER_VENT_ACTIVE_TIMER(obj) -= framesThisStep;
    if (MMP_GEYSER_VENT_ACTIVE_TIMER(obj) <= 0) {
        MMP_GEYSER_VENT_ACTIVE_TIMER(obj) = 0;
    } else {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, MMP_GEYSER_VENT_PARTICLE_GEYSER, NULL, MMP_GEYSER_VENT_PARTICLE_SPAWN_MODE,
                          MMP_GEYSER_VENT_PARTICLE_MODEL_NONE, NULL);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_en_diallp_c_450);
    }
}

void mmpGeyserVent_init(GameObject* obj) {
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    MMP_GEYSER_VENT_IDLE_TIMER(obj) =
        randomGetRange(MMP_GEYSER_VENT_INITIAL_IDLE_MIN, MMP_GEYSER_VENT_INITIAL_IDLE_MAX);
    obj->anim.alpha = 0;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
}

void mmpGeyserVent_release(void) {
}

void mmpGeyserVent_initialise(void) {
}

ObjectDescriptor gMMPGeyserVentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmpGeyserVent_initialise,
    (ObjectDescriptorCallback)mmpGeyserVent_release,
    0,
    (ObjectDescriptorCallback)mmpGeyserVent_init,
    (ObjectDescriptorCallback)mmpGeyserVent_update,
    (ObjectDescriptorCallback)mmpGeyserVent_hitDetect,
    (ObjectDescriptorCallback)mmpGeyserVent_render,
    (ObjectDescriptorCallback)mmpGeyserVent_free,
    (ObjectDescriptorCallback)mmpGeyserVent_getObjectTypeId,
    mmpGeyserVent_getExtraSize,
};
