/*
 * DLL 0x0215 - wmnewcrystal (gResourceDescriptors[0x215]): the blue/green power
 * crystals at Krazoa Palace (map 'warlock').
 * The warlock romlist places all three variants (defs 890/891/892 'WM_newcrystal',
 * types 0x783 blue / 0x784 green / 0x785): Krystal's crystal-prison set seen in
 * the finale. While the active game bit is set, the blue crystal runs its two glow
 * effects every sequence tick (plus an ambient particle pair until the ambient bit
 * is granted) and the green crystal sprays directional bursts from its two path
 * points. Sequence event 1 is the on-camera finale detonation: the object is pulled
 * 100 units toward the camera, blown up via the shared spawnExplosion() (the same
 * engine routine - and therefore the same effect and sound - as the gunpowder
 * barrels), and hidden. Event 2 retires the green crystal's bursts.
 */
#include "main/dll/partfx_interface.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"
#include "main/objfx.h"
#include "main/obj_path.h"
#include "main/camera.h"
#include "main/dll/WM/dll_0215_wmnewcrystal.h"

#define WMNEWCRYSTAL_GAMEBIT_ACTIVE     0xd27
#define WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX 0xe49
#define WMNEWCRYSTAL_OBJECT_BLUE        0x783
#define WMNEWCRYSTAL_OBJECT_GREEN       0x784
#define WMNEWCRYSTAL_PARTICLE_ID        0x7ed

enum
{
    WMNEWCRYSTAL_EVENT_DETONATE = 1,
    WMNEWCRYSTAL_EVENT_STOP_GREEN_BURSTS = 2
};

ObjectDescriptor gWM_newcrystalObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    WM_newcrystal_initialise,
    WM_newcrystal_release,
    0,
    (ObjectDescriptorCallback)WM_newcrystal_init,
    WM_newcrystal_update,
    WM_newcrystal_hitDetect,
    (ObjectDescriptorCallback)WM_newcrystal_render,
    WM_newcrystal_free,
    (ObjectDescriptorCallback)WM_newcrystal_getObjectTypeId,
    WM_newcrystal_getExtraSize,
};

int WM_newcrystal_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WmNewCrystalState* state;
    WmNewCrystalParticleParams params;
    f32 cameraDelta[3];
    int i;

    state = obj->extra;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case WMNEWCRYSTAL_EVENT_DETONATE:
            PSVECSubtract(&Camera_GetCurrentViewSlot()->position.x, &obj->anim.localPosX, cameraDelta);
            PSVECNormalize(cameraDelta, cameraDelta);
            PSVECScale(cameraDelta, cameraDelta, 100.0f);
            PSVECAdd(&obj->anim.localPosX, cameraDelta, &obj->anim.localPosX);
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
            spawnExplosion(obj, 100.0f, 1, 1, 0, 0, 0, 0, 0);
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
            if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE)
            {
                mainSetBits(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 0);
            }
            break;
        case WMNEWCRYSTAL_EVENT_STOP_GREEN_BURSTS:
            state->greenBurstsActive = 0;
            break;
        }
    }

    if (mainGetBit(WMNEWCRYSTAL_GAMEBIT_ACTIVE) == 0)
    {
        return 0;
    }

    if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE)
    {
        if (mainGetBit(WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX) == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, NULL, 2, -1, NULL);
            /* params is uninitialized here on purpose - retail passes the raw
               stack block for this effect */
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, &params, 2, -1, NULL);
        }
        objfx_spawnCrystalOrbitEffects(obj, state->fxState, 640.0f, 36.0f, -60.0f, 5.0f, 100.0f, 1);
        objfx_spawnCrystalOrbitEffects(obj, state->secondaryFxState, 640.0f, 36.0f, 60.0f, 5.0f, 0.0f, 1);
    }
    else if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_GREEN && state->greenBurstsActive != 0)
    {
        ObjPath_GetPointLocalPosition((GameObject*)obj, 0, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 1;
        objfx_spawnDirectionalBurst(obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);

        ObjPath_GetPointLocalPosition((GameObject*)obj, 1, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 0;
        objfx_spawnDirectionalBurst(obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);
    }
    return 0;
}

int WM_newcrystal_getExtraSize(void)
{
    return sizeof(WmNewCrystalState);
}

int WM_newcrystal_getObjectTypeId(void)
{
    return 0x0;
}

void WM_newcrystal_free(void)
{
}

void WM_newcrystal_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f); /* literal, not the named 1.0 extern (#71 pool shape) */
}

void WM_newcrystal_hitDetect(void)
{
}

void WM_newcrystal_update(void)
{
}

void WM_newcrystal_init(GameObject* obj, ObjPlacement* unused)
{
    WmNewCrystalState* state = obj->extra;
    obj->animEventCallback = WM_newcrystal_SeqFn;
    if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) > 1)
    {
        mainSetBits(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 1);
        state->greenBurstsActive = 1;
    }
}

void WM_newcrystal_release(void)
{
}

void WM_newcrystal_initialise(void)
{
}

#include "main/dll/dll_0219.h"
#include "main/dll/dll_021B.h"
#include "main/dll/VF/dll_021C_vfpladders.h"
#include "main/dll/VF/dll_0216_vfplevelcontrol.h"
#include "main/dll/VF/dll_021D_vfplift.h"
#include "main/dll/VF/dll_0218_vfpminifire.h"
#include "main/dll/VF/dll_0217_vfpobjcreator.h"
#include "main/dll/VF/dll_021A_vfpstatueball.h"

/* VFP object descriptors sharing this data pool. */
ObjectDescriptor gVFP_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_LevelControl_initialise,
    (ObjectDescriptorCallback)VFP_LevelControl_release,
    0,
    (ObjectDescriptorCallback)VFP_LevelControl_init,
    (ObjectDescriptorCallback)VFP_LevelControl_update,
    (ObjectDescriptorCallback)VFP_LevelControl_hitDetect,
    (ObjectDescriptorCallback)VFP_LevelControl_render,
    (ObjectDescriptorCallback)VFP_LevelControl_free,
    (ObjectDescriptorCallback)VFP_LevelControl_getObjectTypeId,
    VFP_LevelControl_getExtraSize,
};
ObjectDescriptor gVFP_ObjCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_ObjCreator_initialise,
    (ObjectDescriptorCallback)VFP_ObjCreator_release,
    0,
    (ObjectDescriptorCallback)VFP_ObjCreator_init,
    (ObjectDescriptorCallback)VFP_ObjCreator_update,
    (ObjectDescriptorCallback)VFP_ObjCreator_hitDetect,
    (ObjectDescriptorCallback)VFP_ObjCreator_render,
    (ObjectDescriptorCallback)VFP_ObjCreator_free,
    (ObjectDescriptorCallback)VFP_ObjCreator_getObjectTypeId,
    VFP_ObjCreator_getExtraSize,
};
ObjectDescriptor gVFP_MiniFireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_MiniFire_initialise,
    (ObjectDescriptorCallback)VFP_MiniFire_release,
    0,
    (ObjectDescriptorCallback)VFP_MiniFire_init,
    (ObjectDescriptorCallback)VFP_MiniFire_update,
    (ObjectDescriptorCallback)VFP_MiniFire_hitDetect,
    (ObjectDescriptorCallback)VFP_MiniFire_render,
    (ObjectDescriptorCallback)VFP_MiniFire_free,
    (ObjectDescriptorCallback)VFP_MiniFire_getObjectTypeId,
    VFP_MiniFire_getExtraSize,
};
ObjectDescriptor dll_219 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_219_initialise_nop,
    (ObjectDescriptorCallback)dll_219_release_nop,
    0,
    (ObjectDescriptorCallback)dll_219_init,
    (ObjectDescriptorCallback)dll_219_update,
    (ObjectDescriptorCallback)dll_219_hitDetect_nop,
    (ObjectDescriptorCallback)dll_219_render_nop,
    (ObjectDescriptorCallback)dll_219_free,
    (ObjectDescriptorCallback)dll_219_getObjectTypeId,
    dll_219_getExtraSize_ret_4,
};
ObjectDescriptor gVFP_statueballObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_statueball_initialise,
    (ObjectDescriptorCallback)VFP_statueball_release,
    0,
    (ObjectDescriptorCallback)VFP_statueball_init,
    (ObjectDescriptorCallback)VFP_statueball_update,
    (ObjectDescriptorCallback)VFP_statueball_hitDetect,
    (ObjectDescriptorCallback)VFP_statueball_render,
    (ObjectDescriptorCallback)VFP_statueball_free,
    (ObjectDescriptorCallback)VFP_statueball_getObjectTypeId,
    VFP_statueball_getExtraSize,
};
ObjectDescriptor dll_21B = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_21B_initialise_nop,
    (ObjectDescriptorCallback)dll_21B_release_nop,
    0,
    (ObjectDescriptorCallback)dll_21B_init,
    (ObjectDescriptorCallback)dll_21B_update,
    (ObjectDescriptorCallback)dll_21B_hitDetect_nop,
    (ObjectDescriptorCallback)dll_21B_render_nop,
    (ObjectDescriptorCallback)dll_21B_free,
    (ObjectDescriptorCallback)dll_21B_getObjectTypeId,
    dll_21B_getExtraSize_ret_4,
};
ObjectDescriptor gVFP_LaddersObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_Ladders_initialise,
    (ObjectDescriptorCallback)VFP_Ladders_release,
    0,
    (ObjectDescriptorCallback)VFP_Ladders_init,
    (ObjectDescriptorCallback)VFP_Ladders_update,
    (ObjectDescriptorCallback)VFP_Ladders_hitDetect,
    (ObjectDescriptorCallback)VFP_Ladders_render,
    (ObjectDescriptorCallback)VFP_Ladders_free,
    (ObjectDescriptorCallback)VFP_Ladders_getObjectTypeId,
    VFP_Ladders_getExtraSize,
};
ObjectDescriptor gVFPLiftObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFPLift_initialise,
    (ObjectDescriptorCallback)VFPLift_release,
    0,
    (ObjectDescriptorCallback)VFPLift_init,
    (ObjectDescriptorCallback)VFPLift_update,
    (ObjectDescriptorCallback)VFPLift_hitDetect,
    (ObjectDescriptorCallback)VFPLift_render,
    (ObjectDescriptorCallback)VFPLift_free,
    (ObjectDescriptorCallback)VFPLift_getObjectTypeId,
    VFPLift_getExtraSize,
};
