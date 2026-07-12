/*
 * DLL 0x0215 - wmnewcrystal (gResourceDescriptors[0x215]): the blue/green power
 * crystals at Krazoa Palace (map 'warlock'). TU: 0x801F943C-0x801F9804.
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
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/objfx.h"
#include "main/camera.h"
#include "main/dll/WM/dll_0215_wmnewcrystal.h"

#define WMNEWCRYSTAL_GAMEBIT_ACTIVE     0xd27
#define WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX 0xe49
#define WMNEWCRYSTAL_OBJECT_BLUE        0x783
#define WMNEWCRYSTAL_OBJECT_GREEN       0x784
#define WMNEWCRYSTAL_PARTICLE_ID        0x7ed

extern void PSVECSubtract(f32* a, f32* b, f32* out);
extern void PSVECNormalize(f32* src, f32* dst);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void PSVECAdd(f32* a, f32* b, f32* out);
extern void WM_newcrystalFn_800969b0(GameObject* obj, void* params, f32 a, f32 b, f32 c, f32 d, f32 e, int enabled);

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

int WM_newcrystal_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* actor)
{
    WmNewCrystalState* state;
    WmNewCrystalParticleParams params;
    f32 cameraDelta[3];
    int i;

    state = obj->extra;
    for (i = 0; i < actor->eventCount; i++)
    {
        switch (actor->eventIds[i])
        {
        case 1:
            PSVECSubtract((f32*)((char*)Camera_GetCurrentViewSlot() + 0xc), &obj->anim.localPosX, cameraDelta);
            PSVECNormalize(cameraDelta, cameraDelta);
            PSVECScale(cameraDelta, cameraDelta, 100.0f);
            PSVECAdd(&obj->anim.localPosX, cameraDelta, &obj->anim.localPosX);
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
            spawnExplosionLegacy((int*)obj, 100.0f, 1, 1, 0, 0, 0, 0, 0);
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
            if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE)
            {
                mainSetBits(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 0);
            }
            break;
        case 2:
            state->active = 0;
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
        WM_newcrystalFn_800969b0((GameObject*)obj, state, 640.0f, 36.0f, -60.0f, 5.0f, 100.0f, 1);
        WM_newcrystalFn_800969b0((GameObject*)obj, state->altFxState, 640.0f, 36.0f, 60.0f, 5.0f, 0.0f, 1);
    }
    else if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_GREEN && state->active != 0)
    {
        ObjPath_GetPointLocalPosition((GameObject*)obj, 0, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 1;
        objfx_spawnDirectionalBurstLegacy((int*)obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);

        ObjPath_GetPointLocalPosition((GameObject*)obj, 1, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 0;
        objfx_spawnDirectionalBurstLegacy((int*)obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);
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

void WM_newcrystal_render(int obj, int p2, int p3, int p4, int p5, s8 vis)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f); /* literal, not the named 1.0 extern (#71 pool shape) */
}

void WM_newcrystal_hitDetect(void)
{
}

void WM_newcrystal_update(void)
{
}

void WM_newcrystal_init(GameObject* obj, void* setup)
{
    WmNewCrystalState* state = obj->extra;
    obj->animEventCallback = WM_newcrystal_SeqFn;
    if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) > 1)
    {
        mainSetBits(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 1);
        state->active = 1;
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

/* descriptor/ptr table auto 0x80328e90-0x80329050 */
u32 gVFP_LevelControlObjDescriptor[14] = {0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          0x00090000,
                                          (u32)VFP_LevelControl_initialise,
                                          (u32)VFP_LevelControl_release,
                                          0x00000000,
                                          (u32)VFP_LevelControl_init,
                                          (u32)VFP_LevelControl_update,
                                          (u32)VFP_LevelControl_hitDetect,
                                          (u32)VFP_LevelControl_render,
                                          (u32)VFP_LevelControl_free,
                                          (u32)VFP_LevelControl_getObjectTypeId,
                                          (u32)VFP_LevelControl_getExtraSize};
u32 gVFP_ObjCreatorObjDescriptor[14] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x00090000,
                                        (u32)VFP_ObjCreator_initialise,
                                        (u32)VFP_ObjCreator_release,
                                        0x00000000,
                                        (u32)VFP_ObjCreator_init,
                                        (u32)VFP_ObjCreator_update,
                                        (u32)VFP_ObjCreator_hitDetect,
                                        (u32)VFP_ObjCreator_render,
                                        (u32)VFP_ObjCreator_free,
                                        (u32)VFP_ObjCreator_getObjectTypeId,
                                        (u32)VFP_ObjCreator_getExtraSize};
u32 lbl_80328F00[14] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00090000,
                        (u32)VFP_MiniFire_initialise,
                        (u32)VFP_MiniFire_release,
                        0x00000000,
                        (u32)VFP_MiniFire_init,
                        (u32)VFP_MiniFire_update,
                        (u32)VFP_MiniFire_hitDetect,
                        (u32)VFP_MiniFire_render,
                        (u32)VFP_MiniFire_free,
                        (u32)VFP_MiniFire_getObjectTypeId,
                        (u32)VFP_MiniFire_getExtraSize};
u32 dll_219[14] = {0x00000000,
                   0x00000000,
                   0x00000000,
                   0x00090000,
                   (u32)dll_219_initialise_nop,
                   (u32)dll_219_release_nop,
                   0x00000000,
                   (u32)dll_219_init,
                   (u32)dll_219_update,
                   (u32)dll_219_hitDetect_nop,
                   (u32)dll_219_render_nop,
                   (u32)dll_219_free,
                   (u32)dll_219_getObjectTypeId,
                   (u32)dll_219_getExtraSize_ret_4};
u32 gVFP_statueballObjDescriptor[14] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x00090000,
                                        (u32)VFP_statueball_initialise,
                                        (u32)VFP_statueball_release,
                                        0x00000000,
                                        (u32)VFP_statueball_init,
                                        (u32)VFP_statueball_update,
                                        (u32)VFP_statueball_hitDetect,
                                        (u32)VFP_statueball_render,
                                        (u32)VFP_statueball_free,
                                        (u32)VFP_statueball_getObjectTypeId,
                                        (u32)VFP_statueball_getExtraSize};
u32 dll_21B[14] = {0x00000000,
                   0x00000000,
                   0x00000000,
                   0x00090000,
                   (u32)dll_21B_initialise_nop,
                   (u32)dll_21B_release_nop,
                   0x00000000,
                   (u32)dll_21B_init,
                   (u32)dll_21B_update,
                   (u32)dll_21B_hitDetect_nop,
                   (u32)dll_21B_render_nop,
                   (u32)dll_21B_free,
                   (u32)dll_21B_getObjectTypeId,
                   (u32)dll_21B_getExtraSize_ret_4};
u32 gVFP_LaddersObjDescriptor[14] = {0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     0x00090000,
                                     (u32)VFP_Ladders_initialise,
                                     (u32)VFP_Ladders_release,
                                     0x00000000,
                                     (u32)VFP_Ladders_init,
                                     (u32)VFP_Ladders_update,
                                     (u32)VFP_Ladders_hitDetect,
                                     (u32)VFP_Ladders_render,
                                     (u32)VFP_Ladders_free,
                                     (u32)VFP_Ladders_getObjectTypeId,
                                     (u32)VFP_Ladders_getExtraSize};
u32 gVFPLiftObjDescriptor[14] = {0x00000000,
                                 0x00000000,
                                 0x00000000,
                                 0x00090000,
                                 (u32)VFPLift_initialise,
                                 (u32)VFPLift_release,
                                 0x00000000,
                                 (u32)VFPLift_init,
                                 (u32)VFPLift_update,
                                 (u32)VFPLift_hitDetect,
                                 (u32)VFPLift_render,
                                 (u32)VFPLift_free,
                                 (u32)VFPLift_getObjectTypeId,
                                 (u32)VFPLift_getExtraSize};
