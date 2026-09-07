/*
 * WM_newcryst (DLL 0x0215) - power crystals at Krazoa Palace.
 *
 * The crystal variants emit orbiting or directional effects and react
 * to finale sequence events.
 */
#include "dolphin/mtx/vec.h"
#include "main/camera.h"
#include "main/dll/WM/dll_0215_wmnewcrystal.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/obj_path.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/objseq.h"

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

int WM_newcrystal_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    WmNewCrystalState* state;
    WmNewCrystalParticleParams params;
    Vec cameraDelta;
    int i;

    state = obj->extra;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case WMNEWCRYSTAL_EVENT_DETONATE:
            PSVECSubtract(&Camera_GetCurrent()->position, &obj->anim.localPos, &cameraDelta);
            PSVECNormalize(&cameraDelta, &cameraDelta);
            PSVECScale(&cameraDelta, &cameraDelta, 100.0f);
            PSVECAdd(&obj->anim.localPos, &cameraDelta, &obj->anim.localPos);
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
            spawnExplosion(obj, 100.0f, 1, 1, 0, 0, 0, 0, 0);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            if (obj->anim.romDefNo == WMNEWCRYSTAL_OBJECT_BLUE)
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

    if (obj->anim.romDefNo == WMNEWCRYSTAL_OBJECT_BLUE)
    {
        if (mainGetBit(WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX) == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, NULL, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, &params, 2, -1, NULL);
        }
        objfx_spawnCrystalOrbitEffects(obj, state->fxState, 640.0f, 36.0f, -60.0f, 5.0f, 100.0f, 1);
        objfx_spawnCrystalOrbitEffects(obj, state->secondaryFxState, 640.0f, 36.0f, 60.0f, 5.0f, 0.0f, 1);
    }
    else if (obj->anim.romDefNo == WMNEWCRYSTAL_OBJECT_GREEN && state->greenBurstsActive != 0)
    {
        ObjPath_GetPointLocalPosition(obj, 0, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 1;
        objfx_spawnDirectionalBurst(obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);

        ObjPath_GetPointLocalPosition(obj, 1, &params.x, &params.y, &params.z);
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
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
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
