/*
 * arwgenerato (DLL 0x2A5) - spawner used in the on-rails Arwing flight
 * sections. It holds a single countdown timer (state->spawnTimer, seeded
 * from the placement's spawnInterval) and, when the timer elapses, calls
 * one of two spawn helpers selected by the placement's spawnMode before
 * re-arming the timer. The two spawn helpers (fn_802317A8 / fn_802315EC)
 * live in a sibling flight-section TU.
 */
#include "main/dll/ARW/dll_02A5_arwgenerato.h"
#include "main/frame_timing.h"
#include "main/gameplay_runtime.h"

int arwgenerato_getExtraSize(void)
{
    return 4;
}

int arwgenerato_getObjectTypeId(void)
{
    return 0;
}

void arwgenerato_free(void)
{
}

void arwgenerato_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7150);
}

void arwgenerato_hitDetect(void)
{
}

void arwgenerato_update(GameObject* obj)
{
    ARWGeneratorState* state = (obj)->extra;
    ARWGeneratorSetup* mapData = (ARWGeneratorSetup*)(obj)->anim.placementData;
    f32 timer = state->spawnTimer;
    f32 thr = lbl_803E7154;

    if (timer > thr)
    {
        state->spawnTimer = timer - timeDelta;
        if (state->spawnTimer <= thr)
        {
            switch (mapData->spawnMode)
            {
            case 0:
                fn_802317A8(obj, state, mapData);
                break;
            case 1:
                fn_802315EC(obj, state, mapData);
                break;
            }
            state->spawnTimer = (f32)(u32)mapData->spawnInterval;
        }
    }
}

void arwgenerato_init(GameObject* obj, ARWGeneratorSetup* setup)
{
    ARWGeneratorState* state = obj->extra;
    ARWGeneratorSetup* mapData = setup;

    state->spawnTimer = (f32)(u32)mapData->spawnInterval;
}

void arwgenerato_release(void)
{
}

void arwgenerato_initialise(void)
{
}
