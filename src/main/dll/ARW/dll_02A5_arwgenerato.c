#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

int arwgenerato_getExtraSize(void) { return 4; }

int arwgenerato_getObjectTypeId(void) { return 0; }

void arwgenerato_free(void) {}

void arwgenerato_hitDetect(void) {}

void arwgenerato_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7150);
}

#pragma scheduling off
void arwgenerato_init(int obj, int setup)
{
    ARWGeneratorState *state = ((GameObject *)obj)->extra;
    ARWGeneratorSetup *mapData = (ARWGeneratorSetup *)setup;

    state->spawnTimer = (f32)(u32)mapData->spawnInterval;
}
#pragma scheduling reset

void arwgenerato_release(void) {}

void arwgenerato_initialise(void) {}

#pragma scheduling off
void arwgenerato_update(int obj)
{
    ARWGeneratorState *state = ((GameObject *)obj)->extra;
    ARWGeneratorSetup *mapData = (ARWGeneratorSetup *)((GameObject *)obj)->anim.placementData;
    f32 timer = state->spawnTimer;
    f32 thr = lbl_803E7154;

    if (timer > thr) {
        state->spawnTimer = timer - timeDelta;
        if (state->spawnTimer <= thr) {
            switch (mapData->spawnMode) {
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
#pragma scheduling reset
