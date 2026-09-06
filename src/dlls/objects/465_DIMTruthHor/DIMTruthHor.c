/*
 * DIMTruthHor (DLL 0x1D1) - a breakable ice target.
 *
 * Once its hit count is depleted, the object sets its game bit and advances
 * through a timed particle burst before hiding its model.
 */
#include "dlls/objects/465_DIMTruthHor.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

#define DIM_TRUTH_HORN_ICE_SHATTER_DELAY         20.0f
#define DIM_TRUTH_HORN_ICE_BURST_PARTICLE_COUNT  30
#define DIM_TRUTH_HORN_ICE_PARTICLE_EFFECT_A     2043
#define DIM_TRUTH_HORN_ICE_PARTICLE_EFFECT_B     2044
#define DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MIN       -100
#define DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MAX       100
#define DIM_TRUTH_HORN_ICE_PARTICLE_Y_MIN        0
#define DIM_TRUTH_HORN_ICE_PARTICLE_Y_MAX        350
#define DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE 0.1f
#define DIM_TRUTH_HORN_ICE_PARTICLE_SCALE        1.0f

typedef enum DimTruthHornIcePhase {
    DIM_TRUTH_HORN_ICE_PHASE_INTACT = 0,
    DIM_TRUTH_HORN_ICE_PHASE_SHATTERING = 1,
    DIM_TRUTH_HORN_ICE_PHASE_SHATTERED = 2,
} DimTruthHornIcePhase;

int dimtruthhornice_countdownCallback(GameObject* obj, int damage) {
    u8* stateBytes = obj->extra;

    *(s8*)(stateBytes + 2) = (s8)(stateBytes[2] - damage);
    return *(s8*)(stateBytes + 2) <= 0;
}

int dimtruthhornice_getExtraSize(void) {
    return sizeof(DimTruthHornIceState);
}

void dimtruthhornice_update(GameObject* obj) {
    DimTruthHornIceState* state = obj->extra;

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    switch (state->phase) {
    case DIM_TRUTH_HORN_ICE_PHASE_INTACT:
        if (state->hitsLeft <= 0) {
            if (state->gameBit != -1) {
                mainSetBits(state->gameBit, 1);
                ObjHits_DisableObject(obj);
                state->phase = DIM_TRUTH_HORN_ICE_PHASE_SHATTERING;
                state->timer = 0.0f;
            }
        } else {
            int* tricky = (int*)getTrickyObject();

            if (tricky != NULL) {
                if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                    TRICKY_INTERFACE(tricky)->sideCommandEnable((GameObject*)tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                               TRICKY_COMMAND_TYPE_FLAME);
                }
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            }
        }
        break;
    case DIM_TRUTH_HORN_ICE_PHASE_SHATTERING: {
        PartFxSpawnParams spawnParams;

        state->timer += timeDelta;
        if (state->timer > DIM_TRUTH_HORN_ICE_SHATTER_DELAY) {
            int particleCount;

            state->phase = DIM_TRUTH_HORN_ICE_PHASE_SHATTERED;
            Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
            for (particleCount = DIM_TRUTH_HORN_ICE_BURST_PARTICLE_COUNT; particleCount != 0; particleCount--) {
                spawnParams.posX =
                    DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE *
                    (f32)(int)randomGetRange(DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MIN, DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MAX);
                spawnParams.posY =
                    DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE *
                    (f32)(int)randomGetRange(DIM_TRUTH_HORN_ICE_PARTICLE_Y_MIN, DIM_TRUTH_HORN_ICE_PARTICLE_Y_MAX);
                spawnParams.posZ =
                    DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE *
                    (f32)(int)randomGetRange(DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MIN, DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MAX);
                spawnParams.scale = DIM_TRUTH_HORN_ICE_PARTICLE_SCALE;
                (*gPartfxInterface)->spawnObject(obj, DIM_TRUTH_HORN_ICE_PARTICLE_EFFECT_A, &spawnParams, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, DIM_TRUTH_HORN_ICE_PARTICLE_EFFECT_B, &spawnParams, 2, -1, NULL);
            }
        }
        spawnParams.posX =
            DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE *
            (f32)(int)randomGetRange(DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MIN, DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MAX);
        spawnParams.posY =
            DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE *
            (f32)(int)randomGetRange(DIM_TRUTH_HORN_ICE_PARTICLE_Y_MIN, DIM_TRUTH_HORN_ICE_PARTICLE_Y_MAX);
        spawnParams.posZ =
            DIM_TRUTH_HORN_ICE_PARTICLE_OFFSET_SCALE *
            (f32)(int)randomGetRange(DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MIN, DIM_TRUTH_HORN_ICE_PARTICLE_XZ_MAX);
        spawnParams.scale = DIM_TRUTH_HORN_ICE_PARTICLE_SCALE;
        (*gPartfxInterface)->spawnObject(obj, DIM_TRUTH_HORN_ICE_PARTICLE_EFFECT_B, &spawnParams, 2, -1, NULL);
        break;
    }
    case DIM_TRUTH_HORN_ICE_PHASE_SHATTERED:
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    }
}

void dimtruthhornice_init(GameObject* obj, const DimTruthHornIcePlacement* placement) {
    DimTruthHornIceState* state = obj->extra;

    state->hitsLeft = (s8)placement->hitCount;
    state->gameBit = placement->gameBit;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);
    {
        s16 gameBit = state->gameBit;

        if (gameBit != -1 && mainGetBit(gameBit) != 0u) {
            ObjHits_DisableObject(obj);
            state->phase = DIM_TRUTH_HORN_ICE_PHASE_SHATTERED;
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

ObjectDescriptor gDIMTruthHornIceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dimtruthhornice_init,
    (ObjectDescriptorCallback)dimtruthhornice_update,
    0,
    0,
    0,
    0,
    dimtruthhornice_getExtraSize,
};
