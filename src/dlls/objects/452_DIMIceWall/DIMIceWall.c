/*
 * DIMIceWall (DLL 0x1C4) - breakable DarkIce Mines ice wall.
 * When its hit points reach zero, it emits two particle bursts and latches a
 * game bit; while intact, it offers Tricky's contextual command.
 */

#include "dlls/objects/452_DIMIceWall.h"

#include "dlls/objects/288_TrickyGuard.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/partfx_interface.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/gamebits_api.h"
#include "main/objprint_render_api.h"
#include "main/vecmath.h"

#define DIM_ICE_WALL_SILENT_MAP_ID 7433

#define DIM_ICE_WALL_SHATTER_SCALE_DIVISOR 50.0f
#define DIM_ICE_WALL_RANDOM_OFFSET_SCALE   0.1f

#define DIM_ICE_WALL_HORIZONTAL_RANDOM_MIN (-250)
#define DIM_ICE_WALL_HORIZONTAL_RANDOM_MAX 250
#define DIM_ICE_WALL_VERTICAL_RANDOM_MIN   0
#define DIM_ICE_WALL_VERTICAL_RANDOM_MAX   450

#define DIM_ICE_WALL_PRIMARY_PARTICLE_COUNT   45
#define DIM_ICE_WALL_PRIMARY_PARTICLE_ID      2041
#define DIM_ICE_WALL_SECONDARY_PARTICLE_COUNT 25
#define DIM_ICE_WALL_SECONDARY_PARTICLE_ID    2042
#define DIM_ICE_WALL_PARTICLE_SPAWN_MODE      2

int dimicewall_countdownCallback(GameObject* obj, int delta) {
    DimIceWallState* state = obj->extra;

    state->hitPoints = (s8)(state->hitPoints - delta);
    return state->hitPoints <= 0;
}

int dimicewall_getExtraSize(void) {
    return sizeof(DimIceWallState);
}

void dimicewall_update(GameObject* obj) {
    DimIceWallState* state = obj->extra;
    DimIceWallPlacement* placement = (DimIceWallPlacement*)obj->anim.placementData;

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (state->shattered == 0) {
        if (state->hitPoints <= 0) {
            PartFxSpawnParams spawnParams;
            int i;

            spawnParams.scale = (f32)placement->shatterScale / DIM_ICE_WALL_SHATTER_SCALE_DIVISOR;
            spawnParams.posZ = 0.0f;
            for (i = DIM_ICE_WALL_PRIMARY_PARTICLE_COUNT; i != 0; i--) {
                spawnParams.posX = spawnParams.scale * (DIM_ICE_WALL_RANDOM_OFFSET_SCALE *
                                                        (f32)randomGetRange(DIM_ICE_WALL_HORIZONTAL_RANDOM_MIN,
                                                                                 DIM_ICE_WALL_HORIZONTAL_RANDOM_MAX));
                spawnParams.posY = spawnParams.scale * (DIM_ICE_WALL_RANDOM_OFFSET_SCALE *
                                                        (f32)randomGetRange(DIM_ICE_WALL_VERTICAL_RANDOM_MIN,
                                                                                 DIM_ICE_WALL_VERTICAL_RANDOM_MAX));
                (*gPartfxInterface)
                    ->spawnObject((int*)obj, DIM_ICE_WALL_PRIMARY_PARTICLE_ID, &spawnParams,
                                  DIM_ICE_WALL_PARTICLE_SPAWN_MODE, -1, NULL);
            }
            for (i = DIM_ICE_WALL_SECONDARY_PARTICLE_COUNT; i != 0; i--) {
                spawnParams.posX = spawnParams.scale * (DIM_ICE_WALL_RANDOM_OFFSET_SCALE *
                                                        (f32)randomGetRange(DIM_ICE_WALL_HORIZONTAL_RANDOM_MIN,
                                                                                 DIM_ICE_WALL_HORIZONTAL_RANDOM_MAX));
                spawnParams.posY = spawnParams.scale * (DIM_ICE_WALL_RANDOM_OFFSET_SCALE *
                                                        (f32)randomGetRange(DIM_ICE_WALL_VERTICAL_RANDOM_MIN,
                                                                                 DIM_ICE_WALL_VERTICAL_RANDOM_MAX));
                (*gPartfxInterface)
                    ->spawnObject((int*)obj, DIM_ICE_WALL_SECONDARY_PARTICLE_ID, &spawnParams,
                                  DIM_ICE_WALL_PARTICLE_SPAWN_MODE, -1, NULL);
            }
            if ((u32)placement->base.ident != DIM_ICE_WALL_SILENT_MAP_ID) {
                Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
            }
            state->shattered = 1;
            if (placement->shatterGameBit != -1) {
                mainSetBits(placement->shatterGameBit, 1);
            }
        } else {
            GameObject* tricky = getTrickyObject();

            if (tricky != NULL) {
                if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                    TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                               TRICKY_COMMAND_TYPE_FLAME);
                }
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                objUpdateHitVolumeTransforms(obj);
            }
        }
    }
}

void dimicewall_init(GameObject* obj, DimIceWallPlacement* placement) {
    DimIceWallState* state = obj->extra;

    state->hitPoints = (s8)placement->hitPoints;
    if (placement->shatterGameBit != -1) {
        state->shattered = mainGetBit(placement->shatterGameBit);
    }
    obj->anim.rotX = (s16)((s32)placement->rotationXByte << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}

ObjectDescriptor gDIMIceWallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dimicewall_init,
    (ObjectDescriptorCallback)dimicewall_update,
    0,
    0,
    0,
    0,
    dimicewall_getExtraSize,
};
