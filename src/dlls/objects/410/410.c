/* DLL 0x19A (slot 410) - timed child-object spawner. */
#include "dlls/objects/410.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_placement.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_0082_modgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"

#define DLL19A_EFFECT_RESOURCE_ID          0x82
#define DLL19A_RESET_GAMEBIT               0x5B9
#define DLL19A_TRIGGER_GAMEBIT_BASE        0x1CD
#define DLL19A_DROPPED_ITEM_GAMEBIT        0x1CE
#define DLL19A_CHILD_GAMEBIT               0x1E7
#define DLL19A_CHILD_OBJECT_ID             0x2D0
#define DLL19A_CHILD_DROPPED_ITEM_ID       0x49
#define DLL19A_CHILD_INITIAL_WEAPON_ID     1
#define DLL19A_CHILD_AGGRO_RANGE           0xFF
#define DLL19A_CHILD_FLAGS                 2
#define DLL19A_SPAWN_TIMER                 100
#define DLL19A_FULL_ALPHA                  0xFF
#define DLL19A_RENDER_SCALE                1.0f
#define DLL19A_CHILD_DISABLE_CAMERA_TARGET 0x20

int dll410_getExtraSize(void) {
    return sizeof(Dll19AState);
}

int dll410_getObjectTypeId(void) {
    return 0;
}

void dll410_free(void) {
}

void dll410_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL19A_RENDER_SCALE);
    }
}

void dll410_hitDetect(void) {
}

void dll410_update(GameObject* obj) {
    const Dll19APlacement* placement;
    Dll19AState* state;
    Dll82Interface** effectResource;
    EnemyPlacement* spawnSetup;
    GameObject* child;
    u8 canSetupObject;

    placement = (const Dll19APlacement*)obj->anim.placementData;
    state = obj->extra;
    if (mainGetBit(DLL19A_RESET_GAMEBIT) != 0) {
        obj->userData2 = 0;
        state->spawnTimer = DLL19A_SPAWN_TIMER;
        state->spawnTimerRate = 0;
        obj->anim.renderAlpha = DLL19A_FULL_ALPHA;
        obj->anim.alpha = DLL19A_FULL_ALPHA;
    } else {
        if (obj->userData2 == 0 && mainGetBit(placement->triggerGameBitOffset + DLL19A_TRIGGER_GAMEBIT_BASE) != 0) {
            effectResource = Resource_Acquire(DLL19A_EFFECT_RESOURCE_ID, 1);
            (*effectResource)->spawn(obj, 0, NULL, 1, -1, NULL);
            (*effectResource)->spawn(obj, 1, NULL, 1, -1, NULL);
            Sfx_PlayFromObject(obj, SFXTRIG_hitpos_6);
            Resource_Release(effectResource);
            state->spawnTimerRate = 1;
            obj->userData2 = 1;
        }
        if (state->spawnTimerRate != 0) {
            state->spawnTimer -= state->spawnTimerRate * framesThisStep;
        }
        if (state->spawnTimer <= 0 && (canSetupObject = Obj_CanSetupObject()) > 0) {
            spawnSetup = (EnemyPlacement*)Obj_AllocObjectSetup(sizeof(EnemyPlacement), DLL19A_CHILD_OBJECT_ID);
            spawnSetup->base.posX = placement->base.posX;
            spawnSetup->base.posY = placement->base.posY;
            spawnSetup->base.posZ = placement->base.posZ;
            spawnSetup->base.color[0] = placement->base.color[0];
            spawnSetup->base.color[1] = placement->base.color[1];
            spawnSetup->base.color[2] = placement->base.color[2];
            spawnSetup->base.color[3] = placement->base.color[3];
            spawnSetup->initialWeaponId = DLL19A_CHILD_INITIAL_WEAPON_ID;
            spawnSetup->gameBit = DLL19A_CHILD_GAMEBIT;
            spawnSetup->unk30 = -1;
            spawnSetup->initialYaw = (s8)(obj->anim.rotX >> 8);
            spawnSetup->flags = DLL19A_CHILD_FLAGS;
            if (mainGetBit(DLL19A_DROPPED_ITEM_GAMEBIT) != 0) {
                spawnSetup->droppedItemId = DLL19A_CHILD_DROPPED_ITEM_ID;
            } else {
                spawnSetup->droppedItemId = -1;
            }
            spawnSetup->aggroRangeByte = DLL19A_CHILD_AGGRO_RANGE;
            spawnSetup->triggerSequenceId = -1;
            {
                int hitPoints;

                hitPoints = placement->triggerGameBitOffset;
                spawnSetup->hitPoints = hitPoints;
            }
            child = objSetupObject(&spawnSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
            if (child != NULL && child->extra != NULL) {
                ((GroundBaddieState*)child->extra)->configFlags = DLL19A_CHILD_DISABLE_CAMERA_TARGET;
            }
            state->spawnTimer = DLL19A_SPAWN_TIMER;
            state->spawnTimerRate = 0;
        }
    }
}

void dll410_init(GameObject* obj, const Dll19APlacement* placement) {
    Dll19AState* state;

    state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->initialYaw << 8);
    obj->userData2 = 0;
    state->spawnTimer = DLL19A_SPAWN_TIMER;
    state->spawnTimerRate = 0;
    obj->anim.renderAlpha = DLL19A_FULL_ALPHA;
    obj->anim.alpha = DLL19A_FULL_ALPHA;
}

void dll410_release(void) {
}

void dll410_initialise(void) {
}

ObjectDescriptor gDll19AObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll410_initialise,
    (ObjectDescriptorCallback)dll410_release,
    0,
    (ObjectDescriptorCallback)dll410_init,
    (ObjectDescriptorCallback)dll410_update,
    (ObjectDescriptorCallback)dll410_hitDetect,
    (ObjectDescriptorCallback)dll410_render,
    (ObjectDescriptorCallback)dll410_free,
    (ObjectDescriptorCallback)dll410_getObjectTypeId,
    dll410_getExtraSize,
};
