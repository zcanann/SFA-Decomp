/* DLL 0x0224 */
#include "dlls/object_descriptor.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "game/objects/object_setup.h"
#include "main/gamebits_api.h"
#include "main/objprint_render_api.h"


u32 gSpellStoneEventId;

typedef struct SpellStoneUseState {
    s16 completeGameBit;
    s16 requiredGameBit;
    u8 used;
} SpellStoneUseState;

typedef struct SpellStonePlacement {
    ObjPlacement base;
    s8 rotXByte; /* 0x18 */
    u8 pad19[5];
    s16 completeGameBit; /* 0x1e */
    s16 requiredGameBit; /* 0x20 */
} SpellStonePlacement;

void SpellStoneUse_updateInteraction(GameObject* obj);
int dll_224_getExtraSize_ret_6(void);
int dll_224_getObjectTypeId(void);
void dll_224_free_nop(void);
void dll_224_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_224_hitDetect(GameObject* obj);
void dll_224_update(GameObject* obj);
void dll_224_init(GameObject* obj, void* other);
void dll_224_release_nop(void);
void dll_224_initialise_nop(void);

void SpellStoneUse_updateInteraction(GameObject* obj) {
    SpellStoneUseState* state = obj->extra;
    s16 cond = 1;
    GameObject* player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    if (state->requiredGameBit != -1) {
        cond = mainGetBit(state->requiredGameBit);
    }
    if ((s16)mainGetBit(state->completeGameBit) != 0 || state->used != 0) {
        return;
    }
    if (cond == 0) {
        return;
    }
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if ((*gGameUIInterface)->isItemBeingUsed(gSpellStoneEventId) != 0) {
        if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < 100.0f) {
            mainSetBits(state->completeGameBit, 1);
            state->used = 1;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
    }
}

int dll_224_getExtraSize_ret_6(void) {
    return 0x6;
}

int dll_224_getObjectTypeId(void) {
    return 0x0;
}

void dll_224_free_nop(void) {
}

void dll_224_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible == 0) {
        return;
    }
}

void dll_224_hitDetect(GameObject* obj) {
    if (obj->anim.hitVolumeTransforms != NULL) {
        objUpdateHitVolumeTransforms(obj);
    }
}

void dll_224_update(GameObject* obj) {
    int mapAct;

    mapAct = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    switch (mapAct) {
    case 1:
        gSpellStoneEventId = 0x123;
        break;
    case 2:
        gSpellStoneEventId = 0x83b;
        break;
    case 3:
        gSpellStoneEventId = 0x83c;
        break;
    default:
        gSpellStoneEventId = 0x123;
        break;
    }
    SpellStoneUse_updateInteraction(obj);
}

void dll_224_init(GameObject* obj, void* other) {
    SpellStoneUseState* extra = obj->extra;
    SpellStonePlacement* def = (SpellStonePlacement*)other;
    s16 rotX = (def->rotXByte << 8);
    u8 hitboxFlags;

    obj->anim.rotX = rotX;
    extra->completeGameBit = def->completeGameBit;
    extra->requiredGameBit = def->requiredGameBit;
    hitboxFlags = (*&obj->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    obj->anim.resetHitboxFlags = hitboxFlags;
}

void dll_224_release_nop(void) {
}

void dll_224_initialise_nop(void) {
}

ObjectDescriptor gDll224ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_224_initialise_nop,
    (ObjectDescriptorCallback)dll_224_release_nop,
    0,
    (ObjectDescriptorCallback)dll_224_init,
    (ObjectDescriptorCallback)dll_224_update,
    (ObjectDescriptorCallback)dll_224_hitDetect,
    (ObjectDescriptorCallback)dll_224_render,
    (ObjectDescriptorCallback)dll_224_free_nop,
    (ObjectDescriptorCallback)dll_224_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_224_getExtraSize_ret_6,
};
