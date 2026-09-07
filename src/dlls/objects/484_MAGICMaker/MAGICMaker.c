/*
 * MAGICMaker (DLL 0x1E4) - collectible spawner.
 * A game-bit trigger makes the object count group members against its spawn
 * table, create a collectible near itself when below the match limit, and emit
 * three hit-effect bursts from the new object.
 */
#include "dlls/objects/484_MAGICMaker.h"

#include "dlls/objects/255.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/gamebits_api.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "dlls/objects/237.h"

#define MAGICMAKER_SPAWN_GAMEBIT             0x26B
#define MAGICMAKER_MATCH_COUNT_LIMIT         10
#define MAGICMAKER_SPAWN_RADIUS              350
#define MAGICMAKER_HIT_BURST_COUNT           3
#define MAGICMAKER_CHILD_SETUP_FLAGS         5
#define MAGICMAKER_CHILD_OBJECT_INDEX        -1
#define MAGICMAKER_GAMEBIT_NONE              -1
#define MAGICMAKER_COLLECTIBLE_SPAWN_MODE    3
#define MAGICMAKER_HIT_EFFECT_ID             2
#define MAGICMAKER_HIT_EFFECT_VARIANT        2
#define MAGICMAKER_HIT_EFFECT_PARTICLE_COUNT 0x64

u16 gMagicMakerSpawnObjectIds[MAGICMAKER_SPAWN_OBJECT_COUNT] = {
    MAGICGEM_DEF_GREEN,          /* green magic gem */
    MAGICGEM_DEF_RED,            /* red magic gem */
    MAGICGEM_DEF_YELLOW,         /* yellow magic gem */
    MAGICGEM_DEF_BLUE,           /* blue magic gem */
    COLLECTIBLE_ITEM_ENERGY_EGG, /* energy egg */
    COLLECTIBLE_ITEM_ENERGY_EGG, /* duplicate weighting */
};

int magicmaker_getExtraSize(void) {
    return 0;
}

int magicmaker_getObjectTypeId(void) {
    return 0;
}

void magicmaker_free(void) {
}

void magicmaker_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void magicmaker_hitDetect(void) {
}

void magicmaker_update(GameObject* obj) {
    ObjPlacement* placement;
    GameObject* spawnedObject;
    int matchingEntryCount;
    int groupObjectCount;
    GameObject** groupObjects;
    int i;
    int spawnObjectIndex;
    CollectibleSetup* spawnSetup;
    GameObject* groupObject;

    placement = (ObjPlacement*)obj->anim.placementData;
    if ((u8)Obj_CanSetupObject() != 0) {
        if (mainGetBit(MAGICMAKER_SPAWN_GAMEBIT) != 0u) {
            mainSetBits(MAGICMAKER_SPAWN_GAMEBIT, 0);
            groupObjects = objGetAllOfType(COLLECTIBLE_OBJECT_GROUP, &groupObjectCount);
            matchingEntryCount = 0;
            for (i = 0; i < groupObjectCount; i++) {
                groupObject = groupObjects[i];
                for (spawnObjectIndex = 0; spawnObjectIndex < MAGICMAKER_SPAWN_OBJECT_COUNT; spawnObjectIndex++) {
                    if (groupObject->anim.romDefNo == gMagicMakerSpawnObjectIds[spawnObjectIndex]) {
                        matchingEntryCount++;
                    }
                }
            }
            if (matchingEntryCount < MAGICMAKER_MATCH_COUNT_LIMIT) {
                spawnSetup = (CollectibleSetup*)Obj_AllocObjectSetup(
                    sizeof(CollectibleSetup),
                    gMagicMakerSpawnObjectIds[randomGetRange(0, MAGICMAKER_SPAWN_OBJECT_COUNT - 1)]);
                if (spawnSetup != NULL) {
                    spawnSetup->unk1A = 0x14;
                    spawnSetup->counterGameBit = MAGICMAKER_GAMEBIT_NONE;
                    spawnSetup->hideGameBit = MAGICMAKER_GAMEBIT_NONE;
                    spawnSetup->base.posX =
                        obj->anim.localPosX + randomGetRange(-MAGICMAKER_SPAWN_RADIUS, MAGICMAKER_SPAWN_RADIUS);
                    spawnSetup->base.posY = 10.0f + obj->anim.localPosY;
                    spawnSetup->base.posZ =
                        obj->anim.localPosZ + randomGetRange(-MAGICMAKER_SPAWN_RADIUS, MAGICMAKER_SPAWN_RADIUS);
                    spawnSetup->visibilityGameBit = MAGICMAKER_GAMEBIT_NONE;
                    spawnSetup->base.color[0] = placement->color[0];
                    spawnSetup->base.color[2] = placement->color[2];
                    spawnSetup->base.color[1] = placement->color[1];
                    spawnSetup->base.color[3] = placement->color[3];
                    spawnSetup->spawnMode = MAGICMAKER_COLLECTIBLE_SPAWN_MODE;
                    spawnedObject =
                        objSetupObject(&spawnSetup->base, MAGICMAKER_CHILD_SETUP_FLAGS, obj->anim.mapEventSlot,
                                       MAGICMAKER_CHILD_OBJECT_INDEX, obj->anim.parent);
                    if (spawnedObject != NULL) {
                        i = MAGICMAKER_HIT_BURST_COUNT;
                        do {
                            objfx_spawnHitEffectBurst(spawnedObject, 1.0f, MAGICMAKER_HIT_EFFECT_ID,
                                                      MAGICMAKER_HIT_EFFECT_VARIANT,
                                                      MAGICMAKER_HIT_EFFECT_PARTICLE_COUNT, NULL);
                            i--;
                        } while (i != 0);
                    }
                }
            }
        }
    }
}

void magicmaker_init(void) {
}

void magicmaker_release(void) {
}

void magicmaker_initialise(void) {
}

ObjectDescriptor10WithPadding gMAGICMakerObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        magicmaker_initialise,
        magicmaker_release,
        0,
        magicmaker_init,
        (ObjectDescriptorCallback)magicmaker_update,
        magicmaker_hitDetect,
        (ObjectDescriptorCallback)magicmaker_render,
        magicmaker_free,
        (ObjectDescriptorCallback)magicmaker_getObjectTypeId,
        magicmaker_getExtraSize,
    },
    0,
};
