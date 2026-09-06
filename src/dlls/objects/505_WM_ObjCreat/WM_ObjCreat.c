/*
 * WM_ObjCreat (DLL 0x1F9) - the ambient-object spawner at Krazoa
 * Palace (map 'warlock').
 *
 * Each placed instance runs one spawnMode: a one-shot WM_Galleon or
 * HoodedZyck, periodic LFXEmitter ambience (drifting leaves/petals in
 * several configurations), the cut WM_WallCraw enemy, or a falling
 * WM_rock with a debris-particle burst. Periodic modes rearm
 * spawnTimer from spawnPeriod + randomGetRange(0, spawnJitter); most
 * modes gate on the placement game bit (-1 = always).
 */
#include "dlls/objects/505_WM_ObjCreat.h"

#include "dlls/objects/301_LFXEmitter.h"
#include "dlls/objects/504_WM_Galleon.h"

#include "game/objects/object.h"
#include "dlls/objects/529.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

/*
 * These setup records model the complete allocation widths used below. Field
 * meanings belong to the spawned objects; unrecovered fields remain opaque.
 */
typedef struct WMRockSpawnSetup {
    ObjPlacement base;
    s8 yawByte;
    u8 unknown19[5];
    s16 unknown1E;
    u8 unknown20[4];
} WMRockSpawnSetup;

STATIC_ASSERT(offsetof(WMRockSpawnSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMRockSpawnSetup, unknown1E) == 0x1E);
STATIC_ASSERT(sizeof(WMRockSpawnSetup) == 0x24);

typedef struct HoodedZyckSpawnSetup {
    ObjPlacement base;
    s16 triggerGameBit;
    s16 unknown1A;
    u8 unknown1C[6];
    s16 droppedItemId;
    u8 unknown24[6];
    s8 yawByte;
    u8 unknown2B[0x38 - 0x2B];
} HoodedZyckSpawnSetup;

STATIC_ASSERT(offsetof(HoodedZyckSpawnSetup, triggerGameBit) == 0x18);
STATIC_ASSERT(offsetof(HoodedZyckSpawnSetup, unknown1A) == 0x1A);
STATIC_ASSERT(offsetof(HoodedZyckSpawnSetup, droppedItemId) == 0x22);
STATIC_ASSERT(offsetof(HoodedZyckSpawnSetup, yawByte) == 0x2A);
STATIC_ASSERT(sizeof(HoodedZyckSpawnSetup) == 0x38);

enum {
    /* Creator modes selected by the placement record. */
    WMOBJCREATOR_MODE_GALLEON = 0,
    WMOBJCREATOR_MODE_EAST_EMITTER = 1,
    WMOBJCREATOR_MODE_WEST_EMITTER = 2,
    WMOBJCREATOR_MODE_SCATTER_EMITTERS = 4,
    WMOBJCREATOR_MODE_WALL_CRAWLER = 5,
    WMOBJCREATOR_MODE_FALLING_ROCK = 6,
    WMOBJCREATOR_MODE_RANDOM_EMITTER = 7,
    WMOBJCREATOR_MODE_HOODED_ZYCK = 8,

    /* Spawned object IDs from retail OBJECTS.bin. */
    WMOBJCREATOR_SPAWN_LFX_EMITTER = 0x263,
    WMOBJCREATOR_SPAWN_WM_WALLCRAWLER = 0x275,
    WMOBJCREATOR_SPAWN_HOODED_ZYCK = 0x4AC,
    WMOBJCREATOR_SPAWN_WM_ROCK = 0x2BC
};

/* Particle effects emitted by the one-shot spawn modes. */
#define WMOBJCREATOR_PARTFX_DEBRIS            0x1A6
#define WMOBJCREATOR_PARTFX_SCATTER_TRAIL     0x1A7
#define WMOBJCREATOR_PARTFX_HOODED_ZYCK_SPAWN 0x1C3

s32 gWMObjCreatorWallCrawlerSpawnCount;

/* Retail data order places this descriptor before WM_ObjCreator_update's jump table. */
ObjectDescriptor gWM_ObjCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    WM_ObjCreator_initialise,
    WM_ObjCreator_release,
    0,
    (ObjectDescriptorCallback)WM_ObjCreator_init,
    (ObjectDescriptorCallback)WM_ObjCreator_update,
    WM_ObjCreator_hitDetect,
    (ObjectDescriptorCallback)WM_ObjCreator_render,
    WM_ObjCreator_free,
    (ObjectDescriptorCallback)WM_ObjCreator_getObjectTypeId,
    WM_ObjCreator_getExtraSize,
};

int WM_ObjCreator_getExtraSize(void) {
    return sizeof(WMObjCreatorState);
}

int WM_ObjCreator_getObjectTypeId(void) {
    return 0;
}

void WM_ObjCreator_free(void) {
}

void WM_ObjCreator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void WM_ObjCreator_hitDetect(void) {
}

void WM_ObjCreator_update(GameObject* obj) {
    ObjPlacement* setup;
    GameObject* spawned;
    int remainingCount;
    WMObjCreatorPlacementView* placement;
    WMObjCreatorState* state;
    int objectCount;
    PartFxSpawnParams particleArgs;

    placement = (WMObjCreatorPlacementView*)obj->anim.placementData;
    state = obj->extra;
    if ((u8)Obj_CanSetupObject() != 0) {
        switch (placement->spawnMode) {
        /* Spawn one WM_Galleon at the placement, unless one is already alive. */
        case WMOBJCREATOR_MODE_GALLEON: {
            GameObject** groupObjects;
            int objectIndex;
            state = NULL;
            if (obj->userData2 == 0) {
                state = (WMObjCreatorState*)1;
                if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0) {
                    state = NULL;
                }
                groupObjects = objGetAllOfType(3, &objectCount);
                for (objectIndex = 0; objectIndex < objectCount && (s8)(int)state != 0; objectIndex++) {
                    if (groupObjects[objectIndex]->anim.romDefNo == WM_GALLEON_OBJECT_ID) {
                        state = NULL;
                    }
                }
            }
            if ((s8)(int)state != 0) {
                setup = Obj_AllocObjectSetup(sizeof(WMGalleonSetup), WM_GALLEON_OBJECT_ID);
                setup->posX = placement->base.posX;
                setup->posY = placement->base.posY;
                setup->posZ = placement->base.posZ;
                setup->color[0] = placement->base.color[0];
                setup->color[1] = placement->base.color[1];
                setup->color[2] = placement->base.color[2];
                setup->color[3] = placement->base.color[3];
                ((WMGalleonSetup*)setup)->unknown1E = -1;
                ((WMGalleonSetup*)setup)->unknown1A = 2;
                ((WMGalleonSetup*)setup)->rotationXByte = placement->yaw;
                spawned = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                if (spawned != NULL) {
                    spawned->userData1 = 8;
                }
                obj->userData2 = 1;
            }
            break;
        }
        case WMOBJCREATOR_MODE_EAST_EMITTER:
            if ((mainGetBit(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0)) {
                ObjPlacement* setup = Obj_AllocObjectSetup(sizeof(LFXEmitterPlacement), WMOBJCREATOR_SPAWN_LFX_EMITTER);
                setup->color[0] = 0x20;
                setup->color[1] = 2;
                setup->color[3] = 0xff;
                setup->posX = obj->anim.localPosX;
                setup->posY = obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ;
                ((LFXEmitterPlacement*)setup)->lifeTimer = 0x50;
                ((LFXEmitterPlacement*)setup)->actionIndex = 0x10f;
                ((LFXEmitterPlacement*)setup)->enableGameBit = 0xffff;
                ((LFXEmitterPlacement*)setup)->spinRoll = randomGetRange(-500, 500) + 0x5dc;
                ((LFXEmitterPlacement*)setup)->spinPitch = 0;
                ((LFXEmitterPlacement*)setup)->spinYaw = randomGetRange(-500, 500) + 0x5dc;
                spawned = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                if (spawned != NULL) {
                    spawned->anim.velocityX = 10.0f + randomGetRange(0, 10);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case WMOBJCREATOR_MODE_WALL_CRAWLER:
            if ((mainGetBit(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0)) {
                setup = Obj_AllocObjectSetup(sizeof(WMWallCrawlerSpawnSetup), WMOBJCREATOR_SPAWN_WM_WALLCRAWLER);
                ((WMWallCrawlerSpawnSetup*)setup)->base.rotXByte = randomGetRange(-0x7f, 0x7e);
                setup->posX = obj->anim.localPosX + randomGetRange(-100, 100);
                setup->posY = obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ + randomGetRange(-100, 100);
                ((WMWallCrawlerSpawnSetup*)setup)->base.triggerRadius = 0x31;
                ((WMWallCrawlerSpawnSetup*)setup)->base.heightOffset = 200;
                spawned = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                if (spawned != NULL) {
                    gWMObjCreatorWallCrawlerSpawnCount += 1;
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case WMOBJCREATOR_MODE_HOODED_ZYCK:
            if ((mainGetBit(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0)) {
                setup = Obj_AllocObjectSetup(sizeof(HoodedZyckSpawnSetup), WMOBJCREATOR_SPAWN_HOODED_ZYCK);
                mainSetBits(state->gameBit, 0);
                ((HoodedZyckSpawnSetup*)setup)->yawByte = randomGetRange(-0x7f, 0x7e);
                setup->posX = obj->anim.localPosX;
                setup->posY = obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ;
                ((HoodedZyckSpawnSetup*)setup)->triggerGameBit = state->gameBit;
                ((HoodedZyckSpawnSetup*)setup)->droppedItemId = 1;
                spawned = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                if (spawned != NULL) {
                    (*gPartfxInterface)->spawnObject(obj, WMOBJCREATOR_PARTFX_HOODED_ZYCK_SPAWN, NULL, 2, -1, NULL);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case WMOBJCREATOR_MODE_WEST_EMITTER:
            if ((mainGetBit(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0)) {
                setup = Obj_AllocObjectSetup(sizeof(LFXEmitterPlacement), WMOBJCREATOR_SPAWN_LFX_EMITTER);
                setup->color[0] = 4;
                setup->color[1] = 2;
                setup->posX = placement->base.posX;
                setup->posY = placement->base.posY + randomGetRange(-0x28, 0x28);
                setup->posZ = placement->base.posZ + randomGetRange(-0x28, 0x28);
                ((LFXEmitterPlacement*)setup)->lifeTimer = 100;
                ((LFXEmitterPlacement*)setup)->actionIndex = 0x10f;
                ((LFXEmitterPlacement*)setup)->enableGameBit = 0xffff;
                ((LFXEmitterPlacement*)setup)->spinRoll = randomGetRange(-500, 500) + 0x5dc;
                ((LFXEmitterPlacement*)setup)->spinYaw = randomGetRange(-500, 500) + 0x5dc;
                spawned = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                if (spawned != NULL) {
                    spawned->anim.velocityX = -30.0f - randomGetRange(0, 10);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case WMOBJCREATOR_MODE_SCATTER_EMITTERS:
            if (mainGetBit(state->gameBit) != 0 || state->gameBit == -1) {
                remainingCount = 2;
                do {
                    ObjPlacement* setup;
                    remainingCount--;
                    setup = Obj_AllocObjectSetup(sizeof(LFXEmitterPlacement), WMOBJCREATOR_SPAWN_LFX_EMITTER);
                    setup->color[0] = 0x20;
                    setup->color[1] = 2;
                    setup->color[3] = 0xff;
                    setup->posX = obj->anim.localPosX;
                    setup->posY = obj->anim.localPosY;
                    setup->posZ = obj->anim.localPosZ;
                    ((LFXEmitterPlacement*)setup)->lifeTimer = 400;
                    ((LFXEmitterPlacement*)setup)->actionIndex = 0xf;
                    ((LFXEmitterPlacement*)setup)->enableGameBit = 0x222;
                    ((LFXEmitterPlacement*)setup)->spinRoll = 0;
                    ((LFXEmitterPlacement*)setup)->spinPitch = 0;
                    ((LFXEmitterPlacement*)setup)->spinYaw = 0;
                    ((LFXEmitterPlacement*)setup)->followCurve = 0;
                    spawned = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                    if (spawned != NULL) {
                        ((LFXEmitterState*)spawned->extra)->flags |= LFXEMITTER_FLAG_DAMP_Y_VELOCITY;
                        spawned->anim.velocityX = 0.1f * randomGetRange(-0x23, 0x23);
                        spawned->anim.velocityZ = 0.1f * randomGetRange(-0x23, 0x23);
                        spawned->anim.velocityY = 0.0f;
                        particleArgs.scale = 1.0f;
                        particleArgs.rotX = 0;
                        particleArgs.rotY = 0;
                        particleArgs.rotZ = 0;
                        particleArgs.posX = spawned->anim.velocityX;
                        particleArgs.posZ = spawned->anim.velocityZ;
                        particleArgs.posY = 0.0f;
                        (*gPartfxInterface)
                            ->spawnObject(spawned, WMOBJCREATOR_PARTFX_SCATTER_TRAIL, &particleArgs, 0x10000, -1, NULL);
                    }
                } while (remainingCount != 0);
                mainSetBits(state->gameBit, 0);
            }
            break;
        case WMOBJCREATOR_MODE_RANDOM_EMITTER:
            if ((mainGetBit(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0)) {
                setup = Obj_AllocObjectSetup(sizeof(LFXEmitterPlacement), WMOBJCREATOR_SPAWN_LFX_EMITTER);
                setup->color[0] = 4;
                setup->color[1] = 2;
                setup->posX = placement->base.posX + randomGetRange(-0x28, 0x28);
                setup->posY = placement->base.posY + randomGetRange(0, 0x14);
                setup->posZ = placement->base.posZ + randomGetRange(-0x28, 0x28);
                ((LFXEmitterPlacement*)setup)->lifeTimer = 0x1c2;
                ((LFXEmitterPlacement*)setup)->actionIndex = randomGetRange(0, 2) + 0x1cc;
                ((LFXEmitterPlacement*)setup)->enableGameBit = 0xffff;
                ((LFXEmitterPlacement*)setup)->spinRoll = randomGetRange(-500, 500) + 0x5dc;
                ((LFXEmitterPlacement*)setup)->spinYaw = randomGetRange(-500, 500) + 0x5dc;
                objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case WMOBJCREATOR_MODE_FALLING_ROCK:
            if (mainGetBit(state->gameBit) != 0 || state->gameBit == -1) {
                setup = Obj_AllocObjectSetup(sizeof(WMRockSpawnSetup), WMOBJCREATOR_SPAWN_WM_ROCK);
                setup->posX = obj->anim.localPosX + randomGetRange(-0x104, 0x104);
                setup->posY = 200.0f + obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ + randomGetRange(-0x50, 0x50);
                setup->color[0] = 0x20;
                setup->color[1] = 2;
                setup->color[3] = 0xff;
                ((WMRockSpawnSetup*)setup)->unknown1E = 0xffff;
                ((WMRockSpawnSetup*)setup)->yawByte = obj->anim.rotX >> 8;
                objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                for (remainingCount = randomGetRange(2, 5); remainingCount != 0; remainingCount--) {
                    particleArgs.scale = 1.0f;
                    particleArgs.rotX = 0;
                    particleArgs.rotY = 0;
                    particleArgs.rotZ = 0;
                    particleArgs.posX = randomGetRange(-200, 200);
                    particleArgs.posZ = randomGetRange(-0x14, 0x14);
                    particleArgs.posY = 200.0f;
                    (*gPartfxInterface)->spawnObject(obj, WMOBJCREATOR_PARTFX_DEBRIS, &particleArgs, 0x10002, -1, NULL);
                }
                mainSetBits(state->gameBit, 0);
            }
            break;
        }
    }
}

void WM_ObjCreator_init(GameObject* obj, const WMObjCreatorPlacementView* placement) {
    WMObjCreatorState* state = obj->extra;

    obj->anim.rotX = placement->yaw << 8;
    state->gameBit = placement->gameBit;
    state->spawnPeriod = placement->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->spawnJitter = placement->spawnJitter;
}

void WM_ObjCreator_release(void) {
}

void WM_ObjCreator_initialise(void) {
}
