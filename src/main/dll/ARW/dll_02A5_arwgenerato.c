/*
 * arwgenerato (DLL 0x2A5) - spawner used in the on-rails Arwing flight
 * sections. It holds a single countdown timer (state->spawnTimer, seeded
 * from the placement's spawnInterval) and, when the timer elapses, calls
 * one of two spawn helpers selected by the placement's spawnMode before
 * re-arming the timer.
 *
 * fn_802315EC / fn_802317A8 are the two spawn modes: each allocates an
 * enemy squadron ship (object id 0x616 / 0x617), scatters it around this
 * object's position by the placement's per-axis spread, then loads it and
 * hands it a direction vector and launch speed via the sibling projectile
 * TUs.
 */
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/dll/ARW/dll_02A2_arwspeedstr.h"
#include "main/object.h"
#include "main/dll/ARW/dll_02A3.h"
#include "main/dll/ARW/dll_02A4.h"
#include "main/dll/ARW/dll_02A5_arwgenerato.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/object_render_legacy.h"

/* Spawn-setup buffer for a squadron ship: ObjPlacement head (pos/color) plus
 * the class-specific rotation bytes the parent seeds (all 0) at +0x18. */
typedef struct SquadronShipSetup
{
    ObjPlacement head; /* 0x00: pos/color/mapId */
    u8 rot18;          /* 0x18 */
    u8 rot19;          /* 0x19 */
    u8 rot1A;          /* 0x1a */
} SquadronShipSetup;

/* squadron-ship object ids spawned by the generator's two modes */
#define OBJ_ID_SQUADRON_SHIP_A 0x616
#define OBJ_ID_SQUADRON_SHIP_B 0x617

/* spawned squadron-ship extra block; fields written at +0x4,0x5,0x8,0xc,0x10,0x18..0x1a */
#define SPAWN_EXTRA_SIZE 0x20

#pragma dont_inline on
void fn_802315EC(GameObject* obj, ARWGeneratorState* state, ARWGeneratorSetup* setup)
{
    SquadronShipSetup* newObj;
    Dll2A3Velocity dir;

    if (Obj_IsLoadingLocked())
    {
        newObj = (SquadronShipSetup*)Obj_AllocObjectSetup(SPAWN_EXTRA_SIZE, OBJ_ID_SQUADRON_SHIP_A);
        newObj->head.posX =
            obj->anim.localPosX +
            (f32)(int)randomGetRange(-*(s8*)&setup->spreadX, *(s8*)&setup->spreadX);
        newObj->head.posY =
            obj->anim.localPosY +
            (f32)(int)randomGetRange(-*(s8*)&setup->spreadY, *(s8*)&setup->spreadY);
        newObj->head.posZ =
            obj->anim.localPosZ +
            (f32)(int)randomGetRange(-*(s8*)&setup->spreadZ, *(s8*)&setup->spreadZ);
        newObj->rot1A = 0;
        newObj->rot19 = 0;
        newObj->rot18 = 0;
        newObj->head.color[0] = 1;
        newObj->head.color[1] = 1;
        newObj = (SquadronShipSetup*)loadObjectAtObject(obj, &newObj->head);
        dir.x = setup->velocityX / *(f32*)&lbl_803E7140;
        dir.y = setup->velocityY / *(f32*)&lbl_803E7140;
        dir.z = setup->velocityZ / *(f32*)&lbl_803E7140;
        fn_8023137C((GameObject*)(newObj), &dir);
        fn_8023134C((GameObject*)(newObj), setup->projectileSpeed);
    }
}

void fn_802317A8(GameObject* obj, ARWGeneratorState* state, ARWGeneratorSetup* setup)
{
    SquadronShipSetup* newObj;
    ARWSpeedStrVelocity dir;

    if (Obj_IsLoadingLocked())
    {
        newObj = (SquadronShipSetup*)Obj_AllocObjectSetup(SPAWN_EXTRA_SIZE, OBJ_ID_SQUADRON_SHIP_B);
        newObj->head.posX =
            obj->anim.localPosX +
            (f32)(int)randomGetRange(-*(s8*)&setup->spreadX, *(s8*)&setup->spreadX);
        newObj->head.posY =
            obj->anim.localPosY +
            (f32)(int)randomGetRange(-*(s8*)&setup->spreadY, *(s8*)&setup->spreadY);
        newObj->head.posZ =
            obj->anim.localPosZ +
            (f32)(int)randomGetRange(-*(s8*)&setup->spreadZ, *(s8*)&setup->spreadZ);
        newObj->rot1A = 0;
        newObj->rot19 = 0;
        newObj->rot18 = 0;
        newObj->head.color[0] = 1;
        newObj->head.color[1] = 1;
        newObj = (SquadronShipSetup*)loadObjectAtObject(obj, &newObj->head);
        dir.x = setup->velocityX / *(f32*)&lbl_803E7140;
        dir.y = setup->velocityY / *(f32*)&lbl_803E7140;
        dir.z = setup->velocityZ / *(f32*)&lbl_803E7140;
        fn_80231058((GameObject*)(newObj), &dir);
        fn_80231028((GameObject*)(newObj), setup->projectileSpeed);
    }
}
#pragma dont_inline reset

__declspec(section ".sdata2") f32 lbl_803E7150 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E7154 = 0.0f;
#pragma explicit_zero_data reset

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

ObjectDescriptor gARWGeneratoObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)arwgenerato_initialise, (ObjectDescriptorCallback)arwgenerato_release, 0,
    (ObjectDescriptorCallback)arwgenerato_init, (ObjectDescriptorCallback)arwgenerato_update,
    (ObjectDescriptorCallback)arwgenerato_hitDetect, (ObjectDescriptorCallback)arwgenerato_render,
    (ObjectDescriptorCallback)arwgenerato_free, (ObjectDescriptorCallback)arwgenerato_getObjectTypeId,
    arwgenerato_getExtraSize,
};
