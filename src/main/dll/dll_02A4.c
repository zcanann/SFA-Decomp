/*
 * DLL 0x2A4 - a short-lived spinning debris object plus the two spawn
 * helpers used by the on-rails Arwing flight sections' enemy generator
 * (DLL 0x2A5, arwgenerato).
 *
 * The object itself (init/update/render) seeds random start rotations and
 * random per-axis spin rates, then each frame integrates the rotation,
 * drifts along its anim velocity, and fades out a timer in the first word
 * of its state block; when the timer reaches zero it frees itself.
 *
 * fn_802315EC / fn_802317A8 are the generator's two spawn modes: each
 * allocates an enemy squadron ship (object id 0x616 / 0x617), scatters it
 * around this object's position by the placement's per-axis spread, then
 * loads it and hands it a direction vector and launch speed via the
 * sibling projectile TU.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/ARW/dll_02A2_arwspeedstr.h"
#include "main/object.h"
#include "main/dll/ARW/dll_02A3.h"
#include "main/dll/ARW/dll_02A4.h"
#include "main/dll/ARW/dll_02A5_arwgenerato.h"

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

/* random start-rotation range and per-axis spin-rate range */
#define ROT_RANGE_MAX 0xffff
#define SPIN_RATE_MAG 0x14

int dll_2A4_getExtraSize_ret_12(void)
{
    return sizeof(Dll2A4State);
}

int dll_2A4_getObjectTypeId(void)
{
    return 0x0;
}

void dll_2A4_free_nop(void)
{
}

void dll_2A4_hitDetect_nop(void)
{
}

void dll_2A4_release_nop(void)
{
}

void dll_2A4_initialise_nop(void)
{
}

void dll_2A4_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7138);
}

void dll_2A4_update(GameObject* obj)
{
    Dll2A4State* state = obj->extra;

    if (state->fadeTimer > lbl_803E713C)
    {
        state->fadeTimer -= timeDelta;
        if (state->fadeTimer <= lbl_803E713C)
        {
            state->fadeTimer = lbl_803E713C;
            Obj_FreeObject(obj);
            return;
        }
    }

    obj->anim.rotX = (s16)((f32)state->spinRateX * timeDelta + (f32)obj->anim.rotX);
    obj->anim.rotY = (s16)((f32)state->spinRateY * timeDelta + (f32)obj->anim.rotY);
    obj->anim.rotZ = (s16)((f32)state->spinRateZ * timeDelta + (f32)obj->anim.rotZ);

    objMove((GameObject*)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
            obj->anim.velocityZ * timeDelta);
}

void dll_2A4_init(GameObject* obj)
{
    Dll2A4State* state = obj->extra;

    obj->anim.rotX = randomGetRange(0, ROT_RANGE_MAX);
    obj->anim.rotY = randomGetRange(0, ROT_RANGE_MAX);
    obj->anim.rotZ = randomGetRange(0, ROT_RANGE_MAX);
    state->spinRateX = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
    state->spinRateY = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
    state->spinRateZ = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
}

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
