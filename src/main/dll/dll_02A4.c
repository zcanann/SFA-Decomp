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
#include "main/game_object.h"

/* squadron-ship object ids spawned by the generator's two modes */
#define OBJ_ID_SQUADRON_SHIP_A 0x616
#define OBJ_ID_SQUADRON_SHIP_B 0x617

/* spawned squadron-ship extra block; fields written at +0x4,0x5,0x8,0xc,0x10,0x18..0x1a */
#define SPAWN_EXTRA_SIZE 0x20

/* random start-rotation range and per-axis spin-rate range */
#define ROT_RANGE_MAX 0xffff
#define SPIN_RATE_MAG 0x14

typedef struct Dll2A4State
{
    f32 fadeTimer;      /* 0x00: counts down by timeDelta; frees obj at 0 */
    s16 spinRateX;      /* 0x04 */
    s16 spinRateY;      /* 0x06 */
    s16 spinRateZ;      /* 0x08 */
    u8 padA[0x0C - 0x0A];
} Dll2A4State;

STATIC_ASSERT(sizeof(Dll2A4State) == 0x0c);
STATIC_ASSERT(offsetof(Dll2A4State, spinRateX) == 0x04);
STATIC_ASSERT(offsetof(Dll2A4State, spinRateY) == 0x06);
STATIC_ASSERT(offsetof(Dll2A4State, spinRateZ) == 0x08);

int dll_2A4_getExtraSize_ret_12(void) { return sizeof(Dll2A4State); }

int dll_2A4_getObjectTypeId(void) { return 0x0; }

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
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7138);
}

void dll_2A4_update(int obj)
{
    Dll2A4State* state = ((GameObject*)obj)->extra;

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

    ((GameObject*)obj)->anim.rotX = (s16)((f32)state->spinRateX * timeDelta + (f32) * (s16*)(obj + 0));
    ((GameObject*)obj)->anim.rotY = (s16)((f32)state->spinRateY * timeDelta + (f32) * (s16*)(obj + 2));
    ((GameObject*)obj)->anim.rotZ = (s16)((f32)state->spinRateZ * timeDelta + (f32) * (s16*)(obj + 4));

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
}

void dll_2A4_init(int obj)
{
    Dll2A4State* state = ((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.rotX = randomGetRange(0, ROT_RANGE_MAX);
    ((GameObject*)obj)->anim.rotY = randomGetRange(0, ROT_RANGE_MAX);
    ((GameObject*)obj)->anim.rotZ = randomGetRange(0, ROT_RANGE_MAX);
    state->spinRateX = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
    state->spinRateY = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
    state->spinRateZ = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
}

void fn_802315EC(int obj, ARWGeneratorState* state, ARWGeneratorSetup* setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked())
    {
        newObj = Obj_AllocObjectSetup(SPAWN_EXTRA_SIZE, OBJ_ID_SQUADRON_SHIP_A);
        *(f32*)(newObj + 8) = ((GameObject*)obj)->anim.localPosX + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadX, *(s8*)&setup->spreadX);
        ((GameObject*)newObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosY + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadY, *(s8*)&setup->spreadY);
        ((GameObject*)newObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadZ, *(s8*)&setup->spreadZ);
        *(u8*)(newObj + 0x1a) = 0;
        *(u8*)(newObj + 0x19) = 0;
        *(u8*)(newObj + 0x18) = 0;
        *(u8*)(newObj + 4) = 1;
        *(u8*)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = setup->velocityX / *(f32*)&lbl_803E7140;
        dir[1] = setup->velocityY / *(f32*)&lbl_803E7140;
        dir[2] = setup->velocityZ / *(f32*)&lbl_803E7140;
        fn_8023137C(newObj, dir);
        fn_8023134C(newObj, setup->projectileSpeed);
    }
}

void fn_802317A8(int obj, ARWGeneratorState* state, ARWGeneratorSetup* setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked())
    {
        newObj = Obj_AllocObjectSetup(SPAWN_EXTRA_SIZE, OBJ_ID_SQUADRON_SHIP_B);
        *(f32*)(newObj + 8) = ((GameObject*)obj)->anim.localPosX + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadX, *(s8*)&setup->spreadX);
        ((GameObject*)newObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosY + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadY, *(s8*)&setup->spreadY);
        ((GameObject*)newObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadZ, *(s8*)&setup->spreadZ);
        *(u8*)(newObj + 0x1a) = 0;
        *(u8*)(newObj + 0x19) = 0;
        *(u8*)(newObj + 0x18) = 0;
        *(u8*)(newObj + 4) = 1;
        *(u8*)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = setup->velocityX / *(f32*)&lbl_803E7140;
        dir[1] = setup->velocityY / *(f32*)&lbl_803E7140;
        dir[2] = setup->velocityZ / *(f32*)&lbl_803E7140;
        fn_80231058(newObj, (int)dir);
        fn_80231028(newObj, setup->projectileSpeed);
    }
}
