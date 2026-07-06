/*
 * wmplanets (DLL 0x210) - the orbiting planet models above Krazoa
 * Palace (map 'warlock' = Dinosaur Planet's Warlock Mountain, hence
 * the WM dll prefix). Serves two retail object defs: 899 'WM_Planets'
 * (romlist type 0x561) and 898 'WM_PlanetsS' (type 0x569); no romlist
 * on any of the 124 retail maps places either - instances are spawned
 * at runtime. (The related defs 923 'WM_Planet'/924 'WM_PlanetMo' use
 * DLL 0x12A, not this one.)
 * Each planet circles its spawn point: update spins a (0, 0, radius)
 * arm by the orbit yaw (random per-frame step from init), tilts it by
 * a fixed random pitch, re-bases the model on the result, and turns
 * the model's own yaw at its own random rate. init derives the model
 * scale from the placement scale byte, the orbit radius from the
 * placement radius byte (* 16, negated), and selects the model bank.
 */
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmPlanetsState
{
    s16 orbitYawStep; /* 0x00: orbit advance per frame, random 100..200 */
    s16 yawStep;      /* 0x02: model-spin rate, random 200..400 (timeDelta-scaled) */
    s16 orbitYaw;     /* 0x04: current orbit angle */
    s16 pad06;
    s16 orbitPitch;   /* 0x08: orbit-plane tilt, random 0..2400, fixed at init */
    s16 pad0A;
    f32 orbitRadius;  /* 0x0C: arm length spun around the base point (0 = spin in place) */
    f32 baseX;        /* 0x10: orbit centre = placement position */
    f32 baseY;        /* 0x14 */
    f32 baseZ;        /* 0x18 */
} WmPlanetsState;

/* argument record for vecRotateZXY (angles in, vector in/out) */
typedef struct WmPlanetsRotationWork
{
    s16 yaw;   /* 0x00 */
    s16 pitch; /* 0x02 */
    s16 roll;  /* 0x04 */
    s16 pad06;
    f32 scale; /* 0x08 */
    f32 zeroX; /* 0x0C */
    f32 zeroY; /* 0x10 */
    f32 zeroZ; /* 0x14 */
} WmPlanetsRotationWork;

typedef union WmPlanetsVector
{
    f32 f[3];
    u32 word[3];
} WmPlanetsVector;

typedef struct WmPlanetsMapData
{
    ObjPlacement base;
    s8 scaleByte;   /* 0x18: extra whole-model scale (scale *= 1 + byte) */
    s8 radiusByte;  /* 0x19: orbit radius in 16-unit steps (negated) */
    s16 modelIndex; /* 0x1A: model bank selector (Obj_SetActiveModelIndex) */
} WmPlanetsMapData;

STATIC_ASSERT(offsetof(WmPlanetsState, orbitRadius) == 0x0C);
STATIC_ASSERT(sizeof(WmPlanetsState) == 0x1C);
STATIC_ASSERT(offsetof(WmPlanetsMapData, scaleByte) == 0x18);
STATIC_ASSERT(offsetof(WmPlanetsMapData, radiusByte) == 0x19);
STATIC_ASSERT(offsetof(WmPlanetsMapData, modelIndex) == 0x1A);
STATIC_ASSERT(sizeof(WmPlanetsMapData) == 0x1C);

extern void vecRotateZXY(void* angles, void* outVec);
extern u32 lbl_802C2500[3]; /* (0.0f, 0.0f, 0.0f) */

int wmplanets_getExtraSize(void) { return sizeof(WmPlanetsState); }

int wmplanets_getObjectTypeId(void) { return 0x0; }

void wmplanets_free(void)
{
}

void wmplanets_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    if (vis != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5F98); /* 1.0f */
    }
}

void wmplanets_hitDetect(void)
{
}

void wmplanets_update(int* obj)
{
    WmPlanetsState* state;
    WmPlanetsVector vec;
    WmPlanetsRotationWork rotate;

    state = ((GameObject*)obj)->extra;
    /* whole-struct copy of the zero vector (#31: paired lwz/stw, not
       three lfs/stfs) */
    {
        typedef struct Vec3Words
        {
            int w[3];
        } Vec3Words;
        *(Vec3Words*)&vec.word[0] = *(Vec3Words*)&lbl_802C2500[0];
    }
    vec.f[2] = state->orbitRadius;

    state->orbitYaw += state->orbitYawStep;

    rotate.zeroX = lbl_803E5F9C; /* 0.0f */
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98; /* 1.0f */
    rotate.roll = 0;
    rotate.pitch = 0;
    rotate.yaw = state->orbitYaw;
    vecRotateZXY(&rotate, vec.f);

    rotate.zeroX = lbl_803E5F9C;
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98;
    rotate.roll = 0;
    rotate.pitch = state->orbitPitch;
    rotate.yaw = 0;
    vecRotateZXY(&rotate, vec.f);

    ((GameObject*)obj)->anim.localPosX = vec.f[0] + state->baseX;
    ((GameObject*)obj)->anim.localPosY = vec.f[1] + state->baseY;
    ((GameObject*)obj)->anim.localPosZ = vec.f[2] + state->baseZ;
    ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + state->yawStep * (s32)timeDelta);
}

void wmplanets_init(int* obj, u8* init)
{
    WmPlanetsState* inner = ((GameObject*)obj)->extra;
    f32 a = lbl_803E5FA0 * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase; /* 0.1f * */
    ((GameObject*)obj)->anim.rootMotionScale = a * (lbl_803E5F98 + (f32)(s32)((WmPlanetsMapData*)init)->scaleByte);
    if (*(s16*)init != 0)
    {
        inner->orbitRadius = -(f32)(s32)(((WmPlanetsMapData*)init)->radiusByte << 4);
    }
    else
    {
        inner->orbitRadius = lbl_803E5F9C; /* 0.0f */
    }
    inner->orbitYawStep = randomGetRange(0x64, 0xc8);
    inner->yawStep = randomGetRange(0xc8, 0x190);
    inner->orbitYaw = 0;
    inner->orbitPitch = randomGetRange(0, 0x960);
    inner->baseX = ((GameObject*)obj)->anim.localPosX;
    inner->baseY = ((GameObject*)obj)->anim.localPosY;
    inner->baseZ = ((GameObject*)obj)->anim.localPosZ;
    Obj_SetActiveModelIndex((int)obj, ((WmPlanetsMapData*)init)->modelIndex);
    ((GameObject*)obj)->anim.localPosZ = ((WmPlanetsMapData*)init)->base.posZ + inner->orbitRadius;
}

void wmplanets_release(void)
{
}

void wmplanets_initialise(void)
{
}
