#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define SOFTBODY_OBJECT_FLAGS_INIT 0x2000
#define SOFTBODY_MOVE_PHASE_A_FIRST 0x6af
#define SOFTBODY_MOVE_PHASE_A_END 0x6b2

typedef struct SoftBodySetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 pad1C[3];
    u8 phaseDriverDisabled;
} SoftBodySetup;

STATIC_ASSERT(offsetof(SoftBodySetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(SoftBodySetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(SoftBodySetup, phaseDriverDisabled) == 0x1f);
STATIC_ASSERT(sizeof(SoftBodySetup) == 0x20);

int softbody_getExtraSize(void) { return 0; }

int softbody_getObjectTypeId(void) { return 0; }

void softbody_free(int obj)
{
    if ((void*)obj == lbl_803DDD98)
    {
        lbl_803DDD98 = NULL;
    }
}

void softbody_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7288);
    }
}

void softbody_hitDetect(void)
{
}

void softbody_init(int obj, int setup)
{
    GameObject* object = (GameObject*)obj;
    SoftBodySetup* setupData = (SoftBodySetup*)setup;

    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    if (setupData->scale != 0)
    {
        object->anim.rootMotionScale = (f32)(u32)
        setupData->scale / lbl_803E7294;
        if (object->anim.rootMotionScale == lbl_803E7298)
        {
            object->anim.rootMotionScale = lbl_803E7288;
        }
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags |= SOFTBODY_OBJECT_FLAGS_INIT;
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E7298, 0);
    if (object->anim.hitReactState != NULL)
    {
        ObjHitbox_SetSphereRadius(obj,
                                  (s16)((f32)((ObjHitsPriorityState*)object->anim.hitReactState)->primaryRadius * object->anim.rootMotionScale));
    }
}

void softbody_release(void)
{
}

void softbody_initialise(void)
{
    lbl_803DDD98 = NULL;
    lbl_803DDDA0 = lbl_803E7298;
    lbl_803DDD9C = lbl_803E7298;
}

#pragma opt_common_subs off
void softbody_update(int obj)
{
    GameObject* object = (GameObject*)obj;
    SoftBodySetup* setup = (SoftBodySetup*)object->anim.placementData;

    if (lbl_803DDD98 == NULL && setup->phaseDriverDisabled == 0)
    {
        lbl_803DDD98 = (void*)obj;
    }

    if ((void*)obj == lbl_803DDD98)
    {
        f32 td = timeDelta;
        lbl_803DDDA0 = lbl_803E728C * td + lbl_803DDDA0;
        while (lbl_803DDDA0 > lbl_803E7288)
        {
            lbl_803DDDA0 -= lbl_803E7288;
        }
        lbl_803DDD9C = lbl_803E7290 * td + lbl_803DDD9C;  /* CSE timeDelta */
        while (lbl_803DDD9C > lbl_803E7288)
        {
            lbl_803DDD9C -= lbl_803E7288;
        }
    }

    ObjAnim_SetCurrentMove(obj, 0,
        (object->anim.seqId < SOFTBODY_MOVE_PHASE_A_END &&
         object->anim.seqId >= SOFTBODY_MOVE_PHASE_A_FIRST) ? lbl_803DDDA0 : lbl_803DDD9C, 0);
}
#pragma opt_common_subs reset
