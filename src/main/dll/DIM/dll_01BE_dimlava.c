/*
 * dimlava (DLL 0x1BE) - DIM lava-ball objects; the 0x1BE variant handles
 * both a small debris particle (seqId 0x1FA) and a full physics lava-ball
 * that homes on a target, glows, and triggers explosions on contact.
 */

#define LAVA1BE_SEQID_DEBRIS 0x1fa
#define LAVA1BE_PARTFX       0x1f5

#define LAVA1BE_FLAG_HOMING_OFF 0x08
#define LAVA1BE_FLAG_INACTIVE   0x10
#define LAVA1BE_FLAG_FALLING    0x20
#include "main/dll/partfx_interface.h"
#include "main/rcp_dolphin_api.h"
#include "main/object_api.h"
#include "main/modellight_api.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/objseq.h"
#include "main/object_render_legacy.h"
#include "main/objhits.h"
#include "main/dll/IM/dll_016D_imicepillar.h"

#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/objfx.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

#define DIMLAVA_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MODEL_LIGHT_KIND_POINT             2

typedef struct Lavaball1bePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 linkedId;   /* 0x14: linked-object id, consumed and cleared (-1) at init */
    s8 spawnRotX;   /* 0x18: spawn yaw byte, placed in anim.rotX high byte */
    u8 pad19;       /* 0x19 */
    s16 velScaleY;  /* 0x1A: vertical launch-velocity scale */
    s16 velScaleXZ; /* 0x1C: horizontal launch-velocity scale */
    u8 pad1E[0x20 - 0x1E];
} Lavaball1bePlacement;

STATIC_ASSERT(offsetof(Lavaball1bePlacement, linkedId) == 0x14);
STATIC_ASSERT(offsetof(Lavaball1bePlacement, spawnRotX) == 0x18);
STATIC_ASSERT(offsetof(Lavaball1bePlacement, velScaleY) == 0x1a);
STATIC_ASSERT(offsetof(Lavaball1bePlacement, velScaleXZ) == 0x1c);
STATIC_ASSERT(sizeof(Lavaball1bePlacement) == 0x20);

typedef struct
{
    f32 x, y, z;
} LavaVec;

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

extern f32 lbl_803E47F0;
extern f32 gDimLavaDebrisGravity, gDimLavaGravity, lbl_803E47F8, lbl_803E47FC;
extern f32 gDimLavaDebrisRootMotionScale, gDimLavaVelocityScale, gDimLavaPi, gDimLavaAngleUnitsHalfCircle;
extern f32 gDimLavaLightAttenNear, gDimLavaLightAttenFar, gDimLavaGlowRadius;
__declspec(section ".rodata") u8 gDimLavaDebrisBaseVec[16] = {
    0x3F, 0x99, 0x99, 0x9A, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


static inline int* DIMcannon_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

void lavaball1be_hitDetect(void)
{
}

void lavaball1be_release(void)
{
}

void lavaball1be_initialise(void)
{
}

int lavaball1be_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS)
        return 0x0;
    return 0x14;
}

int lavaball1be_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS)
        return 0x0;
    return 0x2;
}

u32 lavaball1be_isInactive(int* obj)
{
    return *((u8*)(int*)((GameObject*)obj)->extra + 0x10) & LAVA1BE_FLAG_INACTIVE;
}

void lavaball1be_free(GameObject* obj)
{
    Lavaball1beState* inner = obj->extra;
    if (inner->light != 0)
    {
        ModelLightStruct_free(inner->light);
        inner->light = 0;
    }
}

void lavaball1be_render(int* obj, int p2, int p3, int p4, int p5)
{
    Lavaball1beState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        if (modelLightStruct_getActiveState(state->light) != 0)
        {
            queueGlowRender(state->light);
        }
    }
    ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E47F0);
}

void lavaball1be_init(s16* obj, u8* p)
{
    Lavaball1beState* state;
    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS)
    {
        struct
        {
            LavaVec vec;
            s16 rot[3];
            u8 pad[18];
        } s;
        s.vec = *(LavaVec*)gDimLavaDebrisBaseVec;
        s.rot[2] = 0;
        s.rot[1] = randomGetRange(-0x2ee0, 0x2ee0);
        s.rot[0] = randomGetRange(0, 0xfffe);
        vecRotateZXY((s16*)((u8*)&s + 12), (f32*)&s.vec);
        ((GameObject*)obj)->unkF4 = 0x4b;
        ((GameObject*)obj)->anim.velocityX = s.vec.x;
        ((GameObject*)obj)->anim.velocityY = s.vec.y;
        ((GameObject*)obj)->anim.velocityZ = s.vec.z;
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * gDimLavaDebrisRootMotionScale;
    }
    else
    {
        f32 vy;
        f32 vxz;
        int* sub;
        ModelLightStruct* light;
        Lavaball1bePlacement* placement = (Lavaball1bePlacement*)p;

        ((GameObject*)obj)->anim.rotX = (s16)((s32)placement->spawnRotX << 8);
        state = ((GameObject*)obj)->extra;
        vy = gDimLavaVelocityScale * (f32)placement->velScaleY;
        vxz = gDimLavaVelocityScale * (f32)placement->velScaleXZ;
        state->floorY = ((GameObject*)obj)->anim.localPosY;
        state->linkedId = placement->linkedId;
        placement->linkedId = -1;
        ((GameObject*)obj)->anim.velocityX =
            vxz * -mathSinf(gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
        ((GameObject*)obj)->anim.velocityY = vy;
        ((GameObject*)obj)->anim.velocityZ =
            vxz * -mathCosf(gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
        sub = *(int**)&((GameObject*)obj)->anim.hitReactState;
        if (sub != NULL)
        {
            *((u8*)sub + 0x6a) = 0;
        }
        sub = (int*)((GameObject*)obj)->anim.modelState;
        if (sub != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags |= 0x810;
        }
        state->targetObj = ObjList_FindObjectById(state->linkedId);
        state->flags |= LAVA1BE_FLAG_INACTIVE;
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->objectFlags |= DIMLAVA_OBJFLAG_HITDETECT_DISABLED;
        state->light = objCreateLight(obj, 1);
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0x80, 0, 0);
            modelLightStruct_setDistanceAttenuation(state->light, gDimLavaLightAttenNear,
                                                    gDimLavaLightAttenFar);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0x80, 0, 0x64, gDimLavaGlowRadius);
            modelLightStruct_setGlowProjectionRadius(state->light, gDimLavaGlowRadius);
        }
    }
}

void lavaball1be_update(s16* obj)
{
    extern int Sfx_PlayFromObject(int* obj, int sfxId);
    Lavaball1beState* state;
    ObjHitsPriorityState* sub;

    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS)
    {
        ((GameObject*)obj)->anim.localPosX =
            ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY =
            ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ =
            ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.localPosZ;
        (*gPartfxInterface)->spawnObject(obj, LAVA1BE_PARTFX, NULL, 1, -1, NULL);
        ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + framesThisStep * 0x374;
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 0x12c;
        ((GameObject*)obj)->anim.velocityY = -(gDimLavaDebrisGravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            Obj_FreeObject((GameObject*)obj);
        }
    }
    else
    {
        state = ((GameObject*)obj)->extra;
        if (state->flags & LAVA1BE_FLAG_INACTIVE)
        {
            ObjHits_DisableObject(obj);
        }
        else
        {
            f32 dt = timeDelta;
            u8 steps = framesThisStep;
            if (state->explodeCooldown != 0)
            {
                state->explodeCooldown--;
            }
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (steps << 6);
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY - (steps << 9);
            ((GameObject*)obj)->anim.velocityY = gDimLavaGravity * dt + ((GameObject*)obj)->anim.velocityY;
            objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * dt, ((GameObject*)obj)->anim.velocityY * dt,
                    ((GameObject*)obj)->anim.velocityZ * dt);
            if (((GameObject*)obj)->anim.velocityY < lbl_803E47F8)
            {
                if (!(state->flags & LAVA1BE_FLAG_FALLING))
                {
                    Sfx_PlayFromObject((int*)obj, SFXTRIG_en_cvdrip1c_3dd);
                    state->flags |= LAVA1BE_FLAG_FALLING;
                }
            }
            else
            {
                state->flags &= ~LAVA1BE_FLAG_FALLING;
            }
            sub = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (sub != NULL)
            {
                sub->hitVolumePriority = 0xb;
                sub->hitVolumeId = 1;
                sub->objectHitMask = 0x10;
                sub->skeletonHitMask = 0x10;
                if (*(void**)&sub->lastHitObject != NULL)
                {
                    if (state->explodeCooldown != 0)
                    {
                        spawnExplosionLegacy(obj, lbl_803E47FC, 0, 1, 0, 0, 0, 0, 0);
                    }
                    else
                    {
                        state->explodeCooldown = 0xa;
                        spawnExplosionLegacy(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    }
                    state->flags |= LAVA1BE_FLAG_INACTIVE;
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
                if (((ObjAnimComponent*)sub)->bankIndex & 1)
                {
                    spawnExplosionLegacy(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    state->flags |= LAVA1BE_FLAG_INACTIVE;
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    return;
                }
            }
            if (((GameObject*)obj)->anim.localPosY < state->floorY)
            {
                state->flags |= LAVA1BE_FLAG_INACTIVE;
            }
            if (!(state->flags & LAVA1BE_FLAG_HOMING_OFF))
            {
                state->flags |= LAVA1BE_FLAG_HOMING_OFF;
            }
            if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
            {
                modelLightStruct_updateGlowAlpha(state->light);
            }
        }
    }
}

void lavaball1be_relaunch(s16* obj, int vertSpeed, int horizSpeed)
{
    Lavaball1beState* state;
    u8* setup;
    f32 vxz;
    f32 x;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    vxz = gDimLavaVelocityScale * horizSpeed;
    x = state->targetObj->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosX = x;
    ((GameObject*)obj)->anim.localPosX = x;
    x = state->targetObj->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosY = x;
    ((GameObject*)obj)->anim.localPosY = x;
    x = state->targetObj->anim.localPosZ;
    ((GameObject*)obj)->anim.worldPosZ = x;
    ((GameObject*)obj)->anim.localPosZ = x;
    x = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousWorldPosX = x;
    ((GameObject*)obj)->anim.previousLocalPosX = x;
    x = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousWorldPosY = x;
    ((GameObject*)obj)->anim.previousLocalPosY = x;
    x = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->anim.previousWorldPosZ = x;
    ((GameObject*)obj)->anim.previousLocalPosZ = x;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((Lavaball1bePlacement*)setup)->spawnRotX << 8);
    ((GameObject*)obj)->anim.velocityX =
        vxz * -mathSinf(gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
    ((GameObject*)obj)->anim.velocityY = gDimLavaVelocityScale * vertSpeed;
    ((GameObject*)obj)->anim.velocityZ =
        vxz * -mathCosf(gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
    ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ObjHits_EnableObject(obj);
    state->flags &= ~LAVA1BE_FLAG_INACTIVE;
}
