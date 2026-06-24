/*
 * dimlava (DLL 0x1BE) - DIM lava-ball objects; the 0x1BE variant handles
 * both a small debris particle (seqId 0x1FA) and a full physics lava-ball
 * that homes on a target, glows, and triggers explosions on contact.
 */

#define LAVA1BE_SEQID_DEBRIS   0x1fa

#define LAVA1BE_FLAG_HOMING_OFF 0x08
#define LAVA1BE_FLAG_INACTIVE   0x10
#define LAVA1BE_FLAG_FALLING    0x20
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/objseq.h"

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);
STATIC_ASSERT(sizeof(Dll16CState) == 0x24);
STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

extern u32 ObjHits_DisableObject();


void imicepillar_free(void);

int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(int* obj);
extern void warpToMap(int idx, s8 transType);

#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/engine_shared.h"

typedef struct Lavaball1bePlacement
{
    u8 pad0[0x18 - 0x0];
    s8 spawnRotX; /* spawn yaw byte, placed in anim.rotX high byte */
    u8 pad19[0x20 - 0x19];
} Lavaball1bePlacement;

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

extern u32 ObjHits_EnableObject();
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void ModelLightStruct_free(void* light);
extern void queueGlowRender(int* obj);
extern int modelLightStruct_getActiveState(int* p);
extern f32 lbl_803E47F0;
extern void modelLightStruct_updateGlowAlpha(int p);
extern f32 gDimLavaDebrisGravity, gDimLavaGravity, lbl_803E47F8, lbl_803E47FC;
extern f32 gDimLavaDebrisRootMotionScale, gDimLavaVelocityScale, gDimLavaPi, gDimLavaAngleUnitsHalfCircle;
extern f32 gDimLavaLightAttenNear, gDimLavaLightAttenFar, gDimLavaGlowRadius;
extern u8 gDimLavaDebrisBaseVec[];
extern void vecRotateZXY(void* in, void* out);


extern int ObjList_FindObjectById(int id);
extern u8* objCreateLight(s16* obj, int b);
extern void modelLightStruct_setLightKind(u8* light, int value);
extern void modelLightStruct_setDiffuseColor(u8* light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern void modelLightStruct_setupGlow(u8* light, int p3, int p4, int p5, int p6, int p7, f32 a);
extern void modelLightStruct_setGlowProjectionRadius(u8* light, f32 a);

static inline int* DIMcannon_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling on
#pragma peephole on
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

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

#pragma scheduling off
#pragma peephole off
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
    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS) return 0x0;
    return 0x14;
}

int lavaball1be_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS) return 0x0;
    return 0x2;
}

u32 lavaball1be_func11(int* obj) { return *((u8*)(int*)((GameObject*)obj)->extra + 0x10) & 0x10; }

int fn_801B0784(int obj, int delta);

void lavaball1be_free(int obj)
{
    Lavaball1beState* inner = ((GameObject*)obj)->extra;
    if (inner->light != 0)
    {
        ModelLightStruct_free(inner->light);
        inner->light = 0;
    }
}

void lavaball1be_render(int* obj, int p2, int p3, int p4, int p5)
{
    Lavaball1beState* state = ((GameObject*)obj)->extra;
    if ((int*)state->light != NULL)
    {
        if (modelLightStruct_getActiveState((int*)state->light) != 0)
        {
            queueGlowRender((int*)state->light);
        }
    }
    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E47F0);
}

typedef struct
{
    f32 x, y, z;
} LavaVec;

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
        vecRotateZXY((u8*)&s + 12, &s.vec);
        ((GameObject*)obj)->unkF4 = 0x4b;
        ((GameObject*)obj)->anim.velocityX = s.vec.x;
        ((GameObject*)obj)->anim.velocityY = s.vec.y;
        ((GameObject*)obj)->anim.velocityZ = s.vec.z;
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * gDimLavaDebrisRootMotionScale;
    }
    else
    {
        f32 vy;
        f32 vxz;
        int* sub;
        u8* light;

        ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)(p + 0x18) << 8);
        state = ((GameObject*)obj)->extra;
        vy = gDimLavaVelocityScale * (f32) * (s16*)(p + 0x1a);
        vxz = gDimLavaVelocityScale * (f32) * (s16*)(p + 0x1c);
        state->floorY = ((GameObject*)obj)->anim.localPosY;
        state->linkedId = *(int*)(p + 0x14);
        *(int*)(p + 0x14) = -1;
        ((GameObject*)obj)->anim.velocityX = vxz * -mathSinf(
            gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
        ((GameObject*)obj)->anim.velocityY = vy;
        ((GameObject*)obj)->anim.velocityZ = vxz * -mathCosf(
            gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
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
        *(int*)&state->targetObj = ObjList_FindObjectById(state->linkedId);
        state->flags |= LAVA1BE_FLAG_INACTIVE;
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->objectFlags |= 0x2000;
        state->light = objCreateLight(obj, 1);
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setLightKind(light, 2);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0x80, 0, 0);
            modelLightStruct_setDistanceAttenuation(state->light, gDimLavaLightAttenNear, gDimLavaLightAttenFar);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0x80, 0, 0x64, gDimLavaGlowRadius);
            modelLightStruct_setGlowProjectionRadius(state->light, gDimLavaGlowRadius);
        }
    }
}

void lavaball1be_update(s16* obj)
{
    extern void spawnExplosion(s16* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g); /* #57 */
    extern int Sfx_PlayFromObject(int* obj, int sfxId); /* #57 */
    extern void Obj_FreeObject(void* o); /* #57 */
    Lavaball1beState* state;
    int* sub;

    if (((GameObject*)obj)->anim.seqId == LAVA1BE_SEQID_DEBRIS)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.
            localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.
            localPosZ;
        (*gPartfxInterface)->spawnObject(obj, 0x1f5, NULL, 1, -1, NULL);
        ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + framesThisStep * 0x374;
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 0x12c;
        ((GameObject*)obj)->anim.velocityY = -(gDimLavaDebrisGravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            Obj_FreeObject(obj);
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
            objMove((int)obj,
                    ((GameObject*)obj)->anim.velocityX * dt,
                    ((GameObject*)obj)->anim.velocityY * dt,
                    ((GameObject*)obj)->anim.velocityZ * dt);
            if (((GameObject*)obj)->anim.velocityY < lbl_803E47F8)
            {
                if (!(state->flags & LAVA1BE_FLAG_FALLING))
                {
                    Sfx_PlayFromObject((int*)obj, 0x3dd);
                    state->flags |= LAVA1BE_FLAG_FALLING;
                }
            }
            else
            {
                state->flags &= ~LAVA1BE_FLAG_FALLING;
            }
            sub = *(int**)&((GameObject*)obj)->anim.hitReactState;
            if (sub != NULL)
            {
                *((u8*)sub + 0x6e) = 0xb;
                *((u8*)sub + 0x6f) = 1;
                sub[0x48 / 4] = 0x10;
                sub[0x4c / 4] = 0x10;
                if (*(void**)&((ObjHitsPriorityState*)sub)->lastHitObject != NULL)
                {
                    if (state->explodeCooldown != 0)
                    {
                        spawnExplosion(obj, lbl_803E47FC, 0, 1, 0, 0, 0, 0, 0);
                    }
                    else
                    {
                        state->explodeCooldown = 0xa;
                        spawnExplosion(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    }
                    state->flags |= LAVA1BE_FLAG_INACTIVE;
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
                if (((ObjAnimComponent*)sub)->bankIndex & 1)
                {
                    spawnExplosion(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
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
            if ((void*)state->light != NULL && modelLightStruct_getActiveState((int*)state->light) != 0)
            {
                modelLightStruct_updateGlowAlpha((int)state->light);
            }
        }
    }
}

void lavaball1be_setScale(s16* obj, int vertSpeed, int horizSpeed)
{
    Lavaball1beState* state;
    u8* setup;
    f32 vxz;
    f32 x;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    vxz = gDimLavaVelocityScale * horizSpeed;
    x = ((GameObject*)state->targetObj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosX = x;
    ((GameObject*)obj)->anim.localPosX = x;
    x = ((GameObject*)state->targetObj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosY = x;
    ((GameObject*)obj)->anim.localPosY = x;
    x = ((GameObject*)state->targetObj)->anim.localPosZ;
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
    ((GameObject*)obj)->anim.velocityX = vxz * -mathSinf(
        gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
    ((GameObject*)obj)->anim.velocityY = gDimLavaVelocityScale * vertSpeed;
    ((GameObject*)obj)->anim.velocityZ = vxz * -mathCosf(
        gDimLavaPi * (f32)((GameObject*)obj)->anim.rotX / gDimLavaAngleUnitsHalfCircle);
    ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ObjHits_EnableObject(obj);
    state->flags &= ~LAVA1BE_FLAG_INACTIVE;
}
