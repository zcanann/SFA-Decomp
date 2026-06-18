#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

typedef union ArwProjectileParam0
{
    f32 scalar;
    u8 particleKind;
} ArwProjectileParam0;

typedef struct ArwProjectileState
{
    ArwProjectileParam0 param0;
    f32 lifetime;
    f32 deflectSpeedScale;
    u8 pad0C[4];
    f32 despawnTimer;
    void* light;
    u8 hitVolumeMode;
    u8 pad19;
    s16 rotZSpeed;
    s16 rotYSpeed;
    u8 pad1E[2];
} ArwProjectileState;

typedef struct ArwProjectileSetup
{
    u8 pad00[0x19];
    u8 rotY;
    u8 rotX;
} ArwProjectileSetup;

STATIC_ASSERT(sizeof(ArwProjectileState) == 0x20);
STATIC_ASSERT(offsetof(ArwProjectileState, lifetime) == 0x04);
STATIC_ASSERT(offsetof(ArwProjectileState, deflectSpeedScale) == 0x08);
STATIC_ASSERT(offsetof(ArwProjectileState, despawnTimer) == 0x10);
STATIC_ASSERT(offsetof(ArwProjectileState, light) == 0x14);
STATIC_ASSERT(offsetof(ArwProjectileState, hitVolumeMode) == 0x18);
STATIC_ASSERT(offsetof(ArwProjectileState, rotZSpeed) == 0x1A);
STATIC_ASSERT(offsetof(ArwProjectileState, rotYSpeed) == 0x1C);
STATIC_ASSERT(offsetof(ArwProjectileSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwProjectileSetup, rotX) == 0x1A);

int arwingandrossstuff_getExtraSize(void) { return 0x20; }

int arwingandrossstuff_getObjectTypeId(void) { return 0; }

void arwingandrossstuff_free(int obj)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;

    ObjGroup_RemoveObject(obj, 0x2);
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
}

void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E701C);
    }
}

void arwingandrossstuff_release(void)
{
}

void arwingandrossstuff_initialise(void)
{
}

void arwingandrossstuff_hitDetect(int obj)
{
    struct
    {
        f32 x, y, z;
    } d, v, w;
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)objAnim->hitReactState;
    int arwing = getArwing();
    ObjAnimComponent* arwingAnim = &((GameObject*)arwing)->anim;

    if (objAnim->seqId == 0x80d)
    {
        int hit;
        uint vol;

        if (ObjHits_GetPriorityHit(obj, &hit, 0, &vol) != 0)
        {
            spawnExplosion(obj, lbl_803E7014, 1, 0, 0, 1, 0, 0, 3);
            objAnim->flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            state->despawnTimer = lbl_803E7028;
        }
    }
    if (hitState->lastHitObject != 0 && *((u8*)&state->param0 + 1) == 0)
    {
        if (objAnim->seqId != 0x6ae)
        {
            Sfx_PlayFromObjectLimited(obj, SFXbaddie_invin_hit, 4);
        }
        if (objAnim->seqId == 0x7e4)
        {
            s16 a = (s16) - getAngle(objAnim->localPosX - arwingAnim->localPosX,
                                     objAnim->localPosY - arwingAnim->localPosY);
            f32 ang = lbl_803E7030 * (f32)a / lbl_803E7034;

            v.x = lbl_803E702C * mathSinf(ang);
            v.y = lbl_803E7038 * mathCosf(ang);
            v.z = lbl_803E7008;
            w = v;
            arwarwing_setVelocity(arwing, (int)&w);
            doRumble(lbl_803E703C);
        }
        if (hitState->lastHitObject == arwing)
        {
            if (arwarwing_isBarrelRolling(arwing) != 0)
            {
                PSVECNormalize(&objAnim->velocityX, &objAnim->velocityX);
                d.x = objAnim->localPosX - arwingAnim->localPosX;
                d.y = objAnim->localPosY - arwingAnim->localPosY;
                d.z = objAnim->localPosZ - arwingAnim->localPosZ;
                PSVECNormalize(&d, &d);
                C_VECHalfAngle(&objAnim->velocityX, &d, &objAnim->velocityX);
                objAnim->velocityX *= state->deflectSpeedScale;
                objAnim->velocityY *= state->deflectSpeedScale;
                objAnim->velocityZ *= state->deflectSpeedScale;
                *((u8*)&state->param0 + 1) = 1;
            }
        }
        state->despawnTimer = lbl_803E7028;
        objAnim->alpha = 0;
        projectileParticleFxFn_80099660(obj, lbl_803E701C, state->param0.particleKind);
        if (state->light != NULL)
        {
            ModelLightStruct_free(state->light);
            state->light = 0;
        }
    }
}

void arwprojectile_setLifetime(int obj, int lifetime)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;

    state->lifetime = (f32)lifetime;
}

void arwprojectile_placeForward(int obj, f32 dist)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    f32 mtx[16];
    ArwProjPosSrc src;

    state->deflectSpeedScale = dist;
    src.pos[0] = lbl_803E7008;
    src.pos[1] = lbl_803E7008;
    src.pos[2] = lbl_803E7008;
    src.rot[0] = *(s16*)obj;
    src.rot[1] = ((GameObject*)obj)->anim.rotY;
    src.rot[2] = 0;
    src.scale = lbl_803E701C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, lbl_803E7008, *(f32*)&lbl_803E7008, state->deflectSpeedScale,
                          &((GameObject*)obj)->anim.velocityX, &((GameObject*)obj)->anim.velocityY,
                          &((GameObject*)obj)->anim.velocityZ);
    *(s16*)obj += 0x8000;
    ((GameObject*)obj)->anim.rotY = -((GameObject*)obj)->anim.rotY;
}

#pragma peephole off
void arwingandrossstuff_init(int obj, u8* setup)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    ArwProjectileSetup* mapData = (ArwProjectileSetup*)setup;
    ObjHitsPriorityState* hitState;

    *(s16*)obj = (s16)(mapData->rotX << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(mapData->rotY << 8);
    ((GameObject*)obj)->anim.alpha = 1;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x80d:
        state->rotZSpeed = randomGetRange(-0x1f4, 0x1f4);
        state->rotYSpeed = randomGetRange(-0x1f4, 0x1f4);
    case 0x6ae:
    case 0x7e4:
        ObjHits_SetTargetMask(obj, 4);
        state->param0.particleKind = 4;
        state->hitVolumeMode = 2;
        break;
    case 0x655:
        ObjHits_SetTargetMask(obj, 1);
        state->param0.particleKind = 0;
        state->hitVolumeMode = 1;
        break;
    case 0x604:
        ObjHits_SetTargetMask(obj, 1);
        if (((ObjAnimComponent*)obj)->bankIndex != 0)
        {
            state->param0.particleKind = 2;
            state->hitVolumeMode = 2;
        }
        else
        {
            state->param0.particleKind = 1;
            state->hitVolumeMode = 2;
        }
        break;
    default:
        ObjHits_SetTargetMask(obj, 1);
        state->param0.particleKind = 2;
        break;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->trackContactMask = 1;
    }
    ObjGroup_AddObject(obj, 2);
}

#pragma peephole off
void arwingandrossstuff_update(int obj)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    int arwing = getArwing();

    if ((void*)arwing != NULL && (((GameObject*)arwing)->objectFlags & 0x1000) != 0)
    {
        Obj_FreeObject(obj);
        return;
    }
    if (state->despawnTimer > lbl_803E7008)
    {
        state->despawnTimer -= timeDelta;
        if (state->despawnTimer <= lbl_803E7008)
        {
            Obj_FreeObject(obj);
        }
        return;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xf, state->hitVolumeMode, 0);
    ((GameObject*)obj)->anim.alpha = 0xff;
    if (state->lifetime > lbl_803E7008)
    {
        state->lifetime -= timeDelta;
        if (state->lifetime <= lbl_803E7008)
        {
            state->lifetime = lbl_803E7008;
            Obj_FreeObject(obj);
            return;
        }
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            if (((GameObject*)obj)->anim.seqId != 0x6ae)
            {
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_invin_hit, 4);
            }
            state->despawnTimer = lbl_803E7028;
            ((GameObject*)obj)->anim.alpha = 0;
            projectileParticleFxFn_80099660(obj, lbl_803E701C, state->param0.particleKind);
            if (*(int*)&state->light != 0)
            {
                ModelLightStruct_free(state->light);
                state->light = 0;
            }
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        if (((GameObject*)obj)->anim.seqId == 0x80d)
        {
            ((GameObject*)obj)->anim.rotZ += state->rotZSpeed;
            ((GameObject*)obj)->anim.rotY += state->rotYSpeed;
        }
        if (((GameObject*)obj)->anim.seqId == 0x7e4)
        {
            ((GameObject*)obj)->anim.rootMotionScale += lbl_803DC3D0;
            ObjHitbox_SetSphereRadius(obj, (int)(((GameObject*)obj)->anim.rootMotionScale * lbl_803DC3D8));
            ((GameObject*)obj)->anim.rotZ = (int)((f32)((GameObject*)obj)->anim.rotZ + lbl_803DC3D4);
        }
    }
}

void arwprojectile_createLinkedEffect(int obj, u8 enable)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    if (enable == 0)
        return;
    if (state->light != NULL)
        return;
    state->light = objCreateLight(obj, 1);
    if (state->light == NULL)
        return;
    modelLightStruct_setLightKind(state->light, 2);
    modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);
    lightSetFieldBC_8001db14(state->light, 1);
    if (((GameObject*)obj)->anim.seqId == 0x6ae)
    {
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x14, 0x50, 0);
    }
    else if (((ObjAnimComponent*)obj)->bankIndex == 0)
    {
        modelLightStruct_setDiffuseColor(state->light, 0x3c, 0xff, 0x5a, 0);
    }
    else
    {
        modelLightStruct_setDiffuseColor(state->light, 0x3c, 0x5a, 0xff, 0);
    }
    if (((GameObject*)obj)->anim.seqId == 0x655)
    {
        modelLightStruct_setDistanceAttenuation(state->light, lbl_803E700C, lbl_803E7010);
    }
    else
    {
        modelLightStruct_setDistanceAttenuation(state->light, lbl_803E7014, lbl_803E7018);
    }
    modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
}

void fn_8022ED74(int obj, int v)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    state->param0.scalar = (f32)v;
}

void fn_8022ECE0(int obj, f32 param)
{
    ArwProjectileState* state = ((GameObject*)obj)->extra;
    f32 mtx[16];
    ArwProjPosSrc src;

    state->lifetime = param;
    src.pos[0] = lbl_803E7044;
    src.pos[1] = lbl_803E7044;
    src.pos[2] = lbl_803E7044;
    src.rot[0] = *(s16*)obj;
    src.rot[1] = ((GameObject*)obj)->anim.rotY;
    src.rot[2] = 0;
    src.scale = lbl_803E704C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, *(f32*)&lbl_803E7044, lbl_803E7044, state->lifetime,
                          &((GameObject*)obj)->anim.velocityX, &((GameObject*)obj)->anim.velocityY,
                          &((GameObject*)obj)->anim.velocityZ);
}
