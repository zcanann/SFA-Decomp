/*
 * arwingandrossstuff (DLL 0x29B) - the Arwing's projectiles (lasers,
 * bombs, charge shots) and Andross-fight shots.
 *
 * Each instance is one in-flight projectile whose behaviour is keyed off
 * its anim.seqId: bomb (0x80d, given random tumble), the invincible/
 * charge variants (0x6ae/0x7e4), and the basic laser kinds (0x655/0x604).
 * init() sets the hit-target mask, particle kind and hit-
 * volume mode per seqId; update() flies the projectile (objMove by
 * velocity*timeDelta), counts down its lifetime/despawn timers, plays the
 * impact sfx + particle fx, and frees it. hitDetect() handles deflection:
 * an Arwing barrel-roll reflects the shot (half-angle of incoming
 * velocity) and rescales its speed by deflectSpeedScale.
 * createLinkedEffect() attaches a coloured point light to the shot.
 *
 * arwprojectile_placeForward and fn_8022ECE0 position a new projectile in
 * front of the Arwing; arwprojectile_setLifetime and fn_8022ED74 configure
 * its lifetime and speed; all four are called from wcfloortile.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/game_object.h"
#include "main/modellight_api.h"
#include "main/objfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define ARWINGANDROSSSTUFF_OBJGROUP 0x2

#define ARWINGANDROSSSTUFF_OBJFLAG_PARENT_SLACK 0x1000
#define ARWINGANDROSSSTUFF_HIT_VOLUME_SLOT      0xf

#pragma opt_common_subs off
void arwprojectile_createLinkedEffect(GameObject* obj, u8 enable)
{
    ArwProjectileState* state = (obj)->extra;
    if (enable == 0)
        return;
    if (state->light != NULL)
        return;
    state->light = objCreateLight(obj, 1);
    if (state->light == NULL)
        return;
    modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
    modelLightStruct_setPosition(state->light, lbl_803E7008, lbl_803E7008, lbl_803E7008);
    lightSetFieldBC_8001db14(state->light, 1);
    if ((obj)->anim.seqId == ARW_SEQID_INVINCIBLE)
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
    if ((obj)->anim.seqId == ARW_SEQID_LASER_GREEN)
    {
        modelLightStruct_setDistanceAttenuation(state->light, lbl_803E700C, lbl_803E7010);
    }
    else
    {
        modelLightStruct_setDistanceAttenuation(state->light, lbl_803E7014, lbl_803E7018);
    }
    modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
}
#pragma opt_common_subs reset

void arwprojectile_placeForward(GameObject* obj, f32 dist)
{
    ArwProjectileState* state = obj->extra;
    f32 mtx[16];
    MatrixTransform src;

    state->deflectSpeedScale = dist;
    src.x = lbl_803E7008;
    src.y = lbl_803E7008;
    src.z = lbl_803E7008;
    src.rotX = obj->anim.rotX;
    src.rotY = obj->anim.rotY;
    src.rotZ = 0;
    src.scale = lbl_803E701C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, lbl_803E7008, *(f32*)&lbl_803E7008, state->deflectSpeedScale, &obj->anim.velocityX,
                          &obj->anim.velocityY, &obj->anim.velocityZ);
    obj->anim.rotX += 0x8000;
    obj->anim.rotY = -obj->anim.rotY;
}

void arwprojectile_setLifetime(GameObject* obj, int lifetime)
{
    ArwProjectileState* state = obj->extra;

    state->lifetime = lifetime;
}

int arwingandrossstuff_getExtraSize(void)
{
    return 0x20;
}

int arwingandrossstuff_getObjectTypeId(void)
{
    return 0;
}

void arwingandrossstuff_free(GameObject* obj)
{
    ArwProjectileState* state = (obj)->extra;

    ObjGroup_RemoveObject((int)obj, ARWINGANDROSSSTUFF_OBJGROUP);
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
}

void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E701C);
    }
}

void arwingandrossstuff_hitDetect(GameObject* obj)
{
    Vec3f d, v, w;
    ObjAnimComponent* objAnim = &(obj)->anim;
    ArwProjectileState* state = (obj)->extra;
    GameObject* arwing = getArwing();
    ObjAnimComponent* arwingAnim = &arwing->anim;

    if (objAnim->seqId == ARW_SEQID_BOMB)
    {
        int hit;
        u32 vol;

        if (ObjHits_GetPriorityHit(obj, &hit, 0, &vol) != 0)
        {
            spawnExplosionLegacy((int)obj, lbl_803E7014, 1, 0, 0, 1, 0, 0, 3);
            objAnim->flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject((int)obj);
            state->despawnTimer = lbl_803E7028;
        }
    }
    if (((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 && state->param0.deflected == 0)
    {
        if (objAnim->seqId != ARW_SEQID_INVINCIBLE)
        {
            Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_ar_laser116, 4);
        }
        if (objAnim->seqId == ARW_SEQID_CHARGE)
        {
            s16 angle =
                (s16)-getAngle(objAnim->localPosX - arwingAnim->localPosX, objAnim->localPosY - arwingAnim->localPosY);
            f32 ang = gArwingAndrossPi * angle / gArwingAndrossBinAngScale;

            v.x = lbl_803E702C * mathSinf(ang);
            v.y = lbl_803E7038 * mathCosf(ang);
            v.z = lbl_803E7008;
            w = v;
            arwarwing_setVelocity(arwing, (int)&w);
            doRumble(lbl_803E703C);
        }
        if (((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)arwing)
        {
            if (arwarwing_isBarrelRolling((int)arwing) != 0)
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
                state->param0.deflected = 1;
            }
        }
        state->despawnTimer = lbl_803E7028;
        objAnim->alpha = 0;
        projectileParticleFxFn_80099660Legacy((int)obj, lbl_803E701C, state->param0.particleKind);
        if (state->light != NULL)
        {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
    }
}

void arwingandrossstuff_update(GameObject* obj)
{
    GameObject* object = obj;
    ArwProjectileState* state = object->extra;
    GameObject* arwing = getArwing();

    if (arwing != NULL && (arwing->objectFlags & ARWINGANDROSSSTUFF_OBJFLAG_PARENT_SLACK) != 0)
    {
        Obj_FreeObject((GameObject*)object);
        return;
    }
    {
        f32 dt = state->despawnTimer;
        f32 zero = lbl_803E7008;
        if (dt > zero)
        {
            state->despawnTimer = dt - timeDelta;
            if (state->despawnTimer <= zero)
            {
                Obj_FreeObject((GameObject*)object);
            }
            return;
        }
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)object, ARWINGANDROSSSTUFF_HIT_VOLUME_SLOT, state->hitVolumeMode, 0);
    object->anim.alpha = 0xff;
    {
        f32 lt = state->lifetime;
        f32 zero = lbl_803E7008;
        if (lt > zero)
        {
            state->lifetime = lt - timeDelta;
            if (state->lifetime <= zero)
            {
                state->lifetime = zero;
                Obj_FreeObject((GameObject*)object);
                return;
            }
        }
        else
        {
            return;
        }
        if (((ObjHitsPriorityState*)object->anim.hitReactState)->contactFlags != 0)
        {
            if (object->anim.seqId != ARW_SEQID_INVINCIBLE)
            {
                Sfx_PlayFromObjectLimited((int)object, SFXTRIG_ar_laser116, 4);
            }
            state->despawnTimer = lbl_803E7028;
            object->anim.alpha = 0;
            projectileParticleFxFn_80099660Legacy((int)object, lbl_803E701C, state->param0.particleKind);
            if (state->light != NULL)
            {
                ModelLightStruct_free(state->light);
                state->light = NULL;
            }
        }
        objMove((int)object, object->anim.velocityX * timeDelta, object->anim.velocityY * timeDelta,
                object->anim.velocityZ * timeDelta);
        if (object->anim.seqId == ARW_SEQID_BOMB)
        {
            object->anim.rotZ += state->rotZSpeed;
            object->anim.rotY += state->rotYSpeed;
        }
        if (object->anim.seqId == ARW_SEQID_CHARGE)
        {
            object->anim.rootMotionScale += lbl_803DC3D0;
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)object,
                                      (int)(object->anim.rootMotionScale * lbl_803DC3D8));
            object->anim.rotZ = (f32)object->anim.rotZ + lbl_803DC3D4;
        }
    }
}

void arwingandrossstuff_init(GameObject* obj, ArwProjectileSetup* setup)
{
    ArwProjectileState* state = (obj)->extra;
    ObjHitsPriorityState* hitState;

    (obj)->anim.rotX = (s16)(setup->rotX << 8);
    (obj)->anim.rotY = (s16)(setup->rotY << 8);
    (obj)->anim.alpha = 1;
    switch ((obj)->anim.seqId)
    {
    case ARW_SEQID_BOMB:
        state->rotZSpeed = randomGetRange(-0x1f4, 0x1f4);
        state->rotYSpeed = randomGetRange(-0x1f4, 0x1f4);
    case ARW_SEQID_INVINCIBLE:
    case ARW_SEQID_CHARGE:
        ObjHits_SetTargetMask((int)obj, 4);
        state->param0.particleKind = 4;
        state->hitVolumeMode = 2;
        break;
    case ARW_SEQID_LASER_GREEN:
        ObjHits_SetTargetMask((int)obj, 1);
        state->param0.particleKind = 0;
        state->hitVolumeMode = 1;
        break;
    case ARW_SEQID_LASER_BASIC:
        ObjHits_SetTargetMask((int)obj, 1);
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
        ObjHits_SetTargetMask((int)obj, 1);
        state->param0.particleKind = 2;
        break;
    }
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->trackContactMask = 1;
    }
    ObjGroup_AddObject((int)obj, ARWINGANDROSSSTUFF_OBJGROUP);
}

void arwingandrossstuff_release(void)
{
}

void arwingandrossstuff_initialise(void)
{
}

void fn_8022ECE0(GameObject* obj, f32 lifetime)
{
    ArwProjectileState* state = obj->extra;
    f32 mtx[16];
    MatrixTransform src;

    state->lifetime = lifetime;
    src.x = lbl_803E7044;
    src.y = lbl_803E7044;
    src.z = lbl_803E7044;
    src.rotX = obj->anim.rotX;
    src.rotY = obj->anim.rotY;
    src.rotZ = 0;
    src.scale = lbl_803E704C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, *(f32*)&lbl_803E7044, lbl_803E7044, state->lifetime, &obj->anim.velocityX,
                          &obj->anim.velocityY, &obj->anim.velocityZ);
}

void fn_8022ED74(GameObject* obj, int scalar)
{
    ArwProjectileState* state = obj->extra;
    state->param0.scalar = scalar;
}
