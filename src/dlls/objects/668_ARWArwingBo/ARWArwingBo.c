/*
 * ARWArwingBo (DLL 668) - the Arwing's deployed bomb in the on-rails
 * flight sections. While its fuse timer counts down it flies forward along
 * its velocity, trailing particle fx. It detonates when the fuse expires,
 * when it strikes something, or when the player re-presses the bomb button
 * (button bit 0x200): it plays the explosion, arms a blast hitbox for a few
 * frames, then frees itself. It is registered into object group 0x52 and
 * detaches its expgfx source on free; arwarwing keeps a back-pointer that is
 * cleared via arwarwing_clearActiveBomb when the bomb goes away.
 *
 * This unit also owns the bomb-drop projectile entry points
 * arwprojectile_launchForward + arwprojectile_setParamScalar (called from
 * arwarwing's bomb release; the projectile object itself is DLL 0x29B).
 */
#include "main/audio/sfx_play_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/ARW/dll_029C_arwarwingbo.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/objfx.h"
#include "main/pad.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "dolphin/pad.h"

#define ARWARWINGBO_OBJGROUP        0x52
#define ARWARWINGBO_PARTFX          0x79e
#define ARWARWINGBO_HIT_VOLUME_SLOT 5

ObjectDescriptor gARWArwingBoObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)arwarwingbo_initialise,
    (ObjectDescriptorCallback)arwarwingbo_release,
    NULL,
    (ObjectDescriptorCallback)arwarwingbo_init,
    (ObjectDescriptorCallback)arwarwingbo_update,
    (ObjectDescriptorCallback)arwarwingbo_hitDetect,
    (ObjectDescriptorCallback)arwarwingbo_render,
    (ObjectDescriptorCallback)arwarwingbo_free,
    (ObjectDescriptorCallback)arwarwingbo_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)arwarwingbo_getExtraSize,
};

static void arwarwingbo_detonate(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ArwingBombState* state = obj->extra;

    arwarwing_clearActiveBomb(getArwing());
    Sfx_PlayFromObject(obj, SFXTRIG_ar_awghitobj16_2a5);
    state->explosionTimer = 100.0f;
    state->control.fuseTimer = 0.0f;
    objAnim->alpha = 0;
    ((ObjHitsPriorityState*)objAnim->hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_TRACK_CONTACT;
    spawnExplosion(obj, 127.0f, 1, 0, 1, 1, 0, 1, 0);
    ObjHitbox_SetSphereRadius(&obj->anim, 0x280);
    ObjHits_SetHitVolumeSlot(&obj->anim, ARWARWINGBO_HIT_VOLUME_SLOT, 5, 0);
    objAnim->velocityZ = objAnim->velocityY = objAnim->velocityX = 0.0f;
}

void arwprojectile_launchForward(GameObject* obj, f32 lifetime)
{
    ArwProjectileState* state = obj->extra;
    f32 mtx[16];
    MatrixTransform src;

    state->lifetime = lifetime;
    src.x = 0.0f;
    src.y = 0.0f;
    src.z = 0.0f;
    src.rotX = obj->anim.rotX;
    src.rotY = obj->anim.rotY;
    src.rotZ = 0;
    src.scale = 1.0f;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, 0.0f, 0.0f, state->lifetime, &obj->anim.velocityX,
                          &obj->anim.velocityY, &obj->anim.velocityZ);
}

void arwprojectile_setParamScalar(GameObject* obj, int scalar)
{
    ArwProjectileState* state = obj->extra;
    state->param0.scalar = scalar;
}

int arwarwingbo_getExtraSize(void)
{
    return 0xc;
}

int arwarwingbo_getObjectTypeId(void)
{
    return 0;
}

void arwarwingbo_free(int obj)
{
    (*gExpgfxInterface)->freeSource(obj);
    objFreeObjectType((GameObject*)obj, ARWARWINGBO_OBJGROUP);
}

void arwarwingbo_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void arwarwingbo_hitDetect(void)
{
}

void arwarwingbo_update(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ArwingBombState* state = obj->extra;
    GameObject* arwing = getArwing();
    f32 zero;

    if (arwing->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)
    {
        arwarwing_clearActiveBomb(arwing);
        Obj_FreeObject(obj);
        return;
    }
    if (state->explosionTimer > (zero = 0.0f))
    {
        state->explosionTimer -= timeDelta;
        if (state->explosionTimer <= zero)
            Obj_FreeObject(obj);
        return;
    }
    if (state->control.fuseTimer > zero)
    {
        state->control.fuseTimer -= timeDelta;
        if (state->control.fuseTimer <= zero)
        {
            arwarwingbo_detonate(obj);
        }
        (*gPartfxInterface)->spawnObject(obj, ARWARWINGBO_PARTFX, NULL, 1, -1, &objAnim->velocityX);
        (*gPartfxInterface)->spawnObject(obj, ARWARWINGBO_PARTFX, NULL, 1, -1, &objAnim->velocityX);
    }
    else
    {
        return;
    }
    ObjHits_SetHitVolumeSlot(&obj->anim, 0xf, 0, 0);
    if (((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 ||
        ((ObjHitsPriorityState*)objAnim->hitReactState)->contactFlags != 0 ||
        (getButtonsJustPressed(0) & PAD_BUTTON_B))
    {
        arwarwingbo_detonate(obj);
    }
    objMove(obj, objAnim->velocityX * timeDelta, objAnim->velocityY * timeDelta, objAnim->velocityZ * timeDelta);
}

void arwarwingbo_init(GameObject* obj, ArwingBombSetup* setup)
{
    obj->anim.rotX = (s16)(setup->rotX << 8);
    obj->anim.rotY = (s16)(setup->rotY << 8);
    obj->anim.rotZ = (s16)(setup->rotZ << 8);
    objAddObjectType(obj, ARWARWINGBO_OBJGROUP);
}

void arwarwingbo_release(void)
{
}

void arwarwingbo_initialise(void)
{
}

void arwarwingbo_setActiveVisible(GameObject* obj, u8 active, u8 visible)
{
    ArwingBombState* state = obj->extra;
    if (active != 0)
    {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        state->control.active = 1;
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        state->control.active = 0;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
}
