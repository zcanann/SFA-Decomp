/*
 * arwarwingbo (DLL 0x29C) - the Arwing's deployed bomb in the on-rails
 * flight sections. While its fuse timer counts down it flies forward along
 * its velocity, trailing particle fx. It detonates when the fuse expires,
 * when it strikes something, or when the player re-presses the bomb button
 * (button bit 0x200): it plays the explosion, arms a blast hitbox for a few
 * frames, then frees itself. It is registered into object group 0x52 and
 * detaches its expgfx source on free; arwarwing keeps a back-pointer that is
 * cleared via arwarwing_clearActiveBomb when the bomb goes away.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

#define ARWARWINGBO_OBJGROUP 0x52

#define ARWARWINGBO_OBJFLAG_PARENT_SLACK 0x1000
#define PAD_BUTTON_B 0x200

typedef union ArwingBombControl
{
    f32 fuseTimer;
    u8 active;
} ArwingBombControl;

typedef struct ArwingBombState
{
    ArwingBombControl control;
    u8 pad04[4];
    f32 explosionTimer;
} ArwingBombState;

typedef struct ArwingBombSetup
{
    u8 pad00[0x18];
    u8 rotZ;
    u8 rotY;
    u8 rotX;
} ArwingBombSetup;

STATIC_ASSERT(sizeof(ArwingBombState) == 0x0c);
STATIC_ASSERT(offsetof(ArwingBombState, explosionTimer) == 0x08);
STATIC_ASSERT(offsetof(ArwingBombSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(ArwingBombSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwingBombSetup, rotX) == 0x1A);

int arwarwingbo_getExtraSize(void) { return 0xc; }

int arwarwingbo_getObjectTypeId(void) { return 0; }

void arwarwingbo_free(int obj)
{
    (*gExpgfxInterface)->freeSource(obj);
    ObjGroup_RemoveObject(obj, ARWARWINGBO_OBJGROUP);
}

void arwarwingbo_hitDetect(void)
{
}

void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E704C);
    }
}

void arwarwingbo_init(int obj, int setup)
{
    ArwingBombSetup* mapData = (ArwingBombSetup*)setup;

    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotX << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(mapData->rotY << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)(mapData->rotZ << 8);
    ObjGroup_AddObject(obj, ARWARWINGBO_OBJGROUP);
}

void arwarwingbo_setActiveVisible(int obj, u8 active, u8 visible)
{
    ArwingBombState* state = ((GameObject*)obj)->extra;
    if (active != 0)
    {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        state->control.active = 1;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        state->control.active = 0;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
}

void arwarwingbo_release(void)
{
}

void arwarwingbo_initialise(void)
{
}

void arwarwingbo_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ArwingBombState* state = ((GameObject*)obj)->extra;
    int arwing = getArwing();
    f32 zero;
    extern u32 getButtonsJustPressed(int port);

    if (((GameObject*)arwing)->objectFlags & ARWARWINGBO_OBJFLAG_PARENT_SLACK)
    {
        arwarwing_clearActiveBomb(arwing);
        Obj_FreeObject(obj);
        return;
    }
    if (state->explosionTimer > (zero = lbl_803E7044))
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
            state = ((GameObject*)obj)->extra;
            arwarwing_clearActiveBomb(getArwing());
            Sfx_PlayFromObject(obj, SFXbaddie_eba_death);
            state->explosionTimer = lbl_803E7040;
            state->control.fuseTimer = lbl_803E7044;
            objAnim->alpha = 0;
            (*(ObjHitsPriorityState**)&objAnim->hitReactState)->flags &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            objAnim->velocityZ = objAnim->velocityY = objAnim->velocityX = lbl_803E7044;
        }
        (*gPartfxInterface)->spawnObject((void*)obj, 0x79e, NULL, 1, -1,
                                         &objAnim->velocityX);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x79e, NULL, 1, -1,
                                         &objAnim->velocityX);
    }
    else
    {
        return;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xf, 0, 0);
    if ((*(ObjHitsPriorityState**)&objAnim->hitReactState)->lastHitObject != 0 ||
        (*(ObjHitsPriorityState**)&objAnim->hitReactState)->contactFlags != 0 ||
        (getButtonsJustPressed(0) & PAD_BUTTON_B))
    {
        state = ((GameObject*)obj)->extra;
        arwarwing_clearActiveBomb(getArwing());
        Sfx_PlayFromObject(obj, SFXbaddie_eba_death);
        state->explosionTimer = lbl_803E7040;
        state->control.fuseTimer = lbl_803E7044;
        objAnim->alpha = 0;
        (*(ObjHitsPriorityState**)&objAnim->hitReactState)->flags &= ~0x200;
        spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
        ObjHitbox_SetSphereRadius(obj, 0x280);
        ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
        objAnim->velocityZ = objAnim->velocityY = objAnim->velocityX = lbl_803E7044;
    }
    objMove(obj, objAnim->velocityX * timeDelta, objAnim->velocityY * timeDelta,
            objAnim->velocityZ * timeDelta);
}
