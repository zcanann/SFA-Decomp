#include "main/dll/dll_80220608_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
#include "main/objhits_types.h"

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

STATIC_ASSERT (
sizeof
(ArwingBombState)
==
0x0c
);
STATIC_ASSERT (offsetof
(ArwingBombState
,
explosionTimer
)
==
0x08
);
STATIC_ASSERT (offsetof
(ArwingBombSetup
,
rotZ
)
==
0x18
);
STATIC_ASSERT (offsetof
(ArwingBombSetup
,
rotY
)
==
0x19
);
STATIC_ASSERT (offsetof
(ArwingBombSetup
,
rotX
)
==
0x1A
);

int arwarwingbo_getExtraSize(void) { return 0xc; }

int arwarwingbo_getObjectTypeId(void) { return 0; }

void arwarwingbo_free(int obj)
{
    (*gExpgfxInterface)->freeSource(obj);
    ObjGroup_RemoveObject(obj, 0x52);
}

void arwarwingbo_hitDetect(void)
{
}

void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E704C);
    }
}

void arwarwingbo_init(int obj, int setup)
{
    ArwingBombSetup* mapData = (ArwingBombSetup*)setup;

    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotX << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(mapData->rotY << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)(mapData->rotZ << 8);
    ObjGroup_AddObject(obj, 0x52);
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
    ArwingBombState* state = ((GameObject*)obj)->extra;
    int arwing = getArwing();
    f32 zero = lbl_803E7044;

    if (*(u16*)(arwing + 0xb0) & 0x1000)
    {
        arwarwing_clearActiveBomb(arwing);
        Obj_FreeObject(obj);
        return;
    }
    if (state->explosionTimer > zero)
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
            ((GameObject*)obj)->anim.alpha = 0;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            ((GameObject*)obj)->anim.velocityX = lbl_803E7044;
            ((GameObject*)obj)->anim.velocityY = lbl_803E7044;
            ((GameObject*)obj)->anim.velocityZ = lbl_803E7044;
        }
        (*gPartfxInterface)->spawnObject((void*)obj, 0x79e, NULL, 1, -1,
                                         (void*)(obj + 0x24));
        (*gPartfxInterface)->spawnObject((void*)obj, 0x79e, NULL, 1, -1,
                                         (void*)(obj + 0x24));
        ObjHits_SetHitVolumeSlot(obj, 0xf, 0, 0);
        if ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 ||
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->contactFlags != 0 ||
            (getButtonsJustPressed(0) & 0x200))
        {
            state = ((GameObject*)obj)->extra;
            arwarwing_clearActiveBomb(getArwing());
            Sfx_PlayFromObject(obj, SFXbaddie_eba_death);
            state->explosionTimer = lbl_803E7040;
            state->control.fuseTimer = lbl_803E7044;
            ((GameObject*)obj)->anim.alpha = 0;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            ((GameObject*)obj)->anim.velocityX = lbl_803E7044;
            ((GameObject*)obj)->anim.velocityY = lbl_803E7044;
            ((GameObject*)obj)->anim.velocityZ = lbl_803E7044;
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }
}
