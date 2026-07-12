/* DIM wood door falling debris updater [801B13E8-801B13F0) */

#include "main/game_object.h"
#include "main/object.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"

enum DIMwooddoorDebrisState
{
    DIMWOODDOOR_DEBRIS_STATE_FALLING = 0, /* fall under gravity, spin, watch for impact */
    DIMWOODDOOR_DEBRIS_STATE_EXPLODED = 1 /* exploded + hidden, awaiting despawn timer   */
};

typedef struct DIMwooddoorUpdateFallingDebrisState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    s16 unk2;
    u8 pad4[0x5 - 0x4];
    u8 hitboxRadius;
    u8 hitVolumeSlot;
    u8 unk7;
    u8 state;
    s8 rotZRate;
    s8 rotYRate;
    s8 rotXRate;
    u8 padC[0x10 - 0xC];
} DIMwooddoorUpdateFallingDebrisState;

#define DLL801B1D84_HIT_VOLUME_SLOT 5

extern f32 lbl_803E48A0;
extern f32 lbl_803E48A4;
extern f32 lbl_803E48A8;
extern f32 lbl_803DBEF0;

extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);

/* DIMwooddoor_updateFallingDebris: integrate the falling debris under gravity, spin it, and on
 * contact (or scripted trigger) fire the explosion and start the despawn timer. */

void DIMwooddoor_updateFallingDebris(int* obj)
{
    int* extra = ((GameObject*)obj)->extra;
    switch (((DIMwooddoorUpdateFallingDebrisState*)extra)->state)
    {
    case DIMWOODDOOR_DEBRIS_STATE_FALLING:
    {
        f32 oldvy = ((GameObject*)obj)->anim.velocityY;
        f32 grav = lbl_803E48A4 * -lbl_803DBEF0;
        f32 midVel;
        ObjHitsPriorityState* hitState;
        ((GameObject*)obj)->anim.velocityY = grav * timeDelta + oldvy;
        midVel = lbl_803E48A8 * (oldvy + ((GameObject*)obj)->anim.velocityY);
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, midVel * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        ((GameObject*)obj)->anim.rotZ =
            ((GameObject*)obj)->anim.rotZ + ((DIMwooddoorUpdateFallingDebrisState*)extra)->rotZRate * 10;
        ((GameObject*)obj)->anim.rotY =
            ((GameObject*)obj)->anim.rotY + ((DIMwooddoorUpdateFallingDebrisState*)extra)->rotYRate * 10;
        *(s16*)obj = *(s16*)obj + ((DIMwooddoorUpdateFallingDebrisState*)extra)->rotXRate * 10;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        if (hitState != NULL)
        {
            int* vol;
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DLL801B1D84_HIT_VOLUME_SLOT,
                                     ((DIMwooddoorUpdateFallingDebrisState*)extra)->hitVolumeSlot, 0);
            vol = (int*)hitState->lastHitObject;
            if (vol != NULL && vol != *(int**)extra)
            {
                ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                          ((DIMwooddoorUpdateFallingDebrisState*)extra)->hitboxRadius);
                spawnExplosion(obj, lbl_803E48A0, 2, 1, 0, 1, 1, 1, 0);
                ((GameObject*)obj)->unkF4 = 1180;
                *(s8*)&((DIMwooddoorUpdateFallingDebrisState*)extra)->state = DIMWOODDOOR_DEBRIS_STATE_EXPLODED;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
        if ((mainGetBit(GAMEBIT_DIM2_CannonRelated085E) != 0 && mainGetBit(GAMEBIT_CannonRelated0C2D) == 0) ||
            (mainGetBit(GAMEBIT_DIM2_CannonRelated0874) != 0 && mainGetBit(GAMEBIT_CannonRelated0C2E) == 0))
        {
            ((GameObject*)obj)->unkF4 = 1200;
        }
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                      ((DIMwooddoorUpdateFallingDebrisState*)extra)->hitboxRadius);
            spawnExplosion(obj, lbl_803E48A0, 2, 1, 0, 1, 1, 1, 0);
            ((GameObject*)obj)->unkF4 = 1180;
            *(s8*)&((DIMwooddoorUpdateFallingDebrisState*)extra)->state = DIMWOODDOOR_DEBRIS_STATE_EXPLODED;
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        break;
    }
    case DIMWOODDOOR_DEBRIS_STATE_EXPLODED:
        break;
    }
    ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + framesThisStep;
    if (((GameObject*)obj)->unkF4 > 1200)
    {
        Obj_FreeObject((GameObject*)obj);
    }
    else if (((DIMwooddoorUpdateFallingDebrisState*)extra)->unk7 != 0)
    {
        *(s8*)&((DIMwooddoorUpdateFallingDebrisState*)extra)->unk7 = 0;
    }
}
