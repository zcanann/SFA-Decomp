/* DIM wood door falling debris updater [801B13E8-801B13F0) */

#include "main/game_object.h"
#include "main/gamebits.h"

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
    s8 hitboxRadius;
    s8 hitVolumeSlot;
    u8 unk7;
    u8 state;
    s8 rotZRate;
    s8 rotYRate;
    s8 rotXRate;
    u8 padC[0x10 - 0xC];
} DIMwooddoorUpdateFallingDebrisState;

/* dimgate_update: open the gate (hitbox state 1->2) once a type-399 object is
 * present in the trigger list, latching the gamebit. */

extern u8 framesThisStep;

/* dimbarrier_update: while a live type-470 object is in the list, count down the
 * arm timer; on expiry fade the barrier out and latch its gamebit. */

/* dimsnowball1c2_update: on a timer, if loading allows and the player is clear,
 * spawn a rolling snowball seeded from the placement params. */

extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void ObjHits_SetHitVolumeSlot(int* obj, int a, u8 b, int c);
extern void ObjHitbox_SetSphereRadius(int* obj, u8 radius);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern f32 lbl_803E48A0;
extern f32 lbl_803E48A4;
extern f32 lbl_803E48A8;
extern f32 lbl_803DBEF0;

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
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                    midVel * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + ((DIMwooddoorUpdateFallingDebrisState*)
                extra)->rotZRate * 10;
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + ((DIMwooddoorUpdateFallingDebrisState*)
                extra)->rotYRate * 10;
            *(s16*)obj = *(s16*)obj + ((DIMwooddoorUpdateFallingDebrisState*)extra)->rotXRate * 10;
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (hitState != NULL)
            {
                int* vol;
                ObjHits_SetHitVolumeSlot(obj, 5, ((DIMwooddoorUpdateFallingDebrisState*)extra)->hitVolumeSlot, 0);
                vol = (int*)hitState->lastHitObject;
                if (vol != NULL && vol != *(int**)extra)
                {
                    ObjHitbox_SetSphereRadius(obj, ((DIMwooddoorUpdateFallingDebrisState*)extra)->hitboxRadius);
                    spawnExplosion(obj, lbl_803E48A0, 2, 1, 0, 1, 1, 1, 0);
                    ((GameObject*)obj)->unkF4 = 1180;
                    *(s8*)&((DIMwooddoorUpdateFallingDebrisState*)extra)->state = DIMWOODDOOR_DEBRIS_STATE_EXPLODED;
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
            if ((GameBit_Get(2142) != 0 && GameBit_Get(3117) == 0) ||
                (GameBit_Get(2164) != 0 && GameBit_Get(3118) == 0))
            {
                ((GameObject*)obj)->unkF4 = 1200;
            }
            if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
            {
                ObjHitbox_SetSphereRadius(obj, ((DIMwooddoorUpdateFallingDebrisState*)extra)->hitboxRadius);
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
        Obj_FreeObject(obj);
    }
    else if (((DIMwooddoorUpdateFallingDebrisState*)extra)->unk7 != 0)
    {
        *(s8*)&((DIMwooddoorUpdateFallingDebrisState*)extra)->unk7 = 0;
    }
}

/* dimicewall_update: on shatter, emit two snow particle bursts and latch the
 * gamebit; otherwise let Tricky push through it. */
