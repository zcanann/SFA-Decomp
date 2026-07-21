/* DLL 0x0117 - appleontree / groundAnimator group. TU: 0x8017D818-0x8017E1A0. */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/objfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/dll/groundAnimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/obj_message.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/dll/baddie_state.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/track_dolphin_api.h"
#include "main/objhits.h"
#include "main/dll/dll_00FC_babycloudrunner.h"
#include "main/dll/dll_0117_appleontree.h"
#include "main/dll/player_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"

typedef struct AppleontreeObjectDef
{
    ObjPlacement head; /* 0x00 */
    u32 unk18;
    u16 duration;
    u16 elapsed;
    u8 stage0Frac;
    u8 stage1Frac;
    u8 stage2Frac;
    u8 stage3Frac;
    u8 unk24;
    s8 unk25;
    s16 gameBit;
} AppleontreeObjectDef;

/* AppleOnTree_update animState machine: an apple's lifecycle from hanging on
 * the tree through falling, resting, being knocked loose, and despawning. */
#define APPLEONTREE_STATE_GROWING 0 /* unripe, hanging; scales up toward ripe */
#define APPLEONTREE_STATE_RIPE    1 /* ripe, swaying; ready to drop */
#define APPLEONTREE_STATE_FALLING 2 /* dropping from branch to ground */
#define APPLEONTREE_STATE_LANDED  3 /* settled on the ground, collectable */
#define APPLEONTREE_STATE_KNOCKED 4 /* knocked loose, bouncing/rolling physics */
#define APPLEONTREE_STATE_BURST   5 /* fx-burst despawn (no fade) */
#define APPLEONTREE_STATE_FADEOUT 6 /* alpha fade-out despawn */

/* burst-splat particle spawned 8x when the apple enters APPLEONTREE_STATE_BURST */
#define APPLEONTREE_PARTFX_BURST 0x55a

#define APPLEONTREE_MSG_IN_RANGE 0x7000a /* sent to player when grab is offered */
#define APPLEONTREE_MSG_PICKUP   0x7000b /* player collected: restore health + burst */

extern f32 lbl_803E37C8;
extern f32 gAppleOnTreePickupXZRange;
extern f32 gAppleOnTreePickupRange;
extern f32 lbl_803E37D4;
extern f32 lbl_803E37D8;
extern f32 lbl_803E37DC;
extern f32 lbl_803E37E0;
extern f32 lbl_803E37E4;
extern f32 lbl_803E37E8;
extern f32 lbl_803E37F4;
extern f32 lbl_803E37F8;
extern f32 lbl_803E37FC;
extern f32 lbl_803E3800;
extern const f32 lbl_803E3828;
extern f32 lbl_803E382C;
extern f32 lbl_803E3830;
extern f32 lbl_803E3834;
extern f32 lbl_803E3838;
extern f32 lbl_803E37CC;
extern f32 lbl_803E37D0;
extern f32 lbl_803E3804;
extern f32 lbl_803E3808;
extern f32 lbl_803E380C;
extern f32 lbl_803E3810;
extern f32 lbl_803E3814;
extern f32 lbl_803E3818;

void appleontree_handleCollectableHit(GameObject* obj);

ObjectDescriptor13 gAppleOnTreeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)AppleOnTree_init,
    (ObjectDescriptorCallback)AppleOnTree_update,
    0,
    (ObjectDescriptorCallback)AppleOnTree_render,
    (ObjectDescriptorCallback)AppleOnTree_free,
    0,
    AppleOnTree_getExtraSize,
    (ObjectDescriptorCallback)AppleOnTree_setScale,
    (ObjectDescriptorCallback)AppleOnTree_setPosition,
    (ObjectDescriptorCallback)AppleOnTree_modelMtxFn,
};


void AppleOnTree_setPosition(GameObject* obj, float* pos)
{
    AppleOnTreeState* state = obj->extra;

    if (state->animState == APPLEONTREE_STATE_KNOCKED)
    {
        return;
    }
    if (state->animState == APPLEONTREE_STATE_BURST)
    {
        return;
    }
    if (state->animState == APPLEONTREE_STATE_FADEOUT)
    {
        return;
    }
    obj->anim.localPosX = pos[0];
    obj->anim.localPosY = pos[1];
    obj->anim.localPosZ = pos[2];
}

static inline void appleontree_markFallen(GameObject* obj)
{
    int state = *(int*)&(obj)->extra;
    if (((obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        Obj_FreeObject(obj);
    }
    else
    {
        if ((obj)->anim.hitReactState != NULL)
        {
            ObjHits_DisableObject(obj);
        }
        ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 2);
    }
}

void appleontree_knockLoose(GameObject* obj, int msg)
{
    int state = *(int*)&obj->extra;
    int v;

    switch (msg)
    {
    case 0:
        v = 2;
        break;
    case 1:
        v = 2;
        break;
    case 2:
        v = 2;
        break;
    default:
        v = 0;
        break;
    }
    ((AppleOnTreeState*)state)->healthRestore = v;
    ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_KNOCKED;
    ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
    ((AppleOnTreeState*)state)->flightTime = timeDelta;
    ((AppleOnTreeState*)state)->rotX = randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotY = randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotZ = 0x2000;

    if (fn_80065684(obj, obj->anim.localPosX, obj->anim.localPosY,
                    obj->anim.localPosZ, (f32*)(state + 0x30), 0) == 0)
    {
        appleontree_markFallen(obj);
    }
    else
    {
        f32 m = ((AppleOnTreeState*)state)->gravity;
        f32 g = lbl_803E37D8 * m;
        f32 q = sqrtf(-(g * ((AppleOnTreeState*)state)->dropHeight - lbl_803E37D4));
        f32 t = lbl_803E37DC * m;
        f32 r;

        if (t >= lbl_803E37D4)
        {
            r = t;
        }
        else
        {
            r = -t;
        }
        if (r <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r2;
            r = (lbl_803E37E4 - q) / t;
            r2 = (lbl_803E37E4 + q) / t;
            r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
        }
        ((AppleOnTreeState*)state)->totalFlightTime = r;

        if (((AppleOnTreeState*)state)->velY < lbl_803E37D4)
        {
            ((AppleOnTreeState*)state)->dropHeight =
                -(lbl_803E37D8 * ((AppleOnTreeState*)state)->fallScale - ((AppleOnTreeState*)state)->dropHeight);
        }
        else
        {
            ((AppleOnTreeState*)state)->dropHeight = lbl_803E37E8 * (lbl_803E37D8 * ((AppleOnTreeState*)state)->fallScale) +
                                                     ((AppleOnTreeState*)state)->dropHeight;
        }

        if (((AppleOnTreeState*)state)->dropHeight <= lbl_803E37D4)
        {
            state = *(int*)&obj->extra;
            if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                if (obj->anim.hitReactState != NULL)
                {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 2);
            }
        }
        else
        {
            ((AppleOnTreeState*)state)->posY = obj->anim.localPosY;
            ((AppleOnTreeState*)state)->splashPosY =
                obj->anim.localPosY - ((AppleOnTreeState*)state)->dropHeight;
            if (obj->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            Sfx_PlayFromObject((int)obj, SFXTRIG_en_tranch_6);
        }
    }
}

/* appleontree_handleCollectableHit: ground-animator collectable hit handler. When player is in
 * range, either send a trigger event (first contact) or apply healing +
 * particle FX + sfx + free-or-disable. */
void appleontree_handleCollectableHit(GameObject* obj)
{
    int state = *(int*)&obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    AppleOnTreeState* s = (AppleOnTreeState*)state;

    if (!(Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < gAppleOnTreePickupXZRange))
        return;
    if (!(Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) < gAppleOnTreePickupRange))
        return;

    if (mainGetBit(GAMEBIT_SawApple) == 0)
    {
        (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
        s->triggerGameBit = -1;
        s->pickupMsgValue = 0;
        s->unk60 = lbl_803E37C8;
        ObjMsg_SendToObject(player, APPLEONTREE_MSG_IN_RANGE, obj, state + 0x5c);
        mainSetBits(GAMEBIT_SawApple, 1);
        s->flags = (u8)(s->flags | 4);
    }
    else
    {
        playerAddHealth(player, s->healthRestore);
        itemPickupDoParticleFx(obj, lbl_803E37C8, 0xff, 0x28);
        Sfx_PlayFromObject((int)obj, SFXTRIG_cam90_c);
        appleontree_markFallen(obj);
    }
}

u8 AppleOnTree_modelMtxFn(int* obj)
{
    return ((AppleOnTreeState*)(int*)((GameObject*)obj)->extra)->animState;
}

void AppleOnTree_setScale(void)
{
}

int AppleOnTree_getExtraSize(void)
{
    return 0x64;
}

void AppleOnTree_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void AppleOnTree_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    AppleOnTreeState* inner = ((GameObject*)obj)->extra;
    if ((inner->flags & 2) == 0)
    {
        objRenderModelAndHitVolumes((GameObject*)obj, p1, p2, p3, p4, lbl_803E37C8);
    }
}

int appleontree_bounceGroundStep(GameObject* obj, int state, f32 y)
{
    AppleOnTreeState* s = (AppleOnTreeState*)state;
    f32 zero = lbl_803E37D4;
    f32 m = s->gravity;

    if (zero != m)
    {
        if (s->dropHeight - (s->posY - y) < zero)
        {
            f32 b = s->bounceVel;
            if (zero == b)
            {
                f32 g = lbl_803E37D8 * m;
                f32 q = sqrtf(b * b - g * s->dropHeight);
                f32 t = lbl_803E37DC * m;
                f32 r;

                if (t >= lbl_803E37D4)
                {
                    r = t;
                }
                else
                {
                    r = -t;
                }
                if (r <= lbl_803E37E0)
                {
                    r = lbl_803E37C8;
                }
                else
                {
                    f32 r2;
                    f32 nb;
                    nb = -b;
                    r = (nb - q) / t;
                    r2 = (nb + q) / t;
                    r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
                }
                s->flightTime = s->flightTime - r;
                s->posY =
                    s->posY - s->dropHeight;
                s->dropHeight = lbl_803E37D4;
                (obj)->anim.localPosY = s->posY;
                (obj)->anim.rotX = s->rotX;
                (obj)->anim.rotY = s->rotY;
                (obj)->anim.rotZ = s->rotZ;
                s->bounceVel = -s->velY;
                if ((s->flags & 8) == 0)
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_pk_fruit_lands);
                    s->flags = (u8)(s->flags | 8);
                }
                return 1;
            }
            else if (b < lbl_803E37F4)
            {
                (obj)->anim.localPosY = s->posY;
                s->gravity = zero;
                s->bounceVel = zero;
                return 1;
            }
            else
            {
                f32 g;
                f32 q;
                f32 t;
                f32 r;
                m = m + s->extraAccel;
                g = lbl_803E37D8 * m;
                q = sqrtf(b * b - g * s->dropHeight);
                t = lbl_803E37DC * m;

                if (t >= lbl_803E37D4)
                {
                    r = t;
                }
                else
                {
                    r = -t;
                }
                if (r <= lbl_803E37E0)
                {
                    r = lbl_803E37C8;
                }
                else
                {
                    f32 r2;
                    f32 nb;
                    nb = -b;
                    r = (nb - q) / t;
                    r2 = (nb + q) / t;
                    r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
                }
                s->flightTime = s->flightTime - r;
                (obj)->anim.localPosY = s->posY;
                s->bounceVel = s->bounceVel * lbl_803E37F8;
                return 0;
            }
        }
        else
        {
            (obj)->anim.localPosY = y;
            return 1;
        }
    }
    return 1;
}

int appleontree_bounceWaterStep(GameObject* obj, int state, f32 y)
{
    AppleOnTreeState* s = (AppleOnTreeState*)state;
    if (lbl_803E37D4 == s->extraAccel)
    {
        if (s->dropHeight - (s->posY - y) <= lbl_803E37D4)
        {
            f32 b;
            f32 m = s->gravity;
            f32 g;
            f32 q;
            f32 t;
            f32 a;
            f32 r;
            f32 rad;
            b = s->bounceVel;
            g = lbl_803E37D8 * m;
            q = sqrtf(b * b - g * s->dropHeight);
            t = lbl_803E37DC * m;

            if (t >= lbl_803E37D4)
            {
                a = t;
            }
            else
            {
                a = -t;
            }
            if (a <= lbl_803E37E0)
            {
                r = lbl_803E37C8;
            }
            else
            {
                f32 r2;
                f32 nb;
                nb = -b;
                r = (nb - q) / t;
                r2 = (nb + q) / t;
                r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
            }
            s->flightTime = s->flightTime - r;
            s->posY =
                s->posY - s->dropHeight;
            rad = lbl_803E37D4;
            s->dropHeight = rad;
            obj->anim.localPosY = s->posY;
            obj->anim.rotX = s->rotX;
            obj->anim.rotY = s->rotY;
            obj->anim.rotZ = s->rotZ;
            {
                f32 g2 = lbl_803E37DC * s->gravity;
                s->bounceVel = g2 * r + s->bounceVel;
            }
            s->extraAccel = s->velY;
            (*gWaterfxInterface)
                ->spawnSplashBurst((void*)obj, obj->anim.localPosX, s->splashPosY,
                                   obj->anim.localPosZ, rad);
            return 0;
        }
        else
        {
            obj->anim.localPosY = y;
            return 1;
        }
    }
    else if (y - s->posY >= lbl_803E37D4)
    {
        f32 b;
        f32 m = s->gravity + s->extraAccel;
        f32 g;
        f32 q;
        f32 t;
        f32 r;
        b = s->bounceVel;
        g = lbl_803E37D8 * m;
        q = sqrtf(b * b - g * s->dropHeight);
        t = lbl_803E37DC * m;

        if (t >= lbl_803E37D4)
        {
            r = t;
        }
        else
        {
            r = -t;
        }
        if (r <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r2;
            f32 nb;
            nb = -b;
            r = (nb - q) / t;
            r2 = (nb + q) / t;
            r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
        }
        s->flightTime = s->flightTime - r;
        obj->anim.localPosY = s->posY;
        s->extraAccel = lbl_803E37FC;
        s->bounceVel = lbl_803E3800;
        return 0;
    }
    else
    {
        obj->anim.localPosY = y;
        return 1;
    }
}

void AppleOnTree_update(int objArg)
{
    float fa;
    int obj;
    int val;
    u32* modelIdxPtrW;
    u32 bitVal;
    int* modelIdxPtr;
    int state;
    int placement;
    int i;
    f32 fc;
    f32 fb;
    f32 fd;
    f32 frac;
    f32 sunTime;
    int msg;

    obj = objArg;
    state = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    msg = 0;
    if ((((AppleOnTreeState*)state)->flags & 4) != 0)
    {
        while (val = ObjMsg_Pop((void*)obj, (u32*)&msg, 0x0, 0x0), val != 0)
        {
            switch (msg)
            {
            case APPLEONTREE_MSG_PICKUP:
            {
                playerAddHealth(Obj_GetPlayerObject(), (int)((AppleOnTreeState*)state)->healthRestore);
                itemPickupDoParticleFx((void*)obj, lbl_803E37C8, 0xff, 0x28);
                Sfx_PlayFromObject((int)obj, SFXTRIG_cam90_c);
                val = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
                {
                    Obj_FreeObject((GameObject*)obj);
                }
                else
                {
                    if (((GameObject*)obj)->anim.hitReactState != NULL)
                    {
                        ObjHits_DisableObject((GameObject*)obj);
                    }
                    ((AppleOnTreeState*)val)->flags = ((AppleOnTreeState*)val)->flags | 2;
                }
                ((AppleOnTreeState*)state)->flags = ((AppleOnTreeState*)state)->flags & ~4;
            }
            }
        }
        if ((((AppleOnTreeState*)state)->flags & 4) != 0)
            return;
    }
    if ((((AppleOnTreeState*)state)->flags & 2) == 0)
    {
        ((AppleOnTreeState*)state)->elapsedTime = ((AppleOnTreeState*)state)->elapsedTime + timeDelta;
        fa = ((AppleOnTreeState*)state)->flightTime;
        ((AppleOnTreeState*)state)->flightTime = fa + timeDelta;
        fb = ((AppleOnTreeState*)state)->elapsedTime;
        frac = fb / ((AppleOnTreeState*)state)->phaseDuration;
        switch (((AppleOnTreeState*)state)->animState)
        {
        case APPLEONTREE_STATE_GROWING:
            val = ObjHits_GetPriorityHit((GameObject*)(obj), 0x0, 0x0, 0x0);
            if ((val != 0) || ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                                (bitVal = mainGetBit((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
            {
                int burstIndex;
                state = *(int*)&((GameObject*)obj)->extra;
                burstIndex = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, APPLEONTREE_PARTFX_BURST, NULL, 2, -1, NULL);
                    burstIndex = burstIndex + 1;
                } while (burstIndex < 8);
                if (((GameObject*)obj)->anim.hitReactState != NULL)
                {
                    ObjHits_DisableObject((GameObject*)obj);
                }
                ((AppleOnTreeState*)state)->flags = ((AppleOnTreeState*)state)->flags | 2;
                ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_BURST;
            }
            else
            {
                if (frac > ((AppleOnTreeState*)state)->stageEnd0)
                {
                    ((GameObject*)obj)->anim.rootMotionScale =
                        ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                    ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_RIPE;
                }
                else
                {
                    fb = ((AppleOnTreeState*)((GameObject*)obj)->extra)->elapsedTime /
                         ((AppleOnTreeState*)((GameObject*)obj)->extra)->phaseDuration;
                    fb = fb * (lbl_803E37C8 / ((AppleOnTreeState*)((GameObject*)obj)->extra)->stageEnd0);
                    ((GameObject*)obj)->anim.rootMotionScale =
                        ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * fb;
                }
            }
            break;
        case APPLEONTREE_STATE_RIPE:
            val = ObjHits_GetPriorityHit((GameObject*)(obj), 0x0, 0x0, 0x0);
            if ((val != 0) || ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                                (bitVal = mainGetBit((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
            {
                state = *(int*)&((GameObject*)obj)->extra;
                i = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, APPLEONTREE_PARTFX_BURST, NULL, 2, -1, NULL);
                    i = i + 1;
                } while (i < 8);
                if (((GameObject*)obj)->anim.hitReactState != NULL)
                {
                    ObjHits_DisableObject((GameObject*)obj);
                }
                ((AppleOnTreeState*)state)->flags = ((AppleOnTreeState*)state)->flags | 2;
                ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_BURST;
            }
            else
            {
                if (frac > ((AppleOnTreeState*)state)->stageEnd1)
                {
                    i = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, APPLEONTREE_PARTFX_BURST, NULL, 2, -1, NULL);
                        i = i + 1;
                    } while (i < 8);
                    ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_FALLING;
                }
                else
                {
                    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
                    {
                        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E3804, timeDelta,
                                                                                    0);
                    }
                    else
                    {
                        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E3808, timeDelta,
                                                                                    0);
                    }
                }
            }
            break;
        case APPLEONTREE_STATE_FALLING:
            if (frac > ((AppleOnTreeState*)state)->stageEnd2)
            {
                val = *(int*)&((GameObject*)obj)->extra;
                modelIdxPtrW = (u32*)objFindTexture((GameObject*)obj, 0, 0);
                *modelIdxPtrW = 0;
                ((AppleOnTreeState*)val)->fallScale = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale =
                    ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex((GameObject*)obj, 1);
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_LANDED;
            }
            else
            {
                f32 fallProgress;
                val = *(int*)&((GameObject*)obj)->extra;
                fallProgress = -(((AppleOnTreeState*)val)->phaseDuration * ((AppleOnTreeState*)val)->stageEnd1 -
                                 ((AppleOnTreeState*)val)->elapsedTime) /
                               (((AppleOnTreeState*)val)->phaseDuration *
                                (((AppleOnTreeState*)val)->stageEnd2 - ((AppleOnTreeState*)val)->stageEnd1));
                fa = ((AppleOnTreeState*)val)->elapsedTime;
                fc = fa * fa;
                fc = fc * fc;
                state = 0x100 - (int)((fc * fc) / ((AppleOnTreeState*)val)->fallBlendDivisor);
                modelIdxPtr = (int*)objFindTexture((GameObject*)obj, 0, 0);
                *modelIdxPtr = state;
                ((AppleOnTreeState*)val)->fallScale = lbl_803E37D0 * fallProgress + lbl_803E37CC;
                ((GameObject*)obj)->anim.rootMotionScale =
                    ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * ((AppleOnTreeState*)val)->fallScale;
                Obj_SetActiveModelIndex((GameObject*)obj, 1);
            }
            state = ObjHits_GetPriorityHit((GameObject*)obj, 0x0, 0x0, 0x0);
            if ((state != 0) ||
                ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                  (bitVal = mainGetBit((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
            {
                appleontree_knockLoose((GameObject*)obj, 1);
            }
            break;
        case APPLEONTREE_STATE_LANDED:
            ((AppleOnTreeState*)state)->elapsedTime = fb - timeDelta;
            if (frac > ((AppleOnTreeState*)state)->stageEnd3)
            {
                appleontree_knockLoose((GameObject*)obj, 0);
            }
            else
            {
                state = ObjHits_GetPriorityHit((GameObject*)obj, 0x0, 0x0, 0x0);
                if ((state != 0) ||
                    ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                      (bitVal = mainGetBit((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
                {
                    appleontree_knockLoose((GameObject*)obj, 2);
                }
            }
            break;
        case APPLEONTREE_STATE_KNOCKED:
            if (frac > ((AppleOnTreeState*)state)->fadeThreshold)
            {
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_FADEOUT;
                ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
            }
            else
            {
                int iteration;
                placement = 0;
                iteration = 0;
                fd = lbl_803E37D4;
                while (placement == 0)
                {
                    f32 t = ((AppleOnTreeState*)state)->flightTime;
                    fb = t * (((AppleOnTreeState*)state)->gravity + ((AppleOnTreeState*)state)->extraAccel);
                    fc = t * fb + (((AppleOnTreeState*)state)->bounceVel * t + ((AppleOnTreeState*)state)->posY);
                    if (((AppleOnTreeState*)state)->velY > fd)
                    {
                        placement = appleontree_bounceWaterStep((GameObject*)(obj), state, fc);
                    }
                    else
                    {
                        placement = appleontree_bounceGroundStep((GameObject*)(obj), state, fc);
                    }
                    iteration = iteration + 1;
                    if (!((iteration == 100) || (iteration != 0x66)))
                        break;
                }
                if (lbl_803E37D4 != ((AppleOnTreeState*)state)->dropHeight)
                {
                    fb = ((AppleOnTreeState*)state)->flightTime / ((AppleOnTreeState*)state)->totalFlightTime;
                    ((GameObject*)obj)->anim.rotX = (f32)((AppleOnTreeState*)state)->rotX * fb;
                    ((GameObject*)obj)->anim.rotY = (f32)((AppleOnTreeState*)state)->rotY * fb;
                    ((GameObject*)obj)->anim.rotZ = (f32)((AppleOnTreeState*)state)->rotZ * fb;
                }
                modelIdxPtr = (int*)objFindTexture((GameObject*)obj, 0, 0);
                *modelIdxPtr = (int)(lbl_803E380C * frac);
                appleontree_handleCollectableHit((GameObject*)obj);
            }
            break;
        case APPLEONTREE_STATE_BURST:
            if (fb > lbl_803E3810)
            {
                placement = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
                {
                    Obj_FreeObject((GameObject*)obj);
                }
                else
                {
                    if (((GameObject*)obj)->anim.hitReactState != NULL)
                    {
                        ObjHits_DisableObject((GameObject*)obj);
                    }
                    ((AppleOnTreeState*)placement)->flags = ((AppleOnTreeState*)placement)->flags | 2;
                }
            }
            break;
        case APPLEONTREE_STATE_FADEOUT:
            frac = lbl_803E3814;
            if (fb > frac)
            {
                placement = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
                {
                    Obj_FreeObject((GameObject*)obj);
                }
                else
                {
                    if (((GameObject*)obj)->anim.hitReactState != NULL)
                    {
                        ObjHits_DisableObject((GameObject*)obj);
                    }
                    ((AppleOnTreeState*)placement)->flags = ((AppleOnTreeState*)placement)->flags | 2;
                }
            }
            else
            {
                placement = (int)(lbl_803E3818 * fb / frac);
                ((GameObject*)obj)->anim.alpha = 0xff - placement;
                appleontree_handleCollectableHit((GameObject*)obj);
            }
        }
    }
}

void AppleOnTree_init(int obj, int def)
{
    int state;
    f32 zeroScale;
    f32 timeScale;
    f32 progress;
    int eventBit;
    ObjTextureRuntimeSlot* texture;

    state = *(int*)&((GameObject*)obj)->extra;

    ((AppleOnTreeState*)state)->unk00 = ((AppleontreeObjectDef*)def)->unk18;
    ((AppleOnTreeState*)state)->phaseDuration = (f32)((AppleontreeObjectDef*)def)->duration;
    ((AppleOnTreeState*)state)->elapsedTime = (f32)((AppleontreeObjectDef*)def)->elapsed;
    {
        ((AppleOnTreeState*)state)->stageEnd0 = (f32)((AppleontreeObjectDef*)def)->stage0Frac / lbl_803E3828;
        progress = (f32)((AppleontreeObjectDef*)def)->stage1Frac / lbl_803E3828;
        ((AppleOnTreeState*)state)->stageEnd1 = progress + ((AppleOnTreeState*)state)->stageEnd0;
        progress = (f32)((AppleontreeObjectDef*)def)->stage2Frac / lbl_803E3828;
        ((AppleOnTreeState*)state)->stageEnd2 = progress + ((AppleOnTreeState*)state)->stageEnd1;
        progress = (f32)((AppleontreeObjectDef*)def)->stage3Frac / lbl_803E3828;
        ((AppleOnTreeState*)state)->stageEnd3 = progress + ((AppleOnTreeState*)state)->stageEnd2;
        ((AppleOnTreeState*)state)->fadeThreshold = (f32)((AppleontreeObjectDef*)def)->unk24 / lbl_803E3828;
        ((AppleOnTreeState*)state)->velY = (f32)((AppleontreeObjectDef*)def)->unk25 / lbl_803E3828;
        ((AppleOnTreeState*)state)->velY = ((AppleOnTreeState*)state)->velY * lbl_803E37DC;
        ((AppleOnTreeState*)state)->fallScale = lbl_803E37C8;
        ((AppleOnTreeState*)state)->healthRestore = 0;
        zeroScale = lbl_803E37D4;
        ((AppleOnTreeState*)state)->extraAccel = zeroScale;
        ((AppleOnTreeState*)state)->gravity = lbl_803E382C;
        ((AppleOnTreeState*)state)->bounceVel = zeroScale;

        timeScale = ((AppleOnTreeState*)state)->phaseDuration * ((AppleOnTreeState*)state)->stageEnd2;
        timeScale *= timeScale;
        timeScale *= timeScale;
        zeroScale = timeScale * timeScale;
        ((AppleOnTreeState*)state)->fallBlendDivisor = zeroScale * lbl_803E3830;

        ((GameObject*)obj)->anim.rotX = randomGetRange(-0x8000, 0x7fff);
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3834;
        Obj_SetActiveModelIndex((GameObject*)obj, 0);

        eventBit = ((AppleontreeObjectDef*)def)->gameBit;
        if ((eventBit != -1) && (mainGetBit(eventBit) != 0))
        {
            ((AppleOnTreeState*)state)->elapsedTime = lbl_803E3838;
            ((AppleOnTreeState*)state)->animState = 6;
        }
        else
        {
            progress = ((AppleOnTreeState*)state)->elapsedTime / ((AppleOnTreeState*)state)->phaseDuration;
            if (progress < ((AppleOnTreeState*)state)->stageEnd0)
            {
                ((AppleOnTreeState*)state)->animState = 0;
            }
            else if (progress < ((AppleOnTreeState*)state)->stageEnd1)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                ((AppleOnTreeState*)state)->animState = 1;
            }
            else if (progress < ((AppleOnTreeState*)state)->stageEnd2)
            {
                ((AppleOnTreeState*)state)->animState = 2;
            }
            else
            {
                int reread = *(int*)&((GameObject*)obj)->extra;
                texture = objFindTexture((GameObject*)obj, 0, 0);
                texture->textureId = 0;
                ((AppleOnTreeState*)reread)->fallScale = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex((GameObject*)obj, 1);
                ((AppleOnTreeState*)state)->animState = 3;
            }
        }

        ObjMsg_AllocQueue((void*)obj, 2);
    }
}


ObjectDescriptor gDllFCObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};
