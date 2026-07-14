/*
 * pollenfragment (DLL 0x00DA) - the homing pollen-cloud projectile/fragment
 * spawned by the pollen object. Each fragment picks one of five
 * PollenFragmentConfig presets by its pollen type (0..5), spawns a burst of
 * particle fx and a loop sfx on init, then per-frame steers toward the
 * nearest object in its target group, applies velocity damping/gravity,
 * optionally smooth-turns to face its velocity (or free-spins for the
 * 0x482 fragment object), and bursts (explosion fx + sfx) on contact with a
 * non-owner object. Timed variants fade their alpha out and self-free.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "dolphin/mtx/vec.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/maketex_timer_api.h"
#include "main/object_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/objseq_api.h"
#include "main/vecmath.h"
#include "main/dll/dll_00DA_pollenfragment_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/objfx.h"

#define s16toFloatLegacy(timer, duration) \
    ((void (*)(void*, int))s16toFloat)((timer), (duration))
#define storeZeroToFloatParamLegacy(timer) \
    ((void (*)(void*))storeZeroToFloatParam)((timer))
#define timerCountDownLegacy(timer) \
    ((int (*)(int))timerCountDown)((int)(timer))

typedef struct
{
    s16 unk00;         /* 0x00 */
    s16 loopSfx;       /* 0x02 */
    s16 explodeSfx;    /* 0x04 */
    s16 unk06;         /* 0x06 */
    s16 burstFx;       /* 0x08 */
    s16 auraFx;        /* 0x0A */
    s16 unk0C;         /* 0x0C */
    s16 unk0E;         /* 0x0E */
    s16 targetGroup;   /* 0x10 */
    u8 noVertical : 1; /* 0x12 bit 7 */
    u8 timed : 1;      /* 0x12 bit 6 */
    u8 smoothTurn : 1; /* 0x12 bit 5 */
    u8 usePath : 1;    /* 0x12 bit 4 */
} PollenFragmentDef;

typedef struct PollenFragmentExtra
{
    int ownerObj; /* 0x00: owner captured on first update */
    f32 speed;    /* 0x04: steering speed factor */
    f32 timer;    /* 0x08: lifetime/strength timer */
    union {
        struct {
            f32 velX; /* 0x0C */
            f32 velY; /* 0x10 */
            f32 velZ; /* 0x14 */
        };
        Vec velocity;
    };
    u8 unk18[4];
    PollenFragmentDef* def; /* 0x1C */
    f32 deathTimer;         /* 0x20 */
    f32 lifetimeTimer;      /* 0x24 */
} PollenFragmentExtra;

#define POLLENFRAGMENT_HIT_VOLUME_SLOT 0x16

extern f32 lbl_803E3198;
extern f32 lbl_803E319C;
extern f32 lbl_803E3158;
extern f32 lbl_803DBD48;
extern f32 lbl_803DBD4C;
extern const f32 lbl_803E315C;
extern f32 lbl_803E3160;
extern const f32 lbl_803E3164;
extern f32 lbl_803E3168;
extern f32 lbl_803E316C;
extern f32 lbl_803E3170;
extern f32 lbl_803E3174;
extern f32 lbl_803E3178;
extern f32 lbl_803E317C;
extern f32 lbl_803E3180;

extern int Sfx_PlayFromObjectLimited(int obj, int sfxId, int maxCount);

void pollenfragment_init(GameObject* obj, int config)
{
    s8 pollenType;
    u32 randomValue;
    int spawnCount;
    u32* state;

    state = *(u32**)&(obj)->extra;
    if (*(char*)(config + 0x19) == '\x01')
    {
        *(float*)&((XyzAnimatorState*)state)->unk8 = lbl_803E3198;
    }
    else
    {
        randomValue = randomGetRange(0xb4, 300);
        *(float*)&((XyzAnimatorState*)state)->unk8 = (float)(int)randomValue;
    }
    pollenType = *(s8*)(config + 0x19);
    pollenType = (pollenType < 0) ? 0 : ((pollenType > 5u) ? 5 : pollenType);
    *(s8*)(config + 0x19) = pollenType;
    state[7] = (u32)lbl_8032059C[*(char*)(config + 0x19)];
    if ((int)*(short*)state[7] != 0)
    {
        Sfx_PlayFromObjectLimited((int)obj, (int)*(short*)state[7] & 0xffff, 3);
    }
    spawnCount = 4;
    do
    {
        (*gPartfxInterface)->spawnObject((void*)obj, (int)*(short*)(state[7] + 6), NULL, 1, -1, NULL);
    } while (spawnCount-- != 0);
    if (!((PollenFragmentDef*)state[7])->timed)
    {
        *(float*)&((XyzAnimatorState*)state)->unk8 = lbl_803E319C;
    }
    ObjHits_SetTargetMask(obj, 4);
    ((XyzAnimatorState*)state)->unk18 = 0;
    *(f32*)&((XyzAnimatorState*)state)->vertexCount = *(f32*)(state[7] + 0xc);
    ((XyzAnimatorState*)state)->rowCount = 0;
    s16toFloatLegacy(state + 9, 0xe10);
    storeZeroToFloatParamLegacy(state + 8);
}

void pollenfragment_release(void)
{
}

void pollenfragment_initialise(void)
{
}

void pollenfragment_free(GameObject* obj)
{
    int* inner = obj->extra;
    if ((void*)inner[6] != NULL)
    {
        ModelLightStruct_free((void*)inner[6]);
        inner[6] = 0;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

int pollenfragment_getExtraSize(void)
{
    return 0x28;
}
int pollenfragment_getObjectTypeId(void)
{
    return 0x0;
}

void pollenfragment_render(int* obj, int p2, int p3, int p4, int p5)
{
    PollenFragmentExtra* state = ((GameObject*)obj)->extra;
    if (fn_80080150(&state->deathTimer) != 0)
        return;
    ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E3158);
}

void pollenfragment_hitDetect(GameObject* obj)
{
    u8* extra;
    int hitType;
    int hitObject;

    extra = *(u8**)&(obj)->extra;
    if (fn_80080150(&((PollenFragmentExtra*)extra)->deathTimer) == 0)
    {
        hitType = ObjHits_GetPriorityHit(obj, &hitObject, 0, 0);
        if (hitType == 0xe || hitType == 0xf)
        {
            if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
            {
                spawnExplosionLegacy((int)obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited((int)obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
            }
            ObjHits_DisableObject((u32)obj);
            s16toFloatLegacy(extra + 0x20, 0x78);
        }
        if (((ObjHitsPriorityState*)(obj)->anim.hitReactState)->contactFlags != 0)
        {
            ObjHits_DisableObject((u32)obj);
            ((PollenFragmentExtra*)extra)->timer = lbl_803E3160;
            if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
            {
                spawnExplosionLegacy((int)obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited((int)obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
            }
            s16toFloatLegacy(extra + 0x20, 0x78);
        }
    }
}

#pragma opt_strength_reduction on
#pragma opt_common_subs on
void pollenfragment_update(int obj)
{
    u8* extra;
    u8* nearObj;
    PollenFragmentDef* def;
    void* hit;
    int i;
    f32 horizDamping;
    f32 t;
    Vec dir;
    Vec sc;
    Vec pos;

    extra = *(u8**)&((GameObject*)obj)->extra;
    if (getCurSeqNoInt() != 0)
    {
        Obj_FreeObject(obj);
        return;
    }
    if (fn_80080150(&((PollenFragmentExtra*)extra)->deathTimer) != 0)
    {
        if (timerCountDownLegacy(extra + 0x20) != 0)
        {
            Obj_FreeObject(obj);
        }
        return;
    }
    if (timerCountDownLegacy((int)extra + 0x24) != 0)
    {
        s16toFloatLegacy(extra + 0x20, 0x78);
    }
    if (*(void**)&((GameObject*)obj)->ownerObj != NULL)
    {
        ((PollenFragmentExtra*)extra)->ownerObj = *(int*)&((GameObject*)obj)->ownerObj;
        *(int*)&((GameObject*)obj)->ownerObj = 0;
    }
    if ((((PollenFragmentExtra*)extra)->def)->timed)
    {
        ((PollenFragmentExtra*)extra)->timer -= timeDelta;
        if (((PollenFragmentExtra*)extra)->timer <= lbl_803E3160)
        {
            if (((GameObject*)obj)->anim.alpha == 0xff)
            {
                i = 2;
                do
                {
                    (*gPartfxInterface)
                        ->spawnObject((void*)obj, (int)(((PollenFragmentExtra*)extra)->def)->burstFx, NULL, 1, -1,
                                      NULL);
                } while (i-- != 0);
            }
            ((PollenFragmentExtra*)extra)->timer = lbl_803E3160;
            if (((GameObject*)obj)->anim.alpha >= framesThisStep << 3)
            {
                ((GameObject*)obj)->anim.alpha -= framesThisStep << 3;
            }
            else
            {
                ((GameObject*)obj)->anim.alpha = 0;
                Obj_FreeObject(obj);
                return;
            }
        }
    }
    if ((((PollenFragmentExtra*)extra)->def)->auraFx != -1)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, (int)(((PollenFragmentExtra*)extra)->def)->auraFx, NULL, 1, -1, NULL);
    }
    nearObj = (u8*)ObjGroup_FindNearestObject((int)(((PollenFragmentExtra*)extra)->def)->targetGroup, (int)obj, 0);
    if (nearObj != NULL &&
        (!(def = ((PollenFragmentExtra*)extra)->def)->timed || ((PollenFragmentExtra*)extra)->timer < lbl_803E3164))
    {
        if (def->usePath)
        {
            ObjPath_GetPointWorldPosition((GameObject*)nearObj, 0, &pos.x, &pos.y, &pos.z, 0);
        }
        else
        {
            f32 prod;
            pos.x = ((GameObject*)nearObj)->anim.worldPosX;
            prod = ((GameObject*)nearObj)->anim.hitboxScale * ((GameObject*)nearObj)->anim.rootMotionScale;
            pos.y = prod * lbl_803E3168 + ((GameObject*)nearObj)->anim.worldPosY;
            pos.z = ((GameObject*)nearObj)->anim.worldPosZ;
        }
        PSVECSubtract(&pos, &((GameObject*)obj)->anim.worldPos, &dir);
        PSVECMag(&dir);
        PSVECNormalize(&dir, &dir);
        PSVECSubtract(&dir, &((PollenFragmentExtra*)extra)->velocity, &sc);
        ((PollenFragmentExtra*)extra)->velX = dir.x;
        ((PollenFragmentExtra*)extra)->velY = dir.y;
        ((PollenFragmentExtra*)extra)->velZ = dir.z;
        PSVECScale(&sc, &sc, lbl_803E315C);
        PSVECAdd(&dir, &sc, &dir);
        ((GameObject*)obj)->anim.velocityX =
            ((GameObject*)obj)->anim.velocityX +
            ((lbl_803E315C + ((PollenFragmentExtra*)extra)->timer) * (dir.x * ((PollenFragmentExtra*)extra)->speed)) /
                lbl_803E3164;
        ((GameObject*)obj)->anim.velocityZ =
            ((GameObject*)obj)->anim.velocityZ +
            ((lbl_803E315C + ((PollenFragmentExtra*)extra)->timer) * (dir.z * ((PollenFragmentExtra*)extra)->speed)) /
                lbl_803E3164;
        if (!(((PollenFragmentExtra*)extra)->def)->noVertical)
        {
            ((GameObject*)obj)->anim.velocityY =
                ((GameObject*)obj)->anim.velocityY + ((lbl_803E315C + ((PollenFragmentExtra*)extra)->timer) *
                                                      (lbl_803E316C * (dir.y * ((PollenFragmentExtra*)extra)->speed))) /
                                                         lbl_803E3164;
        }
    }
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (horizDamping = lbl_803E3170);
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * horizDamping;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E3174;
    if ((((PollenFragmentExtra*)extra)->def)->noVertical)
    {
        t = lbl_803E3178 * timeDelta;
        ((GameObject*)obj)->anim.velocityY =
            ((GameObject*)obj)->anim.velocityY - (t * ((PollenFragmentExtra*)extra)->timer) / lbl_803E317C;
    }
    if ((((PollenFragmentExtra*)extra)->def)->smoothTurn)
    {
        Obj_SmoothTurnAnglesTowardVelocity((GameObject*)obj, (const Vec3f*)(obj + 0x24), 10, lbl_803E3160,
                                           lbl_803E3158);
        ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + framesThisStep * 0x500;
    }
    else if (((GameObject*)obj)->anim.seqId == POLLEN_FRAGMENT_OBJECT_ID)
    {
        t = lbl_803E3180 * lbl_803DBD48;
        ((GameObject*)obj)->anim.rotX = t * (f32)(u32)framesThisStep + (f32)(int)((GameObject*)obj)->anim.rotX;
        ((GameObject*)obj)->anim.rotY =
            lbl_803DBD4C * (f32)(u32)framesThisStep + (f32)(int)((GameObject*)obj)->anim.rotY;
    }
    Sfx_KeepAliveLoopedObjectSound(obj, (u16)(((PollenFragmentExtra*)extra)->def)->loopSfx);
    objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, POLLENFRAGMENT_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject((u32)obj);
    hit = (void*)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (hit != NULL && ((GameObject*)hit)->anim.seqId != ((GameObject*)obj)->anim.seqId &&
        hit != *(void**)&((PollenFragmentExtra*)extra)->ownerObj)
    {
        ((PollenFragmentExtra*)extra)->timer = lbl_803E3160;
        ObjHits_DisableObject((u32)obj);
        if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
        {
            spawnExplosionLegacy(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
            Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
        }
        s16toFloatLegacy(extra + 0x20, 0x78);
    }
}
#pragma opt_strength_reduction reset
#pragma opt_common_subs reset
