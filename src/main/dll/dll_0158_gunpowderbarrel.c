/*
 * GunPowderBarrel (DLL 0x158) - carryable gunpowder barrel (+ MetalBarrel).
 *
 * The barrel registers with the carry interface (gCarryableInterface) so the
 * player can lift, carry, steal and throw it; gunpowderbarrel_update drives the
 * pickup/steal/toss state machine and the throw is launched via
 * gunpowderbarrel_launchAtTarget. When struck (or resting on a damage source)
 * the fuse is lit: gunpowderbarrel_update grows the hit radius each frame and,
 * after the fuse window (state->fuseFrames > 0x14), spawns the explosion and
 * either hands the barrel back to its owning generator (obj group 0x3a, matched
 * by placement link id) or removes it. seqId 0x754 selects the indestructible
 * cannon-range variant. gunpowderbarrel_updatePhysics applies gravity, velocity
 * clamps, the ground probe and landing/impact sfx.
 *
 * TU = 0x801A0B14..0x801A27B8 (helper group at the head, then the barrel
 * descriptor fns; physically emitted last so the helpers stay out-of-line bls).
 *
 * Mixed provenance: gunpowderbarrel_free and gunpowderbarrel_render are the
 * v1.1-shaped helper group; everything below the "Drift-recovery: v1.0" marker
 * is the v1.0 body. GunpowderBarrelState (extra) layout lives in
 * main/dll/DR/gunpowderbarrel_state.h.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/gunpowderbarrel_state.h"
#include "main/dll/player_motion.h"
#include "main/objlib.h"
#include "main/vecmath.h"
#include "main/dll/dll_0158_gunpowderbarrel.h"
#include "main/audio/sfx_trigger_ids.h"

/* seqId of the indestructible cannon-range barrel variant */
#define GUNPOWDERBARREL_SEQ_CANNONRANGE 0x754
/* object group of the barrel generators this barrel returns home to */
#define GUNPOWDERBARREL_OBJGROUP 0x3a

/* Barrel placement data block (obj group 0x3a link id at 0x1A). init reads
 * the respawn byte (respawnByte) and the return-home word (returnHome); the descriptor
 * fns match the barrel by generatorLinkId. unk1E is the adjacent placement
 * word other call sites reference raw. */
typedef struct GunpowderbarrelPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 respawnByte;
    s16 generatorLinkId;
    s16 returnHome;
    s16 unk1E;
} GunpowderbarrelPlacement;

extern u32* gCarryableInterface;
extern f32 lbl_803E42DC;
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 e);
extern int barrelgener_getLinkId();
extern void saveGame_saveObjectPos(int* obj);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void* getTrickyObject(void);
extern void trickyImpress(u8* obj);
extern void timer_clearManualFlags();
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern int findSurfaceInYRange(int* obj, f32 x, f32 top, f32 z, f32 bottom, f32* outY, int** outObj);


extern f32 timeDelta;
extern f32 lbl_803E42C0;
extern f32 lbl_803E42C4;
extern f32 lbl_803E4308;
extern f32 lbl_803E430C;
extern f32 lbl_803E4310;
extern f32 lbl_803E4314;
extern f32 lbl_803E4318;
extern f32 lbl_803E431C;
extern f32 lbl_803E4320;
extern f32 lbl_803DBE88;
extern int fn_80080150(f32* p);
extern int objHitDetectFn_80062e84(int p1, int p2, int p3);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern f32 PSVECMag(f32 * v);
extern f32 oneOverTimeDelta;
extern f32 lbl_803DBE84;
extern f32 lbl_803E4324;
extern const f32 lbl_803E4328;
extern f32 lbl_803E432C;
extern f32 lbl_803E4330;
extern f32 lbl_803E4334;
extern void storeZeroToFloatParam(f32* p);
extern int timerCountDown(f32* p);
extern void s16toFloat(f32* p, s16 val);
extern void memset(void* p, int c, int n);
extern int playerIsDisguised(u8 * player);
extern int timer_isEffectMode(int obj);
extern void timer_forceStart(int obj);
extern int timer_hasExpired(int obj);
extern void barrelgener_queueObjectRelease(int gen, int obj, int code);
extern void Obj_RemoveFromUpdateList(int obj);
extern u32 playerGetStateFlag310(u8 * player);
extern void setAButtonIcon(int x);
extern int fn_802966B4(u8 * player);
extern int fn_8029669C(u8 * player);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern void* Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern f32 lbl_803E4338;
extern f32 gGunpowderBarrelPi;
extern f32 gGunpowderBarrelHalfAngleUnit;
extern f32 lbl_803DBE80;

extern void vecRotateZXY(s16 * rotIn, f32 * outVec);
extern f32 lbl_803E42C8;
extern f32 lbl_803E42CC;
extern f32 lbl_803E42D0;
extern f32 lbl_803E42D4;
extern f32 lbl_803E42D8;
extern f32 lbl_803E42E0;
extern f32 lbl_803E42E4;
extern const f32 lbl_803E42E8;
extern f32 lbl_803E42EC;
extern f32 gGunpowderBarrelAngleUnit;

/* Bit flags at GunpowderBarrelState+0x4a (heldFlags). */
typedef struct
{
    u8 playerHeld : 1; /* 0x80 */
    u8 pendingThrowVelCapture : 1; /* 0x40 grab-time throw-velocity capture latch */
    u8 held : 1;       /* 0x20 */
    u8 onGround : 1;   /* 0x10 */
    u8 wasOnGround : 1; /* 0x08 */
    u8 landed : 1;     /* 0x04 */
    u8 cannonRangeVariant : 1; /* 0x02 set when seqId==0x754 (indestructible cannon variant) */
    u8 unk01 : 1;      /* 0x01 */
} GpbHeldFlags;

/* Bit flags at GunpowderBarrelState+0x48 (configFlags). */
typedef struct
{
    u8 respawns : 1;   /* 0x80 live-confirmed: 1=respawn after detonation, 0=remove */
    u8 returnHome : 1; /* 0x40 */
    u8 unkRest : 6;
} GpbConfigFlags;

int gunpowderbarrel_getExtraSize(void)
{
    return 0x58;
}

void gunpowderbarrel_free(int obj, int mode)
{
    extern int Obj_IsObjectAlive(int obj);
    int extra;
    void* child;
    extra = *(int*)&((GameObject*)obj)->extra;
    (*(VtableFn*)(*(int*)gCarryableInterface + 0x10))(obj);
    child = (void*)((GunpowderBarrelState*)extra)->linkedTimerObject;
    if (child != NULL && mode == 0)
    {
        if (Obj_IsObjectAlive((int)child) != 0)
        {
            ObjLink_DetachChild(obj, ((GunpowderBarrelState*)extra)->linkedTimerObject);
            ((GunpowderBarrelState*)extra)->linkedTimerObject = 0;
        }
    }
    ObjGroup_RemoveObject(obj, 0x19);
    ObjGroup_RemoveObject(obj, 0x16);
    if (((GunpowderBarrelState*)extra)->fuseFrames != 0)
    {
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
}

void gunpowderbarrel_render(int* obj, int p2, int p3, int p4, int p5,
                            s8 visFlag)
{
    u8* sub;
    int result;
    int* child;

    sub = ((GameObject*)obj)->extra;
    if (((GunpowderBarrelState*)sub)->fuseFrames != 0 || ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->held)
    {
        return;
    }
    if (((GunpowderBarrelState*)sub)->heldByCarryInterface != 0)
    {
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rotY = 0;
    }
    result = (*(int (**)(int*, int))(*(int*)gCarryableInterface + 0xc))(obj, visFlag);
    if (result != 0 || visFlag == -1)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E42DC);
    }
    child = *(int**)&((GunpowderBarrelState*)sub)->linkedTimerObject;
    if (child != 0)
    {
        (*(void (**)(int*, int, int, int, int, s8))(*(int*)(*(int*)&((GameObject*)child)->anim.dll) + 0x10))(
            child, p2, p3, p4, p5, visFlag);
    }
}

/* EN v1.0 0x801A1230  size: 708b  gunpowderbarrel_triggerExplosion: when hit
 * (or touched while resting on a damage source) blow the barrel up, optionally
 * re-saving its position at the owning generator first. */
void gunpowderbarrel_triggerExplosion(int obj)
{
    u8* sub;
    int hitObj;
    int count;
    u8* tricky;
    int* timer;

    sub = ((GameObject*)obj)->extra;
    /* Arm detonation if we took a priority hit, OR we're in flight (motionFlags
     * bit 2) and made contact with a surface. Also mark the barrel sleeping. */
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, 0) != 0 ||
        (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0 && (((GunpowderBarrelState*)sub)->motionFlags & 2) != 0))
    {
        ((GunpowderBarrelState*)sub)->detonateTrigger += 1;
        ((GunpowderBarrelState*)sub)->motionFlags = (u8)(((GunpowderBarrelState*)sub)->motionFlags | 1);
    }
    if (((GunpowderBarrelState*)sub)->detonateTrigger != 0)
    {
        /* returnHome barrels respawn at their owning generator: temporarily move
         * to the generator's position, latch it via saveGame, then restore. */
        if (((GpbConfigFlags*)&((GunpowderBarrelState*)sub)->configFlags)->returnHome)
        {
            int** objs;
            int* best = 0;
            int i;
            int* def = *(int**)&((GameObject*)obj)->anim.placementData;
            int** p;
            if (((GunpowderbarrelPlacement*)def)->generatorLinkId != 0)
            {
                objs = (int**)ObjGroup_GetObjects(GUNPOWDERBARREL_OBJGROUP, &count);
                i = 0;
                p = objs;
                for (; i < count; i++)
                {
                    if (((GunpowderbarrelPlacement*)def)->generatorLinkId == barrelgener_getLinkId(*p))
                    {
                        best = objs[i];
                        break;
                    }
                    p++;
                }
            }
            else
            {
                best = (int*)ObjGroup_FindNearestObject(GUNPOWDERBARREL_OBJGROUP, obj, 0);
            }
            if (best != 0)
            {
                f32 x, y, z;
                x = ((GameObject*)obj)->anim.localPosX;
                y = ((GameObject*)obj)->anim.localPosY;
                z = ((GameObject*)obj)->anim.localPosZ;
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)best)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)best)->anim.localPosY;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)best)->anim.localPosZ;
                saveGame_saveObjectPos((int*)obj);
                ((GameObject*)obj)->anim.localPosX = x;
                ((GameObject*)obj)->anim.localPosY = y;
                ((GameObject*)obj)->anim.localPosZ = z;
            }
        }
        /* Reconfigure the hitbox into a blast-damage volume, play the boom SFX
         * and spawn the explosion effect at a raised Y. */
        ObjHits_ClearFlags(obj, 0x80);
        ObjHits_SetSourceMask(obj, 1);
        ObjHitbox_SetCapsuleBounds(obj, 0x14, -5, 0x14);
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
        Sfx_PlayFromObject(obj, SFXsk_bapt11_c);
        ((GameObject*)obj)->anim.localPosY += lbl_803E4308;
        spawnExplosion((int*)obj, lbl_803E42C0, 1, 1, 0, 0, 0, 1, 0);
        if (((GunpowderBarrelState*)sub)->heldByCarryInterface != 0)
        {
            (*(void (**)(int, u8*))(*(int*)gCarryableInterface + 0x30))(obj, sub);
            ((GunpowderBarrelState*)sub)->heldByCarryInterface = 0;
        }
        /* Light the fuse: update() grows the blast radius each frame and, once
         * fuseFrames > 0x14, finishes the detonation (hide + respawn/remove). */
        ((GunpowderBarrelState*)sub)->fuseFrames = 1;
        ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->held = 0;
        /* (void*) respelling keeps this (u32) conversion a distinct expression
         * from the u32 call args above — matching retail, no CSE'd copy of obj
         * survives across the calls (target passes r30 directly here). */
        ObjGroup_RemoveObject((u32)(void*)obj, 0x19);
        if (((GameObject*)obj)->anim.parent != 0)
        {
            ((GunpowderBarrelState*)sub)->radiusGrowthPerFrame = lbl_803E42C4;
        }
        else
        {
            ((GunpowderBarrelState*)sub)->radiusGrowthPerFrame = lbl_803E42C4;
        }
        tricky = getTrickyObject();
        if (tricky != 0)
        {
            trickyImpress(tricky);
        }
        ((GunpowderBarrelState*)sub)->motionFlags = (u8)(((GunpowderBarrelState*)sub)->motionFlags & ~2);
        timer = *(int**)&((GunpowderBarrelState*)sub)->linkedTimerObject;
        if (timer != 0)
        {
            timer_clearManualFlags(timer);
        }
    }
}

/* EN v1.0 0x801A14F4  size: 928b  gunpowderbarrel_updatePhysics: gravity,
 * velocity clamps, ground probe + landing sfx, contact handling. */
void gunpowderbarrel_updatePhysics(int* obj)
{
    u8* sub;
    int* contact;
    f32 outY;
    int block;
    f32 dt;

    sub = ((GameObject*)obj)->extra;
    if (((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->held)
    {
        return;
    }
    block = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                ((GameObject*)obj)->anim.localPosZ);
    if (block == -1)
    {
        if (((GunpowderBarrelState*)sub)->motionFlags & 2)
        {
            ((GunpowderBarrelState*)sub)->detonateTrigger = 4;
        }
        return;
    }
    if (((GunpowderBarrelState*)sub)->detonateTrigger == 0 && ((((GunpowderBarrelState*)sub)->motionFlags & 2) || ((GunpowderBarrelState*)sub)->throwVelY > lbl_803E430C))
    {
        ObjHits_SetHitVolumeSlot((u32)obj, 0xe, 1, 0);
        ObjHits_EnableObject((u32)obj);
    }
    if (!((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->playerHeld)
    {
        ((GunpowderBarrelState*)sub)->throwVelY -= lbl_803E4310 * timeDelta;
    }
    {
        f32 v = ((GunpowderBarrelState*)sub)->throwVelX;
        ((GunpowderBarrelState*)sub)->throwVelX = (v < lbl_803E4314)
                                                                   ? lbl_803E4314
                                                                   : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    {
        f32 v = ((GunpowderBarrelState*)sub)->throwVelY;
        ((GunpowderBarrelState*)sub)->throwVelY = (v < lbl_803E4314)
                                                                   ? lbl_803E4314
                                                                   : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    {
        f32 v = ((GunpowderBarrelState*)sub)->throwVelZ;
        ((GunpowderBarrelState*)sub)->throwVelZ = (v < lbl_803E4314)
                                                                   ? lbl_803E4314
                                                                   : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    ((GameObject*)obj)->anim.velocityX = ((GunpowderBarrelState*)sub)->throwVelX;
    ((GameObject*)obj)->anim.velocityY = ((GunpowderBarrelState*)sub)->throwVelY;
    ((GameObject*)obj)->anim.velocityZ = ((GunpowderBarrelState*)sub)->throwVelZ;
    dt = timeDelta;
    objMove(obj, ((GameObject*)obj)->anim.velocityX * dt, ((GameObject*)obj)->anim.velocityY * dt,
            ((GameObject*)obj)->anim.velocityZ * dt);
    ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->onGround = 0;
    if (!(((GunpowderBarrelState*)sub)->motionFlags & 2))
    {
        f32 top;
        f32 bottom;
        int below;
        int result;

        top = ((GameObject*)obj)->anim.previousLocalPosY;
        bottom = ((GameObject*)obj)->anim.localPosY;
        below = top < bottom;
        if (below)
        {
            bottom += lbl_803E4318;
        }
        if (!below)
        {
            top += lbl_803E4318;
        }
        result = findSurfaceInYRange(obj, ((GameObject*)obj)->anim.localPosX, top, ((GameObject*)obj)->anim.localPosZ,
                             bottom, &outY, &contact);
        if (result != 0)
        {
            if (result == 2)
            {
                ((GunpowderBarrelState*)sub)->detonateTrigger = 4;
            }
            else
            {
                if (!((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->wasOnGround)
                {
                    if (((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->landed)
                    {
                        Sfx_PlayFromObject((u32)obj, SFXsk_baptr1_c);
                    }
                    else
                    {
                        ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->landed = 1;
                    }
                }
                ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->onGround = 1;
                ((GameObject*)obj)->anim.localPosY = outY;
            }
        }
    }
    if (((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->onGround)
    {
        f32 z = lbl_803E42C0;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        ((GunpowderBarrelState*)sub)->throwVelX = z;
        ((GunpowderBarrelState*)sub)->throwVelY = z;
        ((GunpowderBarrelState*)sub)->throwVelZ = z;
        if (contact != 0)
        {
            u32 flags;
            ObjHits_AddContactObject((int)contact, (int)obj);
            flags = ((ObjAnimComponent*)contact)->modelInstance->flags;
            if ((flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) && !(flags & 0x8000))
            {
                *(int**)&((GunpowderBarrelState*)sub)->queuedHitObject = contact;
            }
            else if (((GunpowderBarrelState*)sub)->fallAccum < lbl_803E431C)
            {
                ((GunpowderBarrelState*)sub)->detonateTrigger = 4;
            }
        }
        if (((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->playerHeld)
        {
            gunpowderbarrel_setPlayerHeldState(obj, 0);
        }
        ((GunpowderBarrelState*)sub)->fallAccum = lbl_803E42C0;
    }
    else
    {
        if (((GunpowderBarrelState*)sub)->throwVelY < lbl_803E4320)
        {
            gunpowderbarrel_homeOnTarget(obj, ((GunpowderBarrelState*)sub)->homingHeadingA,
                        ((GunpowderBarrelState*)sub)->homingHeadingB);
        }
        if (!((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->held && !((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->playerHeld)
        {
            ((GunpowderBarrelState*)sub)->fallAccum += ((GameObject*)obj)->anim.velocityY;
            if (((GunpowderBarrelState*)sub)->fallAccum < -lbl_803DBE88)
            {
                ((GunpowderBarrelState*)sub)->detonateTrigger = 4;
            }
        }
    }
    ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->wasOnGround = ((GpbHeldFlags*)&((GunpowderBarrelState*)sub)->heldFlags)->onGround;
}

/* Tail of the TU (0x801A1A60..0x801A27B8) - formerly the head of
 * cannontargetControl.c (now dll_0159_blasted.c). */

void gunpowderbarrel_hitDetect(int obj)
{
    GameObject* barrel;
    GunpowderBarrelState* state;
    f32 sp1c[3];
    f32 sp10[3];
    f32 collision_buf[24];

    barrel = (GameObject*)obj;
    state = barrel->extra;

    if ((int)Obj_IsObjectAlive(state->linkedTimerObject) == 0)
    {
        if ((void*)state->linkedTimerObject != NULL)
        {
            ObjLink_DetachChild(obj, state->linkedTimerObject);
            state->linkedTimerObject = 0;
        }
    }

    if (state->fuseFrames != 0u)
    {
        return;
    }

    if (fn_80080150(&state->respawnTimer) != 0)
    {
        return;
    }
    switch (fn_80080150(&state->releaseTimer))
    {
    case 0:
        break;
    default:
        return;
    }

    if ((void*)state->queuedHitObject != NULL)
    {
        objHitDetectFn_80062e84(obj, state->queuedHitObject, 1);
        state->queuedHitObject = 0;
    }

    if (((state->heldFlags >> 7) & 1) != 0u)
    {
        sp1c[0] = barrel->anim.localPosX - barrel->anim.previousLocalPosX;
        sp1c[1] = barrel->anim.localPosY - barrel->anim.previousLocalPosY;
        sp1c[2] = barrel->anim.localPosZ - barrel->anim.previousLocalPosZ;
        {
            f32 inv = lbl_803E4324 * oneOverTimeDelta;
            sp1c[0] = sp1c[0] * inv;
            sp1c[1] = sp1c[1] * inv;
            sp1c[2] = sp1c[2] * inv;
        }
        state->throwVelX = ((f32*)sp1c)[0] + state->throwVelX;
        state->throwVelY = ((f32*)sp1c)[1] + state->throwVelY;
        state->throwVelZ = ((f32*)sp1c)[2] + state->throwVelZ;
        {
            f32 zero = lbl_803E42C0;
            sp1c[1] = zero;
            state->throwVelX = lbl_803E4328 * state->throwVelX;
            state->throwVelY = lbl_803E4328 * state->throwVelY;
            state->throwVelZ = lbl_803E4328 * state->throwVelZ;
            state->throwVelY = zero;
        }
        state->motionFlags = (u8)(state->motionFlags | 1);
    }

    if (state->heldByCarryInterface != 0)
    {
        goto copy_end;
    }

    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E432C, 1,
                           (int)&collision_buf[0], obj, 8, -1, 0xff, 0) == 0)
    {
        goto copy_end;
    }

    if ((s8) * ((u8*)&collision_buf[0] + 0x51) == 0x14)
    {
        state->detonateTrigger = 4;
    }

    if (((state->heldFlags >> 7) & 1) != 0u &&
        (s8) * ((u8*)&collision_buf[0] + 0x51) == 3)
    {
        gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
        ObjGroup_RemoveObject(obj, 0x16);
        goto copy_end;
    }

    sp10[0] = *((f32*)&collision_buf[0] + 7);
    sp10[1] = *((f32*)&collision_buf[0] + 8);
    sp10[2] = *((f32*)&collision_buf[0] + 9);
    Vec3_ReflectAgainstNormal(sp10, (void*)(obj + 0x24), (void*)(obj + 0x24));
    Vec3_ReflectAgainstNormal(sp10, &state->throwVelX, &state->throwVelX);

    {
        f32 damp = lbl_803E4330;
        barrel->anim.velocityX = damp * barrel->anim.velocityX;
        barrel->anim.velocityY = damp * barrel->anim.velocityY;
        barrel->anim.velocityZ = damp * barrel->anim.velocityZ;
        state->throwVelX = damp * state->throwVelX;
        state->throwVelY = damp * state->throwVelY;
        state->throwVelZ = damp * state->throwVelZ;
    }
    (void)sp1c; /* keep sp1c allocated on the stack (matching artifact) */

    if (state->impactSoundCooldown > lbl_803E4334)
    {
        if (PSVECMag(&state->throwVelX) > lbl_803DBE84)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_statue_waterfall);
        }
        state->impactSoundCooldown = lbl_803E42C0;
    }

copy_end:
    barrel->anim.previousLocalPosX = barrel->anim.localPosX;
    barrel->anim.previousLocalPosY = barrel->anim.localPosY;
    barrel->anim.previousLocalPosZ = barrel->anim.localPosZ;
}

/* EN v1.0 0x801A25E8  size: 464b  Gunpowder-barrel setup: registers with the
 * carryable interface and obj groups, zeroes the roll/contact state, seeds
 * the hit radius from the model's bound halfword, and latches the
 * indestructible bit for the cannon-range variant (type 0x754). */
void gunpowderbarrel_init(int obj, u8* def)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;

    ((GunpowderBarrelState*)((GameObject*)obj)->extra)->unk07 |= 2;
    (*(void (**)(int, GunpowderBarrelState*, int))((char*)*gCarryableInterface + 0x4))(obj, state, 5);
    ObjGroup_AddObject(obj, 0x19);
    ObjGroup_AddObject(obj, 0x16);
    ObjMsg_AllocQueue((void*)obj, 8);
    ((GameObject*)obj)->unkF8 = 0;
    state->homingHeadingA = 0;
    state->homingHeadingB = 0;
    state->heldByCarryInterface = 0;
    state->unk3C = 0;
    state->detonateTrigger = 0;
    state->fuseFrames = 0;
    state->unk3E = 0;
    state->unk40 = 0;
    state->unk30 = lbl_803E42C0;
    state->motionFlags = 0;
    storeZeroToFloatParam(&state->respawnTimer);
    storeZeroToFloatParam(&state->releaseTimer);
    state->motionFlags |= 1;
    {
        GunpowderbarrelPlacement* placement = (GunpowderbarrelPlacement*)def;
        u8 v;
        v = (placement->respawnByte >= 1) ? 0 : 1;
        ((GpbConfigFlags*)&state->configFlags)->respawns = v;
        v = (placement->returnHome == 0) ? 0 : 1;
        ((GpbConfigFlags*)&state->configFlags)->returnHome = v;
    }
    ObjHits_EnableObject(obj);
    state->hitRadius = (f32)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->primaryRadius;
    ((GpbHeldFlags*)&state->heldFlags)->held = 0;
    state->fallAccum = lbl_803E42C0;
    state->linkedTimerObject = 0;
    (*(void (**)(GunpowderBarrelState*, int))((char*)*gCarryableInterface + 0x2c))(state, 1);
    if ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState != NULL)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->trackContactMask = 1;
    }
    if (((GameObject*)obj)->anim.seqId == GUNPOWDERBARREL_SEQ_CANNONRANGE)
    {
        ((GpbHeldFlags*)&state->heldFlags)->cannonRangeVariant = 1;
    }
}

/* EN v1.0 0x801A1D48  size: 2208b  Gunpowder-barrel per-frame driver: runs
 * the fuse/respawn timers, manages the cannon attach link, drains the
 * held/released message queue, grows the hitbox while the fuse burns and
 * hands the barrel back to its generator, and handles the pickup/steal/toss
 * transitions against the player's carry state. */
void gunpowderbarrel_update(int obj)
{
    extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
    u8* player;
    int def;
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    def = *(int*)&((GameObject*)obj)->anim.placementData;

    if (state->impactSoundCooldown <= lbl_803E4334)
    {
        state->impactSoundCooldown += timeDelta;
    }
    /* --- Respawn phase: while the respawn timer runs the barrel stays hidden;
     * the frame it expires we un-hide, reset state and pop back onto the pad. --- */
    if (fn_80080150(&state->respawnTimer) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if (timerCountDown(&state->respawnTimer) != 0)
        {
            state->fuseFrames = 0;
            state->detonateTrigger = 0;
            state->motionFlags |= 1;
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ObjHits_ClearHitVolumes(obj);
            ObjHitbox_SetCapsuleBounds(obj, 8, -2, 0x19);
            ObjHits_EnableObject(obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
            gunpowderbarrel_updatePhysics((int*)obj);
            gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
        }
        return;
    }
    /* --- Release-cooldown phase: just after a generator hand-back, hold the
     * barrel still (zero throw + object velocity) until the timer drains. --- */
    if (fn_80080150(&state->releaseTimer) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        timerCountDown(&state->releaseTimer);
        memset(&state->throwVelX, 0, 0xc);
        memset((void*)&((GameObject*)obj)->anim.velocityX, 0, 0xc);
        return;
    }
    if (((GpbHeldFlags*)&state->heldFlags)->held == 0)
    {
        if (((GpbHeldFlags*)&state->heldFlags)->cannonRangeVariant != 0 && playerIsDisguised(player) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    /* --- Cannon/effect-timer link: with no child yet, grab the nearest free
     * group-0x4c effect-timer object and attach it; drop it if it dies. --- */
    if (((GameObject*)obj)->childObjs[0] == NULL)
    {
        f32 range = lbl_803E4338;
        if ((u32)(state->linkedTimerObject = ObjGroup_FindNearestObject(0x4c, obj, &range)) != 0 &&
            timer_isEffectMode(state->linkedTimerObject) != 0 &&
            ((GameObject*)state->linkedTimerObject)->ownerObj == NULL)
        {
            ObjLink_AttachChild(obj, state->linkedTimerObject, 0);
        }
    }
    else
    {
        if ((int)Obj_IsObjectAlive(state->linkedTimerObject) == 0 && *(void* *)&state->linkedTimerObject != NULL)
        {
            ObjLink_DetachChild(obj, state->linkedTimerObject);
            state->linkedTimerObject = 0;
        }
    }
    {
        u32 arg;
        u32 msg;
        msg = 0;
        arg = 0;
        while ((int)ObjMsg_Pop((void*)obj, &msg, 0, &arg) != 0)
        {
            switch (msg)
            {
            case 0xf:
                gunpowderbarrel_setPlayerHeldState((int*)obj, 1);
                break;
            case 0x10:
                gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
                if (arg != 0)
                {
                    ObjGroup_AddObject(obj, 0x16);
                }
                break;
            }
        }
    }
    if (((GpbHeldFlags*)&state->heldFlags)->held != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    }
    /* --- Fuse phase: once lit (fuseFrames != 0) grow the blast hitbox each
     * frame; after the fuse window (> 0x14) consume the barrel below. --- */
    if (state->fuseFrames != 0)
    {
        state->fuseFrames += framesThisStep;
        state->hitRadius = state->radiusGrowthPerFrame * (f32)(u32)
        state->fuseFrames + lbl_803E42DC;
        {
            f32 r = state->hitRadius;
            ObjHitbox_SetCapsuleBounds(obj, r, (s32)(-r * lbl_803E4328), (s32)(r * lbl_803E4328));
        }
        if (*(void* *)&state->linkedTimerObject != NULL)
        {
            timer_clearManualFlags(state->linkedTimerObject);
        }
        if (state->fuseFrames > 0x14)
        {
            int i;
            u32 gen;
            if (((GpbHeldFlags*)&state->heldFlags)->playerHeld != 0)
            {
                gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
            }
            /* Find the owning generator: match a placement link id against the
             * group-0x3a generators, otherwise take the nearest one. */
            gen = 0;
            if (((GunpowderbarrelPlacement*)def)->generatorLinkId != 0)
            {
                int cnt;
                u32* objs = ObjGroup_GetObjects(GUNPOWDERBARREL_OBJGROUP, &cnt);
                u32* p;
                i = 0;
                p = objs;
                for (; i < cnt; i++)
                {
                    if (((GunpowderbarrelPlacement*)def)->generatorLinkId == barrelgener_getLinkId(*p))
                    {
                        gen = objs[i];
                        break;
                    }
                    p++;
                }
            }
            else
            {
                gen = ObjGroup_FindNearestObject(GUNPOWDERBARREL_OBJGROUP, obj, 0);
            }
            if (gen == 0)
            {
                Obj_RemoveFromUpdateList(obj);
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                s16toFloat(&state->respawnTimer, 0x3c);
                return;
            }
            memset(&state->throwVelX, 0, 0xc);
            memset((void*)&((GameObject*)obj)->anim.velocityX, 0, 0xc);
            state->motionFlags &= ~2;
            ObjHits_RefreshObjectState(obj);
            /* Generator + respawns flag: hand the barrel back to the generator,
             * hide it, and arm both the respawn and release timers. */
            if (((GpbConfigFlags*)&state->configFlags)->respawns != 0)
            {
                s16toFloat(&state->respawnTimer, 0x3c);
                storeZeroToFloatParam(&state->releaseTimer);
                s16toFloat(&state->releaseTimer, 0x5a);
                barrelgener_queueObjectRelease(gen, obj, 0x46);
                ObjHits_ClearHitVolumes(obj);
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                return;
            }
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        return;
    }
    if (state->heldByCarryInterface != 0)
    {
        if ((playerGetStateFlag310(player) & 0x4000) != 0)
        {
            setAButtonIcon(5);
        }
        else
        {
            setAButtonIcon(4);
        }
    }
    else
    {
        if (((GpbConfigFlags*)&state->configFlags)->returnHome != 0 && ((GpbHeldFlags*)&state->heldFlags)->onGround != 0 &&
            (state->motionFlags & 2) == 0)
        {
            saveGame_saveObjectPos((int*)obj);
        }
    }
    if ((state->motionFlags & 2) != 0 || ((GpbHeldFlags*)&state->heldFlags)->held != 0 ||
        (*(int (**)(int, GunpowderBarrelState*))((char*)*gCarryableInterface + 0x8))(obj, state) == 0 ||
        (((GpbHeldFlags*)&state->heldFlags)->cannonRangeVariant != 0 && playerIsDisguised(player) == 0))
    {
        ObjHits_EnableObject(obj);
        gunpowderbarrel_triggerExplosion(obj);
        ((GameObject*)obj)->anim.alpha = 0xff;
        /* Releasing from carry: dispatch on the player's controlMode —
         * 6 = place in-place, 7 = launch at a target, no lift velocity = toss. */
        if (state->heldByCarryInterface != 0)
        {
            state->heldByCarryInterface = 0;
            if (fn_802966B4(player) != 0) /* controlMode 6: set down in place */
            {
                ObjHits_SyncObjectPositionIfDirty(obj);
            }
            else if (fn_8029669C(player) != 0) /* controlMode 7: launch at target */
            {
                ObjHits_MarkObjectPositionDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 1);
            }
            else if (lbl_803E42C0 == Player_GetLiftVelocityY((int)player)) /* no lift: gentle toss */
            {
                ObjHits_SyncObjectPositionIfDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 0);
            }
            else if (state->fuseFrames == 0)
            {
                ((GameObject*)obj)->anim.velocityX = state->throwVelX =
                    mathSinf(gGunpowderBarrelPi * (f32) ((GameObject*)player)->anim.rotX / gGunpowderBarrelHalfAngleUnit);
                ((GameObject*)obj)->anim.velocityY = state->throwVelY = lbl_803E42C0;
                ((GameObject*)obj)->anim.velocityZ = state->throwVelZ =
                    mathCosf(gGunpowderBarrelPi * (f32) ((GameObject*)player)->anim.rotX / gGunpowderBarrelHalfAngleUnit);
                ((GameObject*)obj)->anim.localPosX =
                    lbl_803DBE80 * -mathSinf(gGunpowderBarrelPi * (f32) ((GameObject*)player)->anim.rotX /
                        gGunpowderBarrelHalfAngleUnit) +
                    ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ =
                    lbl_803DBE80 * -mathCosf(gGunpowderBarrelPi * (f32) ((GameObject*)player)->anim.rotX / gGunpowderBarrelHalfAngleUnit) +
                    ((GameObject*)obj)->anim.localPosZ;
                ObjGroup_AddObject(obj, 0x16);
            }
            /* faithful double-add: retail emits two adjacent ObjGroup_AddObject
             * (target 0x19b8/0x19c4) when the inner branch is taken. */
            ObjGroup_AddObject(obj, 0x16);
        }
        gunpowderbarrel_updatePhysics((int*)obj);
    }
    else
    {
        state->motionFlags |= 1;
        if (state->heldByCarryInterface == 0)
        {
            if (*(void* *)&state->linkedTimerObject != NULL)
            {
                timer_forceStart(state->linkedTimerObject);
            }
            ObjGroup_RemoveObject(obj, 0x16);
        }
        state->heldByCarryInterface = 1;
        ((GpbHeldFlags*)&state->heldFlags)->pendingThrowVelCapture = 1;
        state->launchYaw = ((GameObject*)player)->anim.rotX;
        gunpowderbarrel_triggerExplosion(obj);
    }
    if (((GpbHeldFlags*)&state->heldFlags)->playerHeld != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if (((GpbHeldFlags*)&state->heldFlags)->pendingThrowVelCapture != 0 && ((GpbHeldFlags*)&state->heldFlags)->playerHeld != 0)
        {
            state->throwVelX = ((GameObject*)obj)->anim.velocityX;
            state->throwVelY = ((GameObject*)obj)->anim.velocityY;
            state->throwVelZ = ((GameObject*)obj)->anim.velocityZ;
            state->throwVelY = lbl_803E42C0;
            ((GpbHeldFlags*)&state->heldFlags)->pendingThrowVelCapture = 0;
        }
    }
    if (*(void* *)&state->linkedTimerObject != NULL)
    {
        if (timer_hasExpired(state->linkedTimerObject) != 0)
        {
            state->detonateTrigger = 0xa;
        }
    }
}

/* Head of the TU (0x801A0B14..0x801A1230) - formerly the
 * gunpowder-barrel helper group inside sandwormBoss.c. Placed LAST in
 * this file so none of the small helpers can be auto-inlined into the
 * update/hitDetect callers above (they were extern bls before the
 * re-split, and the retail unit keeps the bls). */

u32 gunpowderbarrel_isHeld(int* obj) { return (((GunpowderBarrelState*)((GameObject*)obj)->extra)->heldFlags >> 5) & 1; }

/* EN v1.0 0x801A0BDC  size: 56b  gunpowderbarrel_setHeldState: flag the
 * barrel as held, mark obj active, and clear its physics-sleep bit. */
void gunpowderbarrel_setHeldState(int* obj)
{
    GunpowderBarrelState* sub = ((GameObject*)obj)->extra;
    ((GpbHeldFlags*)&sub->heldFlags)->held = 1;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    sub->motionFlags = (u8)(sub->motionFlags & ~2);
}

/* EN v1.0 0x801A0B90  size: 76b  gunpowderbarrel_clearHeldState: zero the
 * barrel's velocity/throw vectors, mark it sleeping, clear obj-active and
 * the held flag. */
void gunpowderbarrel_clearHeldState(int* obj)
{
    GunpowderBarrelState* sub = ((GameObject*)obj)->extra;
    f32 z = lbl_803E42C0;
    sub->throwVelY = z;
    sub->throwVelX = z;
    sub->throwVelZ = z;
    sub->motionFlags = (u8)(sub->motionFlags | 1);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
    sub->fallAccum = z;
    ((GpbHeldFlags*)&sub->heldFlags)->held = 0;
}

/* EN v1.0 0x801A0E04  size: 244b  gunpowderbarrel_setPlayerHeldState: when
 * grabbed by the player, copy the held-pose and enable hit reactions; when
 * released, restore the default pose and clear them. */
void gunpowderbarrel_setPlayerHeldState(int* obj, u8 heldByPlayer)
{
    GunpowderBarrelState* sub;
    int o = (int)obj;
    u8* h;
    sub = ((GameObject*)o)->extra;
    h = *(u8**)&((GameObject*)o)->anim.hitReactState;
    if (heldByPlayer != 0)
    {
        h[0x6a] = 1;
        h[0x6b] = 1;
        *(u8*)&((GameObject*)o)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)o)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        ((GpbHeldFlags*)&sub->heldFlags)->playerHeld = 1;
        sub->motionFlags = (u8)(sub->motionFlags & ~2);
        ObjHits_SetFlags(o, 0x480);
        ObjHits_ClearSourceMask(o, 1);
        ObjHits_EnableObject(o);
        ObjHits_SyncObjectPositionIfDirty(o);
    }
    else
    {
        h[0x6a] = (*(u8**)&((GameObject*)o)->anim.modelInstance)[0x63];
        h[0x6b] = (*(u8**)&((GameObject*)o)->anim.modelInstance)[0x64];
        ((GpbHeldFlags*)&sub->heldFlags)->playerHeld = 0;
        *(u8*)&((GameObject*)o)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)o)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        ObjHits_ClearFlags(o, 0x400);
        sub->motionFlags = (u8)(sub->motionFlags | 1);
    }
}

void gunpowderbarrel_addThrowVelocity(int* obj, f32* params)
{
    int* state = ((GameObject*)obj)->extra;
    if (((GunpowderBarrelState*)state)->heldByCarryInterface != 0) return;
    if (((GunpowderBarrelState*)state)->fuseFrames != 0) return;
    ((GunpowderBarrelState*)state)->throwVelY = ((GunpowderBarrelState*)state)->throwVelY + params[1];
    ((GunpowderBarrelState*)state)->throwVelX = ((GunpowderBarrelState*)state)->throwVelX + params[0];
    ((GunpowderBarrelState*)state)->throwVelZ = ((GunpowderBarrelState*)state)->throwVelZ + params[2];
    ((GunpowderBarrelState*)state)->motionFlags = (u8)(((GunpowderBarrelState*)state)->motionFlags | 1);
}

int gunpowderbarrel_canBeGrabbed(int* obj)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;
    int result = 0;
    if (state->heldByCarryInterface == 0 &&
        state->respawnTimer == lbl_803E42C0 &&
        (*(int (**)(GunpowderBarrelState*))(*(int*)gCarryableInterface + 0x14))(state) == 0)
    {
        result = 1;
    }
    return result;
}

/* gunpowderbarrel_launchAtTarget: gunpowder-barrel "throw at target" launch. Seeds state's
 * launch velocity (state+0x20..28) from a per-axis pair scaled by the
 * player's strength (player_state[0x298]), or a fixed pair when the flag
 * is clear. Builds a rotation-vec from state[0x50], runs the 3-vec rotor
 * via vecRotateZXY, sets thrown/inflight flags, plays sfx 0xd3. When
 * state[0x48] bit 0x40 is set, looks up the linked barrel by data[0x1a]
 * (or the nearest one if 0), temporarily moves obj to that barrel's
 * position so saveGame_saveObjectPos latches the target slot, then
 * restores. */
void gunpowderbarrel_launchAtTarget(int obj, u8 flag)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;
    u8* playerState;
    s16 stk[8];
    f32 fz;
    f32 sx, sy, sz;

    playerState = (u8*)((GameObject*)Obj_GetPlayerObject())->extra;
    state->throwVelX = lbl_803E42C0;
    if (flag != 0)
    {
        state->throwVelY = lbl_803E42C8 * *(f32*)(playerState + 0x298) + lbl_803E42C4;
        state->throwVelZ = lbl_803E42D0 * *(f32*)(playerState + 0x298) + lbl_803E42CC;
    }
    else
    {
        state->throwVelY = lbl_803E42D4;
        state->throwVelZ = lbl_803E42D8;
    }
    fz = lbl_803E42C0;
    *(f32*)((u8*)stk + 0xc) = fz;
    *(f32*)((u8*)stk + 0x10) = fz;
    *(f32*)((u8*)stk + 0x14) = fz;
    *(f32*)((u8*)stk + 0x8) = lbl_803E42DC;
    stk[2] = 0;
    stk[1] = 0;
    stk[0] = state->launchYaw;
    vecRotateZXY(stk, &state->throwVelX);
    state->motionFlags = (u8)(state->motionFlags | 1);
    Sfx_PlayFromObject((u32)obj, SFXsk_baptr6_c);
    state->motionFlags = (u8)(state->motionFlags | 2);
    if (((GpbConfigFlags*)&state->configFlags)->returnHome != 0)
    {
        int i;
        GunpowderbarrelPlacement* params = *(GunpowderbarrelPlacement**)&((GameObject*)obj)->anim.placementData;
        int target = 0;
        u32* barrels;
        u32* p;
        int count;
        if (params->generatorLinkId != 0)
        {
            barrels = ObjGroup_GetObjects(GUNPOWDERBARREL_OBJGROUP, &count);
            i = 0;
            p = barrels;
            for (; i < count; i++)
            {
                if (params->generatorLinkId == barrelgener_getLinkId(*p))
                {
                    target = barrels[i];
                    break;
                }
                p++;
            }
        }
        else
        {
            target = ObjGroup_FindNearestObject(GUNPOWDERBARREL_OBJGROUP, obj, 0);
        }
        if ((void*)target != NULL)
        {
            sx = ((GameObject*)obj)->anim.localPosX;
            sy = ((GameObject*)obj)->anim.localPosY;
            sz = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)target)->anim.localPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)target)->anim.localPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)target)->anim.localPosZ;
            saveGame_saveObjectPos((int*)obj);
            ((GameObject*)obj)->anim.localPosX = sx;
            ((GameObject*)obj)->anim.localPosY = sy;
            ((GameObject*)obj)->anim.localPosZ = sz;
        }
    }
}

/* EN v1.0 0x801A0F58  size: 728b  gunpowderbarrel_homeOnTarget: home the object on the nearest
 * group-0x1e object above it, scaling velocity and the two heading words by
 * approach rate; on a steep approach play the dive cue and bump the target's
 * cycle phase. */
void gunpowderbarrel_homeOnTarget(int* obj, s16 a, s16 b)
{
    f32 dx;
    f32 dy2;
    f32 dz;
    f32 scale;
    f32 rate;
    f32 dy;
    int v;
    int w;
    char* player;
    char* near;
    f32 radius = lbl_803E42E0;
    player = Obj_GetPlayerObject();
    near = (char*)ObjGroup_FindNearestObject(0x1e, (u32)obj, &radius);
    if (near == NULL)
    {
        return;
    }
    dy = ((GameObject*)near)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
    dy = (dy >= 0.0f) ? dy : -dy;
    if (dy < lbl_803E42E4)
    {
        return;
    }
    dx = ((GameObject*)near)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy2 = ((GameObject*)near)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    scale = 0.0f;
    if (dy2 > scale)
    {
        return;
    }
    dz = ((GameObject*)near)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    if (dy2 != scale)
    {
        rate = ((GameObject*)obj)->anim.velocityY / dy2;
    }
    else
    {
        rate = scale;
    }
    if (rate >= lbl_803E42DC)
    {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_barrel_putdown);
        rate = lbl_803E42DC;
        ((GameObject*)obj)->anim.velocityY = dy2;
        ((GameObject*)near)->anim.localPosX += lbl_803E42E8;
        ((GameObject*)near)->anim.velocityZ += lbl_803E42E8;
        if (((GameObject*)near)->anim.velocityZ > lbl_803E42EC)
        {
            ((GameObject*)near)->anim.localPosX -= ((GameObject*)near)->anim.velocityZ;
            ((GameObject*)near)->anim.velocityZ = 0.0f;
        }
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        a = 0;
        b = 0;
    }
    ((GameObject*)obj)->anim.velocityX = dx * rate;
    ((GameObject*)obj)->anim.velocityZ = dz * rate;
    v = a;
    if (v != 0)
    {
        f32 t;
        if (v == 1)
        {
            t = gGunpowderBarrelAngleUnit - (f32)(u16)((GameObject*)obj)->anim.rotY;
            t = t * rate;
        }
        else
        {
            t = (f32)(u16)((GameObject*)obj)->anim.rotY * (rate * v);
        }
        ((GameObject*)obj)->anim.rotY = (f32)((GameObject*)obj)->anim.rotY + t;
    }
    w = b;
    if (w != 0)
    {
        f32 t;
        if (w == 1)
        {
            t = 0.0f;
        }
        else
        {
            t = (f32)(u16)((GameObject*)obj)->anim.rotZ;
            t = t * (rate * w);
        }
        ((GameObject*)obj)->anim.rotZ = (f32)((GameObject*)obj)->anim.rotZ + t;
    }
}
