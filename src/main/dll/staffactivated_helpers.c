/*
 * staffactivated helpers (CF dll) - shared routines for the staff-activated
 * pad/lift object family.
 *
 * staffactivated_updateLiftHeight: per-frame spring physics for the rising
 *   lift platform (gravity-decayed velocity, height integration, peak
 *   tracking) with sfx/rumble on landing and threshold crossings; feeds the
 *   resulting height back into the object's anim move-progress.
 * cfPrisonGuard_setGameBitMirror / _isGameBitMirrorSet: mirror a setup's
 *   lock game bit into state->flags bit 5 for the prison-guard variant.
 * staffactivated_spawnMapEventDebris: on a timed map event (only while
 *   loading is locked and the event isn't time-saved) adds event time,
 *   triggers Tricky, and scatters a burst of debris objects with randomised
 *   outward velocity and yaw.
 * cfPrisonGuard_getPullRateMode: clamps the setup size param to [0,2].
 */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/CF/staffactivated_helpers.h"
#include "main/mapEventTypes.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"
extern int randomGetRange(int lo, int hi);


extern int Obj_GetPlayerObject(void);
extern int getTrickyObject(void);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int objectId);
extern int Obj_SetupObject(int setup, int mode, int mapLayer, int objIndex, int parent);
extern void trickyImpress(int obj);
extern f32 sqrtf(f32 value);
extern void vecRotateZXY(void* rotation, void* vec);
extern u16 getAngle(f32 x, f32 z);
extern f32 timeDelta;
extern const f32 lbl_803E3BBC;
extern const f32 lbl_803E3BC4;
extern f32 lbl_803E3BC8;
extern f32 lbl_803E3BCC;
extern f32 lbl_803E3BD8;
extern const f32 lbl_803E3BDC;
extern const f32 lbl_803E3BE0;
extern s16 lbl_803DBDE0[4];

void staffactivated_updateLiftHeight(int obj, StaffActivatedState* state)
{
    u32 flags;
    s32 prevHeight;
    s32 rumbleStrength;

    flags = state->flags;
    if ((flags >> 7 & 1) == 0u || (flags >> 6 & 1) != 0u)
    {
        return;
    }
    if (state->liftReset == 0)
    {
        state->liftVelocity = (s32) - (lbl_803E3BC8 * timeDelta - state->liftVelocity);
        state->liftHeight =
            (s32)((f32)state->liftVelocity * timeDelta + state->liftHeight);
        if (state->liftHeight > state->peakLiftHeight)
        {
            state->peakLiftHeight = state->liftHeight;
        }
        if (state->previousLiftHeight == 0x800 && state->liftHeight < 0x800)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_mammoth_grunt);
        }
        if (state->liftHeight < 0)
        {
            if (state->previousLiftHeight > 0)
            {
                Sfx_PlayFromObject(obj, SFXmn_dimraw36);
                rumbleStrength = state->peakLiftHeight / 200;
                if (rumbleStrength > 0)
                {
                    doRumble((f32)rumbleStrength);
                }
            }
            state->liftVelocity = 0;
            state->liftHeight = 0;
        }
    }
    else
    {
        state->liftReset = 0;
        state->peakLiftHeight = 0;
    }

    prevHeight = state->previousLiftHeight;
    if ((prevHeight < 0x40 && state->liftHeight >= 0x40) ||
        (prevHeight >= 0x40 && state->liftHeight < 0x40))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mammoth_grunt);
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                              &state->hitCooldown);
    state->previousLiftHeight = state->liftHeight;
    ((void(*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, state->liftHeight / lbl_803E3BCC);
}

typedef struct PrisonGuardStateFlags
{
    u8 pad[0x1d];
    u8 active : 1;
    u8 locked : 1;
    u8 mirror : 1;
} PrisonGuardStateFlags;

void cfPrisonGuard_setGameBitMirror(int obj, u8 flag)
{
    StaffActivatedSetup* setup = (StaffActivatedSetup*)((GameObject*)obj)->anim.placementData;
    StaffActivatedState* state = ((GameObject*)obj)->extra;
    if (flag != 0)
    {
        GameBit_Set(setup->lockGameBit, 1);
        ((PrisonGuardStateFlags*)state)->mirror = 1;
    }
    else
    {
        GameBit_Set(setup->lockGameBit, 0);
        ((PrisonGuardStateFlags*)state)->mirror = 0;
    }
}

u32 cfPrisonGuard_isGameBitMirrorSet(int* obj)
{
    return (((StaffActivatedState*)((GameObject*)obj)->extra)->flags >> 5) & 1;
}

typedef struct PrisonGuardRotationWork
{
    s16 y;
    s16 x;
    s16 z;
    s16 pad;
    f32 scale;
    f32 tx;
    f32 ty;
    f32 tz;
} PrisonGuardRotationWork;

void staffactivated_spawnMapEventDebris(int obj)
{
    int i;
    StaffActivatedSetup* setup;
    int player;
    u32 tricky;
    StaffActivatedState* state;
    int spawnedSetup;
    int spawnedObj;
    ObjPlacement* spawnedPlacement;
    f32 lenSq;
    f32 len;
    s32 yawDelta;
    PrisonGuardRotationWork rotate;

    setup = (StaffActivatedSetup*)((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    state = ((GameObject*)obj)->extra;

    if ((*gMapEventInterface)->shouldNotSaveTime(setup->base.mapId) != 0 &&
        Obj_IsLoadingLocked() != 0)
    {
        (*gMapEventInterface)->addTime(setup->base.mapId,
                                               lbl_803E3BD8 * setup->timedEventSeconds);
        if (tricky != 0)
        {
            trickyImpress(tricky);
        }

        i = 0;
        while (i < setup->debrisCount)
        {
            spawnedSetup = Obj_AllocObjectSetup(0x24, lbl_803DBDE0[setup->debrisObjectSet]);
            spawnedPlacement = (ObjPlacement*)spawnedSetup;
            spawnedPlacement->posX = state->targetX;
            spawnedPlacement->posY = ((GameObject*)obj)->anim.localPosY;
            spawnedPlacement->posZ = state->targetZ;
            *(s16*)((StaffActivatedSetup*)spawnedPlacement)->pad1A = 0x190;

            spawnedObj = Obj_SetupObject(spawnedSetup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         *(int*)&((GameObject*)obj)->anim.parent);
            ((GameObject*)spawnedObj)->anim.velocityX = ((GameObject*)obj)->anim.localPosX - *(f32*)(player + 0xc);
            ((GameObject*)spawnedObj)->anim.velocityZ = ((GameObject*)obj)->anim.localPosZ - *(f32*)(player + 0x14);

            lenSq = (((GameObject*)spawnedObj)->anim.velocityX * ((GameObject*)spawnedObj)->anim.velocityX) +
                (((GameObject*)spawnedObj)->anim.velocityZ * ((GameObject*)spawnedObj)->anim.velocityZ);
            if (lenSq != lbl_803E3BDC)
            {
                len = sqrtf(lenSq);
                ((GameObject*)spawnedObj)->anim.velocityX = ((GameObject*)spawnedObj)->anim.velocityX / len;
                ((GameObject*)spawnedObj)->anim.velocityZ = ((GameObject*)spawnedObj)->anim.velocityZ / len;
            }

            ((GameObject*)spawnedObj)->anim.velocityX =
                ((GameObject*)spawnedObj)->anim.velocityX *
                (lbl_803E3BBC - (lbl_803E3BC4 * (f32)(int)randomGetRange(0, 0x19)));
            ((GameObject*)spawnedObj)->anim.velocityZ =
                ((GameObject*)spawnedObj)->anim.velocityZ *
                (lbl_803E3BBC - (lbl_803E3BC4 * (f32)(int)randomGetRange(0, 0x19)));
            ((GameObject*)spawnedObj)->anim.velocityY = lbl_803E3BE0;

            rotate.tx = lbl_803E3BDC;
            rotate.ty = lbl_803E3BDC;
            rotate.tz = lbl_803E3BDC;
            rotate.scale = lbl_803E3BBC;
            rotate.z = 0;
            rotate.x = 0;
            rotate.y = randomGetRange(-10000, 10000);
            vecRotateZXY(&rotate, (void*)(spawnedObj + 0x24));

            yawDelta = ((GameObject*)spawnedObj)->anim.rotX -
                getAngle(((GameObject*)spawnedObj)->anim.velocityX, -((GameObject*)spawnedObj)->anim.velocityZ);
            if (yawDelta > 0x8000)
            {
                yawDelta -= 0xffff;
            }
            if (yawDelta < -0x8000)
            {
                yawDelta += 0xffff;
            }
            ((GameObject*)spawnedObj)->anim.rotX = yawDelta;
            i++;
        }
    }
}

u32 cfPrisonGuard_getPullRateMode(int obj)
{
    u32 mode;
    mode = ((StaffActivatedSetup*)((GameObject*)obj)->anim.placementData)->size;
    if (mode > 2) mode = 2;
    return mode;
}
