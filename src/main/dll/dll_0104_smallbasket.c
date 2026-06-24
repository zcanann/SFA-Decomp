/*
 * smallbasket (DLL 0x104) - a pick-up-and-throw basket/pot object whose
 * extra record is the shared CfperchState (obj+0xB8).
 *
 * smallbasket_init acquires resource 0x5b, joins object group 0x10, seeds a
 * random idle timer, and picks the impact sfx from the spawn seqId
 * (0x3cf -> 0x60, 0x662 -> 0x37d, otherwise 0x4a).
 *
 * smallbasket_update drives the lifecycle: a respawn countdown
 * (CfperchState.unk12) that scatters basket contents and warps the object
 * back to its placement, fade-in via anim.alpha, the carry/throw state
 * machine on unk5/unk9 (A-button grab, charged vs. normal throw via the
 * player query helpers fn_80295BF0/fn_8029669C/fn_802966B4), in-flight
 * physics integration calling smallbasket_resolveCollision each step for swept-sphere
 * ground/wall collision, leash to the placement origin (unkC range), and
 * the periodic ambient sfx (0x6c/0x6d) keyed on the object subtype unk1E.
 *
 * fn_801816F8 spawns the basket "contents" on break/throw: it dispatches on
 * the contents mode (data+0x1e, or a health-weighted random roll when 7),
 * allocating one of several object types (0x3d3/0x3d4/0x3d5 fruit, 0xb/0x3cd
 * effect) and launching it with a randomized outward velocity.
 *
 * objThrowFn_80182504 is the external entry the player code calls to launch
 * a held basket.
 */
#include "main/dll/dll_0104_smallbasket.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/dll/cfperch_state.h"
#include "main/dll/player_status.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/pad.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"

typedef void (*ObjThrowInitFn)(void* obj, f32 vx, f32 vy, f32 vz);

/* mirrors CfperchState for the fields used here, but unk6/unk9 are s8 (not u8)
   - the sign-checked reads in smallbasket_update treat them as signed. */
typedef struct SmallbasketState
{
    u8 pad0[0x5 - 0x0];
    s8 carryState;
    s8 carryAttached;
    u8 pad7[0x9 - 0x7];
    s8 throwState;
    u8 padA[0x14 - 0xA];
    s32 hiddenTimer;
} SmallbasketState;

/* engine/runtime symbols (game bits, object spawn/group, hit-detect, sky,
   player query) and this object's tuning floats (lbl_803Exxxx) - no home
   header in the import skeleton; declared locally. */

extern int randomGetRange(int lo, int hi);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern u8* Obj_SetupObject(u8* setup, int a, int b, int c, void* d);
extern f32 sqrtf(f32 x);
extern int getAngle(float y, float x);
extern void vecRotateZXY(void* in, void* out);
extern f32 gSmallBasketHitVelocity[];
extern const f32 lbl_803E3930;
extern f32 lbl_803E3938;
extern const f32 lbl_803E393C;
extern const f32 lbl_803E3940;
extern const f32 lbl_803E3944;
extern const f32 lbl_803E3948;
extern const f32 lbl_803E394C;
extern const f32 lbl_803E3950;
extern f32 lbl_803E3954;
extern const f32 lbl_803E3958;
extern const f32 lbl_803E395C;
extern const f32 lbl_803E3960;
extern const f32 lbl_803E3964;
extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, void* obj,
                              int p7, int p8, int p9, int p10);
extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, f32* startPoints, f32* endPoints,
                                            f32* radii, int pointCount);
extern void hitDetectFn_800691c0(u8* obj, void* bounds, u32 mask, int flags);
extern u8 hitDetectFn_80067958(u8* obj, f32* startPoints, f32* endPoints, int pointCount,
                               void* outHits, int flags);
extern const f32 lbl_803E3970;
void smallbasket_init(int obj, int def);
void smallbasket_update(int obj);
void smallbasket_render(int obj, int p2, int p3, int p4,
                        int p5, char visible);
extern ModgfxInterface** gModgfxInterface;
extern void* gSmallBasketResource;
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern const f32 lbl_803E3974;
extern void objRenderFn_8003b8f4(void* obj, int p2, int p3, int p4,
                                 int p5, double scale);
extern void* Obj_GetPlayerObject(void);
extern u32 ObjHits_DisableObject();
extern u32 ObjHits_EnableObject();
extern f32 Vec_distance(f32* a, f32* b);

extern void ObjGroup_AddObject(u32 obj, int group);
extern void ObjHits_ClearHitVolumes(int objPtr);
extern void ObjHits_SetHitVolumeSlot(u32 objPtr, int hitVolume, int hitType, int sourceSlot);
extern void ObjHits_SyncObjectPositionIfDirty(u32 objPtr);


extern int ObjTrigger_IsSet(int obj);
extern int playerIsDisguised(int obj);
extern u32 playerGetStateFlag310(int obj);

extern int fn_80295BF0(int obj);
extern int fn_8029669C(int obj);
extern int fn_802966B4(int obj);
extern void ObjMsg_SendToObject(int target, int msg, int obj, u32 value);
extern void fn_801814D0(int obj, int player, int state);
extern f32 getXZDistance(f32* a, f32* b);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E3934;
extern const f32 lbl_803E3978;
extern const f32 lbl_803E397C;
extern const f32 lbl_803E3980;
extern const f32 lbl_803E3984;
extern const f32 lbl_803E3988;
extern const f32 lbl_803E398C;
extern const f32 lbl_803E3990;
extern const f32 lbl_803E3994;
extern f32 lbl_803E3998;

int fn_801816F8(u8* obj, u8* player, u8* dataIn)
{
    GameObject* playerObj;
    int mode;
    u8* data;
    f32* vel;
    u8 slowMo;
    u8* setup;
    u8* spawned;
    int bit;
    int max;
    int ang;
    int diff;
    f32 ratio;
    f32 num;
    f32 den;
    f32 sc;
    f32 mag;
    struct
    {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } spread;

    data = dataIn;
    playerObj = (GameObject*)player;
    slowMo = 0;
    bit = *(s16*)(data + 0x1c);
    if (bit != -1)
    {
        GameBit_Set(bit, 1);
    }
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    if (gSmallBasketHitVelocity[1] < lbl_803E393C)
    {
        slowMo = 1;
    }
    if (data[0x1e] == 7)
    {
        num = (f32)(int)
        Player_GetCurrentHealth((int)player);
        ratio = num;
        den = (f32)(int)
        Player_GetMaxHealth((int)player);
        ratio = ratio / den;
        ratio = ratio * lbl_803E3930;
        if (ratio <= lbl_803E3940)
        {
            mode = 6;
        }
        else if (ratio <= lbl_803E3944)
        {
            if ((int)randomGetRange(0, (s16)(int)(ratio - lbl_803E3940)) < 7)
            {
                mode = 6;
                max = (s16)(den * lbl_803E393C);
                if (max < 1)
                {
                    max = 1;
                }
                randomGetRange(1, max);
            }
            else
            {
                mode = 1;
                randomGetRange(1, 4);
            }
        }
        else
        {
            return 1;
        }
    }
    else
    {
        mode = data[0x1e];
    }

    vel = gSmallBasketHitVelocity;
    switch ((s16)mode)
    {
    case 1:
        setup = Obj_AllocObjectSetup(0x24, 0x3d3);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x1a) = 0x190;
        spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        if (slowMo)
        {
            sc = lbl_803E3948;
            ((GameObject*)spawned)->anim.velocityX = sc * gSmallBasketHitVelocity[0];
            ((GameObject*)spawned)->anim.velocityY = lbl_803E394C * vel[1];
            ((GameObject*)spawned)->anim.velocityZ = sc * vel[2];
        }
        else
        {
            ((GameObject*)spawned)->anim.velocityX =
                ((GameObject*)obj)->anim.localPosX - playerObj->anim.localPosX;
            ((GameObject*)spawned)->anim.velocityZ =
                ((GameObject*)obj)->anim.localPosZ - playerObj->anim.localPosZ;
        }
        mag = ((GameObject*)spawned)->anim.velocityX * ((GameObject*)spawned)->anim.velocityX;
        mag += ((GameObject*)spawned)->anim.velocityZ * ((GameObject*)spawned)->anim.velocityZ;
        if (mag != lbl_803E3938)
        {
            mag = sqrtf(mag);
            ((GameObject*)spawned)->anim.velocityX = ((GameObject*)spawned)->anim.velocityX / mag;
            ((GameObject*)spawned)->anim.velocityZ = ((GameObject*)spawned)->anim.velocityZ / mag;
        }
        ((GameObject*)spawned)->anim.velocityX =
            ((GameObject*)spawned)->anim.velocityX *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityZ =
            ((GameObject*)spawned)->anim.velocityZ *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityY = lbl_803E3958;
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = randomGetRange(-10000, 10000);
        vecRotateZXY(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)
        getAngle(((GameObject*)spawned)->anim.velocityX, -((GameObject*)spawned)->anim.velocityZ);
        diff = ((GameObject*)spawned)->anim.rotX - ang;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        ((GameObject*)spawned)->anim.rotX = diff;
        break;
    case 2:
        setup = Obj_AllocObjectSetup(0x24, 0x3d4);
        *(s8*)(setup + 0x18) = randomGetRange(-0x7f, 0x7e);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x1a) = 0x190;
        spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        if (slowMo)
        {
            sc = lbl_803E3948;
            ((GameObject*)spawned)->anim.velocityX = sc * gSmallBasketHitVelocity[0];
            ((GameObject*)spawned)->anim.velocityY = lbl_803E394C * vel[1];
            ((GameObject*)spawned)->anim.velocityZ = sc * vel[2];
        }
        else
        {
            ((GameObject*)spawned)->anim.velocityX =
                ((GameObject*)obj)->anim.localPosX - playerObj->anim.localPosX;
            ((GameObject*)spawned)->anim.velocityZ =
                ((GameObject*)obj)->anim.localPosZ - playerObj->anim.localPosZ;
        }
        mag = ((GameObject*)spawned)->anim.velocityX * ((GameObject*)spawned)->anim.velocityX;
        mag += ((GameObject*)spawned)->anim.velocityZ * ((GameObject*)spawned)->anim.velocityZ;
        if (mag != lbl_803E3938)
        {
            mag = sqrtf(mag);
            ((GameObject*)spawned)->anim.velocityX = ((GameObject*)spawned)->anim.velocityX / mag;
            ((GameObject*)spawned)->anim.velocityZ = ((GameObject*)spawned)->anim.velocityZ / mag;
        }
        ((GameObject*)spawned)->anim.velocityX =
            ((GameObject*)spawned)->anim.velocityX *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityZ =
            ((GameObject*)spawned)->anim.velocityZ *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityY = lbl_803E3958;
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = randomGetRange(-10000, 10000);
        vecRotateZXY(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)
        getAngle(((GameObject*)spawned)->anim.velocityX, -((GameObject*)spawned)->anim.velocityZ);
        diff = ((GameObject*)spawned)->anim.rotX - ang;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        ((GameObject*)spawned)->anim.rotX = diff;
        break;
    case 3:
        setup = Obj_AllocObjectSetup(0x24, 0x3d5);
        *(s8*)(setup + 0x18) = randomGetRange(-0x7f, 0x7e);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x1a) = 0x7d0;
        spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        if (slowMo)
        {
            sc = lbl_803E3948;
            ((GameObject*)spawned)->anim.velocityX = sc * gSmallBasketHitVelocity[0];
            ((GameObject*)spawned)->anim.velocityY = lbl_803E394C * vel[1];
            ((GameObject*)spawned)->anim.velocityZ = sc * vel[2];
        }
        else
        {
            ((GameObject*)spawned)->anim.velocityX =
                ((GameObject*)obj)->anim.localPosX - playerObj->anim.localPosX;
            ((GameObject*)spawned)->anim.velocityZ =
                ((GameObject*)obj)->anim.localPosZ - playerObj->anim.localPosZ;
        }
        mag = ((GameObject*)spawned)->anim.velocityX * ((GameObject*)spawned)->anim.velocityX;
        mag += ((GameObject*)spawned)->anim.velocityZ * ((GameObject*)spawned)->anim.velocityZ;
        if (mag != lbl_803E3938)
        {
            mag = sqrtf(mag);
            ((GameObject*)spawned)->anim.velocityX = ((GameObject*)spawned)->anim.velocityX / mag;
            ((GameObject*)spawned)->anim.velocityZ = ((GameObject*)spawned)->anim.velocityZ / mag;
        }
        ((GameObject*)spawned)->anim.velocityX =
            ((GameObject*)spawned)->anim.velocityX *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityZ =
            ((GameObject*)spawned)->anim.velocityZ *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityY = lbl_803E3958;
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = randomGetRange(-10000, 10000);
        vecRotateZXY(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)
        getAngle(((GameObject*)spawned)->anim.velocityX, -((GameObject*)spawned)->anim.velocityZ);
        diff = ((GameObject*)spawned)->anim.rotX - ang;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        ((GameObject*)spawned)->anim.rotX = diff;
        break;
    case 5:
    case 6:
        if (data[0x1e] == 5)
        {
            setup = Obj_AllocObjectSetup(0x30, 0xb);
        }
        else
        {
            setup = Obj_AllocObjectSetup(0x30, 0x3cd);
        }
        setup[0x1a] = 0x14;
        *(s16*)(setup + 0x2c) = -1;
        *(s16*)(setup + 0x1c) = -1;
        if ((s8)data[9] != 0)
        {
            ((ObjPlacement*)setup)->posX =
                ((GameObject*)obj)->anim.localPosX + (f32)(int)
            randomGetRange(-0xf, 0xf);
            ((ObjPlacement*)setup)->posY = lbl_803E395C + ((GameObject*)obj)->anim.localPosY;
            ((ObjPlacement*)setup)->posZ =
                ((GameObject*)obj)->anim.localPosZ + (f32)(int)
            randomGetRange(-0xf, 0xf);
        }
        else
        {
            ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
            ((ObjPlacement*)setup)->posY = lbl_803E3960 + ((GameObject*)obj)->anim.localPosY;
            ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        }
        *(s16*)(setup + 0x24) = -1;
        spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        if (slowMo)
        {
            sc = lbl_803E3948;
            ((GameObject*)spawned)->anim.velocityX = sc * gSmallBasketHitVelocity[0];
            ((GameObject*)spawned)->anim.velocityY = lbl_803E394C * vel[1];
            ((GameObject*)spawned)->anim.velocityZ = sc * vel[2];
        }
        mag = ((GameObject*)spawned)->anim.velocityX * ((GameObject*)spawned)->anim.velocityX;
        mag += ((GameObject*)spawned)->anim.velocityZ * ((GameObject*)spawned)->anim.velocityZ;
        if (mag != lbl_803E3938)
        {
            mag = sqrtf(mag);
            ((GameObject*)spawned)->anim.velocityX = ((GameObject*)spawned)->anim.velocityX / (mag = lbl_803E3964 *
                mag);
            ((GameObject*)spawned)->anim.velocityZ = ((GameObject*)spawned)->anim.velocityZ / mag;
        }
        ((GameObject*)spawned)->anim.velocityX =
            ((GameObject*)spawned)->anim.velocityX *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityZ =
            ((GameObject*)spawned)->anim.velocityZ *
            -(lbl_803E3954 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E3950
        )
        ;
        ((GameObject*)spawned)->anim.velocityY = lbl_803E3958;
        (*(ObjThrowInitFn*)(*(int*)*(int*)&((GameObject*)spawned)->anim.dll + 0x2c))(
            spawned, ((GameObject*)spawned)->anim.velocityX, ((GameObject*)spawned)->anim.velocityY,
            ((GameObject*)spawned)->anim.velocityZ);
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = randomGetRange(-10000, 10000);
        vecRotateZXY(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)
        getAngle(((GameObject*)spawned)->anim.velocityX, -((GameObject*)spawned)->anim.velocityZ);
        diff = ((GameObject*)spawned)->anim.rotX - ang;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        ((GameObject*)spawned)->anim.rotX = diff;
        break;
    }
    return 1;
}

int smallbasket_resolveCollision(u8* obj)
{
    typedef struct
    {
        f32 hitInfo[4][4];
        f32 radii[4];
        s8 axes[12];
        u32 solidFlags[4];
    } HitDetectResults;

    u8* st;
    f32* endY;
    f32* endZ;
    s8* axes;
    int idx;
    u8 hit;
    f32 fz;
    HitDetectResults hitResults;
    f32 endPoints[12];
    f32 startPoints[12];
    u32 sweptBounds[6];

    st = *(u8**)&((GameObject*)obj)->anim.hitReactState;
    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E3970, 1, 0, obj, 1, -1, 0xff, 0) != 0)
    {
        ((ObjHitsPriorityState*)st)->contactFlags |= 1;
        ((ObjHitsPriorityState*)st)->localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
        ((ObjHitsPriorityState*)st)->localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
        ((ObjHitsPriorityState*)st)->localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
        fz = lbl_803E3938;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        return 1;
    }

    if ((int)(((ObjHitsPriorityState*)st)->objectHitMask >> 4) != 0 && (s8)st[0x70] == 0)
    {
        endPoints[0] = ((GameObject*)obj)->anim.localPosX;
        *(endY = &endPoints[1]) = ((GameObject*)obj)->anim.localPosY;
        *(endZ = &endPoints[2]) = ((GameObject*)obj)->anim.localPosZ;
        startPoints[0] = ((GameObject*)obj)->anim.previousLocalPosX;
        startPoints[1] = ((GameObject*)obj)->anim.previousLocalPosY;
        startPoints[2] = ((GameObject*)obj)->anim.previousLocalPosZ;
        hitResults.radii[0] = (f32)((ObjHitsPriorityState*)st)->primaryRadius;
        *(axes = hitResults.axes) = -1;
        axes[4] = 3;
    }
    else
    {
        return 0;
    }

    hitDetect_calcSweptSphereBounds(sweptBounds, startPoints, endPoints, hitResults.radii, 1);
    hitDetectFn_800691c0(obj, sweptBounds, ((ObjHitsPriorityState*)st)->trackContactMask, 1);
    hit = hitDetectFn_80067958(obj, startPoints, endPoints, 1, &hitResults, 0);
    if (hit != 0)
    {
        if (hit & 1)
        {
            idx = 0;
        }
        else if (hit & 2)
        {
            idx = 1;
        }
        else if (hit & 4)
        {
            idx = 2;
        }
        else
        {
            idx = 3;
        }
        st[0xac] = axes[idx];
        ((ObjHitsPriorityState*)st)->contactPosX = endPoints[idx * 3];
        ((ObjHitsPriorityState*)st)->contactPosY = endY[idx * 3];
        ((ObjHitsPriorityState*)st)->contactPosZ = endZ[idx * 3];
        gSmallBasketHitVelocity[0] = hitResults.hitInfo[idx][0];
        gSmallBasketHitVelocity[1] = hitResults.hitInfo[idx][1];
        gSmallBasketHitVelocity[2] = hitResults.hitInfo[idx][2];
        gSmallBasketHitVelocity[3] = hitResults.hitInfo[idx][3];
        if (hitResults.solidFlags[idx] != 0)
        {
            ((ObjHitsPriorityState*)st)->contactFlags |= 2;
            ((GameObject*)obj)->anim.localPosX = ((ObjHitsPriorityState*)st)->contactPosX;
            ((GameObject*)obj)->anim.localPosY = ((ObjHitsPriorityState*)st)->contactPosY;
            ((GameObject*)obj)->anim.localPosZ = ((ObjHitsPriorityState*)st)->contactPosZ;
            ((ObjHitsPriorityState*)st)->localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
            ((ObjHitsPriorityState*)st)->localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
            ((ObjHitsPriorityState*)st)->localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
            fz = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityY = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
            return 1;
        }
        else
        {
            ((ObjHitsPriorityState*)st)->contactFlags |= 1;
            ((GameObject*)obj)->anim.localPosX = ((ObjHitsPriorityState*)st)->contactPosX;
            ((GameObject*)obj)->anim.localPosY = ((ObjHitsPriorityState*)st)->contactPosY;
            ((GameObject*)obj)->anim.localPosZ = ((ObjHitsPriorityState*)st)->contactPosZ;
            ((ObjHitsPriorityState*)st)->localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
            ((ObjHitsPriorityState*)st)->localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
            ((ObjHitsPriorityState*)st)->localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
            fz = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityY = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
            return 1;
        }
    }
    return 0;
}

int smallbasket_getExtraSize(void)
{
    return 0x24;
}

void smallbasket_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    Resource_Release(gSmallBasketResource);
    ObjGroup_RemoveObject(obj, 0x10);
}

void objThrowFn_80182504(int obj)
{
    struct LocalArgs
    {
        short f8;
        short fa;
        short fc;
        short pad_e;
        float f10;
        float f14;
        float f18;
        float f1c;
    } local;
    int extra;
    short* player;
    extra = *(int*)&((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    ((SmallbasketState*)extra)->carryAttached = 0;
    ((SmallbasketState*)extra)->carryState = 0;
    ((SmallbasketState*)extra)->throwState = 1;
    ((GameObject*)obj)->anim.velocityY = lbl_803E3958;
    ((GameObject*)obj)->anim.velocityZ = lbl_803E3974;
    local.f14 = lbl_803E3938;
    local.f18 = lbl_803E3938;
    local.f1c = lbl_803E3938;
    local.f10 = lbl_803E3950;
    local.fc = 0;
    local.fa = 0;
    local.f8 = *player;
    vecRotateZXY(&local.f8, &((GameObject*)obj)->anim.velocityX);
}

void smallbasket_render(int obj, int p2, int p3, int p4,
                        int p5, char visible)
{
    int extra;
    int result;
    short field_a;
    extra = *(int*)&((GameObject*)obj)->extra;
    result = (*gMapEventInterface)->shouldNotSaveTime(
        *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14));
    if (result == 0)
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        field_a = *(short*)(extra + 0xa);
        if ((field_a != 0 && field_a <= 0x32) || ((SmallbasketState*)extra)->hiddenTimer != 0)
        {
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        else if (((GameObject*)obj)->unkF8 != 0 && visible != -1)
        {
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        else
        {
            objRenderFn_8003b8f4((void*)obj, p2, p3, p4, p5,
                                 (double)lbl_803E3950);
        }
    }
}

ObjectDescriptor gSmallBasketObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)smallbasket_init,
    (ObjectDescriptorCallback)smallbasket_update,
    0,
    (ObjectDescriptorCallback)smallbasket_render,
    (ObjectDescriptorCallback)smallbasket_free,
    0,
    smallbasket_getExtraSize,
};

typedef struct SmallbasketObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 rotX;
    u8 subtype;
    s16 unk1A;
    f32 unk1C;
    s16 leashRange;
    u8 pad22[0x24 - 0x22];
    f32 unk24;
} SmallbasketObjectDef;

void smallbasket_init(int obj, int def)
{
    int state;
    s16 v1c;
    s16 mode;

    state = *(int*)&((GameObject*)obj)->extra;
    ObjHits_DisableObject(obj);
    ObjGroup_AddObject(obj, 0x10);

    v1c = *(s16*)(def + 0x1c);
    if (v1c == 0)
    {
        ((CfperchState*)state)->respawnDelay = 0;
    }
    else
    {
        ((CfperchState*)state)->respawnDelay = v1c * 0x3c;
    }

    gSmallBasketResource = Resource_Acquire(0x5b, 1);
    ((CfperchState*)state)->randomTimer = (s16)(randomGetRange(0, 0x64) + 0x12c);
    ((CfperchState*)state)->unk1F = (u8)((SmallbasketObjectDef*)def)->unk1A;
    ((GameObject*)obj)->anim.rotX = (s16)(((SmallbasketObjectDef*)def)->rotX << 8);
    ((CfperchState*)state)->enableGameBit = *(s16*)(def + 0x1e);
    ((CfperchState*)state)->leashRange = ((SmallbasketObjectDef*)def)->leashRange;
    if (((CfperchState*)state)->leashRange == 0)
    {
        ((CfperchState*)state)->leashRange = 0x14;
    }
    ((CfperchState*)state)->respawnTimer = 0x320;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((CfperchState*)state)->subtype = ((SmallbasketObjectDef*)def)->subtype;
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosZ;

    if ((u32)GameBit_Get(((CfperchState*)state)->enableGameBit) != 0)
    {
        ((CfperchState*)state)->hiddenTimer = 1;
        ObjHits_DisableObject(obj);
    }

    mode = ((GameObject*)obj)->anim.seqId;
    if (mode == 0x3cf)
    {
        ((CfperchState*)state)->sfxId = 0x60;
    }
    else if (mode == 0x662)
    {
        ((CfperchState*)state)->disguiseGated = 1;
        ((CfperchState*)state)->sfxId = 0x37d;
    }
    else
    {
        ((CfperchState*)state)->sfxId = 0x4a;
    }
}

typedef struct
{
    s16 h0;
    s16 h1;
    s16 h2;
    f32 fx;
    f32 fy;
    f32 fz;
    f32 fw;
} BasketMathArgs;

void smallbasket_update(int obj)
{
    /* int-param redecls override the u8* definitions for these call sites only
       (caller passes int locals); can't live at file scope - conflicts with the
       earlier definitions. #57 */
    extern void smallbasket_resolveCollision(int obj);
    extern void fn_801816F8(int obj, int player, int state);
    int player;
    int def;
    int state;
    int playerState;
    int flag;
    s8 c;
    u8 k;
    int level;
    f32 zf;
    f32 animSpeed;
    BasketMathArgs blk;

    player = (int)Obj_GetPlayerObject();
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    animSpeed = lbl_803E3950;
    (*gSkyInterface)->getClockTime(&animSpeed);
    state = *(int*)&((GameObject*)obj)->extra;
    if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)def)->mapId) == 0)
    {
        return;
    }
    playerState = *(int*)&((GameObject*)player)->extra;
    if (((CfperchState*)state)->respawnTimer <= 0)
    {
        ((CfperchState*)state)->respawnTimer = 800;
        ((CfperchState*)state)->disableTimer = 1;
        ((CfperchState*)state)->throwState = 0;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        fn_801816F8(obj, player, state);
        zf = lbl_803E3938;
        ((GameObject*)obj)->anim.velocityX = zf;
        ((GameObject*)obj)->anim.velocityZ = zf;
    }
    if (((CfperchState*)state)->hiddenTimer != 0)
    {
        flag = 0;
        ((GameObject*)obj)->anim.alpha = flag;
        ((CfperchState*)state)->hiddenTimer -= (s16)(int)(timeDelta * animSpeed);
        if (((CfperchState*)state)->hiddenTimer <= 0)
        {
            if ((Vec_distance(&((GameObject*)obj)->anim.worldPosX,
                    &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) >
                    lbl_803E3930) &&
                (((CfperchState*)state)->enableGameBit == -1))
            {
                flag = 1;
            }
            if (flag == 0)
            {
                ((CfperchState*)state)->hiddenTimer = 1;
            }
            else
            {
                ((CfperchState*)state)->hiddenTimer = 0;
                ((CfperchState*)state)->disableTimer = 0;
                ObjHits_EnableObject(obj);
                ObjHits_SyncObjectPositionIfDirty(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            }
        }
    }
    else
    {
        if (((CfperchState*)state)->carryState != 2)
        {
            level = (int)(lbl_803E3978 * timeDelta + (f32)(u32)((GameObject*)obj)->anim.alpha);
            if (level > 0xff)
            {
                level = 0xff;
            }
            ((GameObject*)obj)->anim.alpha = level;
        }
        if (((CfperchState*)state)->disableTimer != 0)
        {
            ObjHits_DisableObject(obj);
            ((CfperchState*)state)->disableTimer -= framesThisStep;
            if (((CfperchState*)state)->disableTimer <= 0)
            {
                if (((CfperchState*)state)->respawnDelay != 0)
                {
                    ((CfperchState*)state)->hiddenTimer = ((CfperchState*)state)->respawnDelay;
                }
                else
                {
                    ((CfperchState*)state)->hiddenTimer = 1;
                }
                (*gMapEventInterface)->addTime(((ObjPlacement*)def)->mapId, (f32)((CfperchState*)state)->respawnDelay);
                ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)def)->posX;
                ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)def)->posZ;
                ((GameObject*)obj)->anim.previousLocalPosX = ((ObjPlacement*)def)->posX;
                ((GameObject*)obj)->anim.previousLocalPosY = ((ObjPlacement*)def)->posY;
                ((GameObject*)obj)->anim.previousLocalPosZ = ((ObjPlacement*)def)->posZ;
                zf = lbl_803E3938;
                ((GameObject*)obj)->anim.velocityX = zf;
                ((GameObject*)obj)->anim.velocityY = zf;
                ((GameObject*)obj)->anim.velocityZ = zf;
            }
            if (((CfperchState*)state)->disableTimer <= 0x32)
            {
                return;
            }
        }
        if (*(s8*)&((CfperchState*)state)->throwState != 1)
        {
            if (((CfperchState*)state)->carryState == 0)
            {
                flag = 0;
                if (((buttonGetDisabled(0) & 0x100) == 0) && (((GameObject*)obj)->unkF8 == 0) &&
                    (ObjTrigger_IsSet(obj) != 0))
                {
                    ((CfperchState*)state)->unk0 = -0x8000;
                    ((CfperchState*)state)->unk2 = 0;
                    ObjHits_DisableObject(obj);
                    flag = 1;
                }
                ((CfperchState*)state)->carryState = flag;
                if (((CfperchState*)state)->carryState != 0)
                {
                    ((CfperchState*)state)->carryAttached = 1;
                }
                if (((GameObject*)obj)->unkF8 == 0)
                {
                    ObjHits_EnableObject(obj);
                    if ((((CfperchState*)state)->disguiseGated != 0) && (playerIsDisguised(player) == 0))
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                    }
                    else
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
                    }
                }
                ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosZ;
                ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
            }
            else
            {
                ObjHits_DisableObject(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                if ((playerGetStateFlag310(player) & 0x4000) != 0)
                {
                    setAButtonIcon(5);
                }
                else
                {
                    setAButtonIcon(4);
                }
                if ((getButtonsJustPressed(0) & 0x100) != 0)
                {
                    if (fn_80295BF0(player) != 0)
                    {
                        ((CfperchState*)state)->carryAttached = 0;
                        buttonDisable(0, 0x100);
                    }
                    else
                    {
                        Sfx_PlayFromObject(0, 0x10a);
                    }
                }
                if (((GameObject*)obj)->unkF8 == 1)
                {
                    *(u8*)&((CfperchState*)state)->carryState = 2;
                }
                if (((((CfperchState*)state)->carryState == 2) && (((GameObject*)obj)->unkF8 == 0)) ||
                    ((((CfperchState*)state)->disguiseGated != 0) && (playerIsDisguised(player) == 0)))
                {
                    if (fn_8029669C(player) != 0)
                    {
                        *(u8*)&((CfperchState*)state)->carryState = 0;
                        ((CfperchState*)state)->throwState = 1;
                        ((GameObject*)obj)->anim.velocityY = lbl_803E397C * *(f32*)(playerState + 0x298) + lbl_803E3958;
                        ((GameObject*)obj)->anim.velocityZ = lbl_803E3980 * *(f32*)(playerState + 0x298) + lbl_803E3974;
                        blk.fy = lbl_803E3938;
                        blk.fz = lbl_803E3938;
                        blk.fw = lbl_803E3938;
                        blk.fx = lbl_803E3950;
                        blk.h2 = 0;
                        blk.h1 = 0;
                        blk.h0 = ((GameObject*)player)->anim.rotX;
                        if (*(void**)(player + 0x30) != NULL)
                        {
                            blk.h0 = blk.h0 + **(s16**)(player + 0x30);
                        }
                        vecRotateZXY(&blk, &((GameObject*)obj)->anim.velocityX);
                        Sfx_PlayFromObject(obj, 0x6b);
                    }
                    else if (fn_802966B4(player) != 0)
                    {
                        *(u8*)&((CfperchState*)state)->carryState = 0;
                        ((CfperchState*)state)->throwState = 2;
                        zf = lbl_803E3938;
                        ((GameObject*)obj)->anim.velocityX = zf;
                        ((GameObject*)obj)->anim.velocityY = zf;
                        ((GameObject*)obj)->anim.velocityZ = zf;
                        ObjHits_EnableObject(obj);
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                        ObjHits_ClearHitVolumes(obj);
                    }
                    else
                    {
                        *(u8*)&((CfperchState*)state)->carryState = 0;
                        ((CfperchState*)state)->throwState = 1;
                        ((GameObject*)obj)->anim.velocityY = lbl_803E3988 * *(f32*)(playerState + 0x298) + lbl_803E3984;
                        ((GameObject*)obj)->anim.velocityZ = lbl_803E3990 * *(f32*)(playerState + 0x298) + lbl_803E398C;
                        blk.fy = lbl_803E3938;
                        blk.fz = lbl_803E3938;
                        blk.fw = lbl_803E3938;
                        blk.fx = lbl_803E3950;
                        blk.h2 = 0;
                        blk.h1 = 0;
                        blk.h0 = ((GameObject*)player)->anim.rotX;
                        vecRotateZXY(&blk, &((GameObject*)obj)->anim.velocityX);
                        Sfx_PlayFromObject(obj, 0x6b);
                        ((CfperchState*)state)->carryAttached = 0;
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                    }
                }
                if (*(s8*)&((CfperchState*)state)->carryAttached != 0)
                {
                    ((CfperchState*)state)->disableTimer = 0;
                    ((CfperchState*)state)->hiddenTimer = 0;
                    ObjMsg_SendToObject(player, 0x100010, obj,
                                        (((CfperchState*)state)->unk2 << 16) | ((u16)((CfperchState*)state)->unk0));
                }
            }
        }
        else if (*(s8*)&((CfperchState*)state)->throwState != 0)
        {
            ((CfperchState*)state)->respawnTimer -= framesThisStep;
            if (*(s8*)&((CfperchState*)state)->throwState == 1)
            {
                ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
                if (((GameObject*)obj)->anim.velocityY > lbl_803E3994)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E3998 * timeDelta + ((GameObject*)obj)->anim.velocityY;
                }
                ObjHits_EnableObject(obj);
            }
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->
                anim.localPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->
                anim.localPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->
                anim.localPosZ;
            smallbasket_resolveCollision(obj);
            c = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->contactFlags;
            if ((c != 0) && (*(s8*)&((CfperchState*)state)->throwState == 1))
            {
                blk.fy = ((GameObject*)obj)->anim.localPosX;
                blk.fz = ((GameObject*)obj)->anim.localPosY;
                blk.fw = ((GameObject*)obj)->anim.localPosZ;
                objLightFn_8009a1dc((void*)obj, lbl_803E3934, &blk, 1, 0);
                (**(void (**)(int, int, int, int, int, int))(*(int*)gSmallBasketResource + 0x4))(
                    obj, 1, 0, 2, -1, 0);
                Sfx_PlayFromObject(obj, (u16)((CfperchState*)state)->sfxId);
                ((CfperchState*)state)->disableTimer = 0x32;
                ((CfperchState*)state)->throwState = 0;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                fn_801816F8(obj, player, state);
                zf = lbl_803E3938;
                ((GameObject*)obj)->anim.velocityX = zf;
                ((GameObject*)obj)->anim.velocityZ = zf;
                ObjHits_ClearHitVolumes(obj);
            }
            else if ((c != 0) && (*(s8*)&((CfperchState*)state)->throwState == 2))
            {
                zf = lbl_803E3938;
                ((GameObject*)obj)->anim.velocityX = zf;
                ((GameObject*)obj)->anim.velocityZ = zf;
                ((CfperchState*)state)->disableTimer = 500;
                ((CfperchState*)state)->throwState = 0;
                ((GameObject*)obj)->unkF8 = 0;
                ObjHits_EnableObject(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                ObjHits_ClearHitVolumes(obj);
            }
        }
        ((CfperchState*)state)->randomTimer -= framesThisStep;
        if (((CfperchState*)state)->carryState != 0)
        {
            if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(def + 0x8)) >=
                (f32)(((CfperchState*)state)->leashRange * ((CfperchState*)state)->leashRange))
            {
                zf = lbl_803E3938;
                ((GameObject*)obj)->anim.velocityX = zf;
                ((GameObject*)obj)->anim.velocityZ = zf;
                ((CfperchState*)state)->disableTimer = 500;
                ((CfperchState*)state)->throwState = 0;
                ((GameObject*)obj)->unkF8 = 0;
                ObjHits_EnableObject(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                ObjHits_ClearHitVolumes(obj);
            }
        }
        else
        {
            fn_801814D0(obj, player, state);
        }
        if ((((CfperchState*)state)->randomTimer <= 0) && (((CfperchState*)state)->carryState != 0))
        {
            k = ((CfperchState*)state)->subtype;
            if ((k == 5) || (k == 6))
            {
                Sfx_PlayFromObject(obj, 0x6c);
                ((CfperchState*)state)->randomTimer = (s16)(randomGetRange(0, 100) + 0x12c);
            }
            else if (((u8)(k - 1) <= 1) || (k == 3))
            {
                Sfx_PlayFromObject(obj, 0x6d);
                ((CfperchState*)state)->randomTimer = (s16)(randomGetRange(0, 100) + 0x12c);
            }
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
    }
}
