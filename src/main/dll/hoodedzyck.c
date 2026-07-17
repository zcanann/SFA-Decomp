/*
 * hoodedzyck - the hooded-Zyck flyer baddie: line-probes the ground each frame
 * and toggles its move/visibility, chases the player with a per-frame yaw step,
 * and seeds its move/speed fields on init.
 *
 *   hoodedZyckUpdateWhileFrozen  freeze-event handler.
 *   fn_80156DA0                  per-frame ground probe + move/visibility toggle.
 *   hoodedZyck_updateB           chase/attack update.
 *   hoodedZyck_update            approach update.
 *   hoodedZyck_init              seeds BaddieState speed/move fields.
 */
#include "dolphin/mtx/mtx_legacy.h"
#include "main/frame_timing.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/obj_group.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_query.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
#include "main/dll/player_api.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"

typedef struct DusterState
{
    u8 pad00[0x324];
    f32 phaseTimer; /* 0x324 */
    f32 decoyTimer; /* 0x328 */
    u8 pad32C[0x338 - 0x32C];
    u16 turnDelta; /* 0x338 hooded-zyck per-frame rotY step */
} DusterState;

typedef struct FCVars
{
    u8 pad000[0x324];
    f32 engineTimer; /* 0x324 */
    f32 emergeTimer; /* 0x328 */
    u8 pad32c[0x338 - 0x32c];
    u16 turnDelta; /* 0x338 */
} FCVars;

#define FIRECRAWLER_HIT_VOLUME_SLOT      9
#define LANTERNFIREFLY_OBJGROUP 0x30 /* DLL 0x10C lanternfirefly */

extern f32 lbl_803DBCE0;
extern f32 lbl_803DBCE4;
extern f32 lbl_803DBCE8;
extern f32 lbl_803DBCEC;
extern f32 lbl_803E2B18;
extern f32 lbl_803E2B28;
extern f32 lbl_803E2B2C;
extern f32 lbl_803E2B30;
extern f32 lbl_803E2B34;
extern f32 lbl_803E2B38;
extern f32 lbl_803E2B3C;
extern f32 lbl_803E2B40;
extern f32 lbl_803E2B44;
extern f32 lbl_803E2B48;
extern f32 lbl_803E2B4C;
extern f32 lbl_803E2B50;
extern f32 lbl_803E2B60;
extern f32 lbl_803E2B64;
extern f32 lbl_803E2B68;
extern f32 lbl_803E2B6C;
extern f32 lbl_803E2B70;
extern f32 lbl_803E2B74;
extern f32 lbl_803E2B78;

void hoodedZyckUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_244);
        ((BaddieState*)state)->hitCounter = 0;
    }
    return;
}

void fn_80156DA0(GameObject* obj, int state)
{
    bool resetting;
    int groundHit;
    u8 noHit;
    int randBit;
    float toPos[3];
    float fromPos[3];
    float cosYaw;
    float sinYaw;
    float hitOut[22];

    ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
    if (((DusterState*)state)->phaseTimer <= lbl_803E2B18)
    {
        ((DusterState*)state)->phaseTimer = (float)(int)randomGetRange(0x3c, 0x78);
    }
    if (lbl_803E2B18 != ((DusterState*)state)->decoyTimer)
    {
        ObjHits_DisableObject((int)obj);
        if ((obj)->anim.currentMove != 5)
        {
            Baddie_SetMove(obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject((int)obj);
            ((DusterState*)state)->decoyTimer = lbl_803E2B18;
        }
        (obj)->anim.alpha = 0xff;
        resetting = true;
    }
    else
    {
        resetting = false;
    }
    if (!resetting)
    {
        (obj)->anim.rotX = (short)((obj)->anim.rotX + ((DusterState*)state)->turnDelta);
        fromPos[0] = (obj)->anim.localPosX;
        fromPos[1] = (obj)->anim.localPosY;
        fromPos[2] = (obj)->anim.localPosZ;
        fn_80292E20((u32)(u16)(obj)->anim.rotX, &sinYaw, &cosYaw);
        toPos[0] = (obj)->anim.localPosX - lbl_803E2B38 * sinYaw;
        toPos[1] = lbl_803E2B3C + (obj)->anim.localPosY;
        toPos[2] = (obj)->anim.localPosZ - lbl_803E2B38 * cosYaw;
        groundHit = objBboxFn_800640cc(fromPos, toPos, lbl_803E2B18, 3, (TrackBBoxHit*)hitOut,
                                       (GameObject*)obj,
                                       (u32) * (u8*)(state + 0x261),
                                       0xffffffff, 0xff, 0);
        noHit = !(groundHit & 0xff);
        if (!noHit || ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0))
        {
            if (noHit && (obj)->anim.currentMove != 0)
            {
                ((DusterState*)state)->turnDelta = 0;
                Baddie_SetMove(obj, state, 0, lbl_803E2B40, 0, 1);
            }
            else
            {
                float fz;
                Baddie_SetMove(obj, state, 1, lbl_803E2B44, 0, 0);
                fz = lbl_803E2B18;
                (obj)->anim.velocityX = fz;
                (obj)->anim.velocityY = fz;
                (obj)->anim.velocityZ = fz;
                randBit = randomGetRange(0, 1);
                ((DusterState*)state)->turnDelta = (u16)((randBit - 1) * 0x12c);
            }
        }
        (obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
        (obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    }
    return;
}

void hoodedZyck_updateB(s16* obj, u8* state)
{
    f32 scale;
    int moved;
    int turnRaw;
    u8 noHit;
    u16 mag;
    u8 bufA[88];
    u8 bufB[84];
    f32 tgtA[3];
    f32 posA[3];
    f32 tgtB[3];
    f32 posB[3];
    f32 range;
    f32 cosA;
    f32 sinA;
    f32 cosB;
    f32 sinB;

    {
        u8 n = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x2f);
        scale = n;
        if (lbl_803E2B18 == n)
        {
            scale = lbl_803E2B38;
        }
        scale = scale / lbl_803E2B38;
    }

    ((FCVars*)state)->engineTimer = ((FCVars*)state)->engineTimer - timeDelta;
    if (((FCVars*)state)->engineTimer <= lbl_803E2B18)
    {
        ((FCVars*)state)->engineTimer = (f32)(int)randomGetRange(0x3c, 0x78);
    }

    if (lbl_803E2B18 != ((FCVars*)state)->emergeTimer)
    {
        ObjHits_DisableObject((int)obj);
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            Baddie_SetMove((int*)obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject((int)obj);
            ((FCVars*)state)->emergeTimer = lbl_803E2B18;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        moved = 1;
    }
    else
    {
        moved = 0;
    }

    if (moved == 0)
    {
        u32 ang;
        f32 diff;
        GameObject* other;

        *(s16*)obj = *(s16*)obj + ((FCVars*)state)->turnDelta;
        posA[0] = ((GameObject*)obj)->anim.localPosX;
        posA[1] = ((GameObject*)obj)->anim.localPosY;
        posA[2] = ((GameObject*)obj)->anim.localPosZ;
        fn_80292E20((u16)((GameObject*)obj)->anim.rotX, &sinA, &cosA);
        tgtA[0] = -(lbl_803E2B38 * sinA - ((GameObject*)obj)->anim.localPosX);
        tgtA[1] = lbl_803E2B3C + ((GameObject*)obj)->anim.localPosY;
        tgtA[2] = -(lbl_803E2B38 * cosA - ((GameObject*)obj)->anim.localPosZ);
        /* 0x261 = BaddieState.contactSfxFlags; kept raw - typed member as a
         * call arg shifts arg emission bytes here. */
        noHit = !(u8)objBboxFn_800640cc(posA, tgtA, lbl_803E2B18, 3, (TrackBBoxHit*)bufA, (GameObject*)obj,
                                        *(u8*)(state + 0x261), -1, 0xff, 0);
        ang =
            getAngle(
                ((GameObject*)obj)->anim.localPosX - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                ((GameObject*)obj)->anim.localPosZ - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ) &
            0xffff;
        diff = (f32)(int)(ang - ((int)*(s16*)obj & 0xffffu));
        if (diff > lbl_803E2B2C)
        {
            diff = lbl_803E2B28 + diff;
        }
        if (diff < lbl_803E2B34)
        {
            diff = lbl_803E2B30 + diff;
        }
        turnRaw = diff;
        {
            s16 t = turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        if (fn_80295C88(Obj_GetPlayerObject()) != 0)
        {
            range = lbl_803E2B48;
            other = (GameObject*)ObjGroup_FindNearestObject(LANTERNFIREFLY_OBJGROUP, (int)obj, &range);
            if (other != NULL)
            {
                s16 yaw = Obj_GetYawDeltaToObject((GameObject*)obj, other, &range);
                int t;
                if (yaw < -300)
                {
                    yaw = -300;
                }
                else if (yaw > 300)
                {
                    yaw = 300;
                }
                t = yaw;
                ((FCVars*)state)->turnDelta = t;
                t = yaw >= 0 ? yaw : -yaw;
                if (t < 0x4000)
                {
                    *(s16*)obj = -*(s16*)obj;
                    posB[0] = ((GameObject*)obj)->anim.localPosX;
                    posB[1] = ((GameObject*)obj)->anim.localPosY;
                    posB[2] = ((GameObject*)obj)->anim.localPosZ;
                    fn_80292E20((u16)((GameObject*)obj)->anim.rotX, &sinB, &cosB);
                    tgtB[0] = -(lbl_803E2B38 * sinB - ((GameObject*)obj)->anim.localPosX);
                    tgtB[1] = lbl_803E2B3C + ((GameObject*)obj)->anim.localPosY;
                    tgtB[2] = -(lbl_803E2B38 * cosB - ((GameObject*)obj)->anim.localPosZ);
                    if ((u8)objBboxFn_800640cc(posB, tgtB, lbl_803E2B18, 3, (TrackBBoxHit*)bufB, (GameObject*)obj,
                                               *(u8*)(state + 0x261), -1, 0xff, 0) == 0)
                    {
                        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
                        {
                            Baddie_SetMove((int*)obj, state, 7, lbl_803E2B40 / (lbl_803E2B4C * scale), 0, 1);
                        }
                        ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
                        ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
                    }
                    *(s16*)obj = -*(s16*)obj;
                }
                return;
            }
        }
        if (((BaddieState*)state)->trackedObj != NULL &&
            ((GameObject*)((BaddieState*)state)->trackedObj)->anim.hitboxScale > lbl_803E2B50)
        {
            ((BaddieState*)state)->speedScale = lbl_803DBCE8;
        }
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 || noHit == 0 ||
            (mag < 3000 && noHit != 0 && ((GameObject*)obj)->anim.currentMove != 0))
        {
            if (noHit != 0 && mag < 3000)
            {
                ((FCVars*)state)->turnDelta = 0;
                Baddie_SetMove((int*)obj, state, 0, lbl_803E2B40 / scale, 0, 1);
            }
            else
            {
                Baddie_SetMove((int*)obj, state, 1, lbl_803E2B44 / scale, 0, 0);
                {
                    f32 z = lbl_803E2B18;
                    ((GameObject*)obj)->anim.velocityX = z;
                    ((GameObject*)obj)->anim.velocityY = z;
                    ((GameObject*)obj)->anim.velocityZ = z;
                }
                if (mag < 3000)
                {
                    ((FCVars*)state)->turnDelta = (randomGetRange(0, 1) - 1) * 300;
                }
                else if ((s16)turnRaw < 0)
                {
                    ((FCVars*)state)->turnDelta = 0xfed4;
                }
                else
                {
                    ((FCVars*)state)->turnDelta = 300;
                }
            }
        }
        ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
        ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    }
}

void hoodedZyck_update(s16* obj, u8* state)
{
    int moved;
    int turnRaw;
    u16 mag;
    u32 grabbed;

    ((FCVars*)state)->engineTimer = ((FCVars*)state)->engineTimer - timeDelta;
    if (((FCVars*)state)->engineTimer <= lbl_803E2B18)
    {
        ((FCVars*)state)->engineTimer = (f32)(int)randomGetRange(0x3c, 0x78);
    }

    if (lbl_803E2B18 != ((FCVars*)state)->emergeTimer)
    {
        ObjHits_DisableObject((int)obj);
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            Baddie_SetMove((int*)obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject((int)obj);
            ((FCVars*)state)->emergeTimer = lbl_803E2B18;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        moved = 1;
    }
    else
    {
        moved = 0;
    }

    if (moved == 0)
    {
        f32 diff;
        f32 z;
        u32 ang;
        *(s16*)obj = (f32)((FCVars*)state)->turnDelta * timeDelta + (f32)(int)*obj;
        z = lbl_803E2B18;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FIRECRAWLER_HIT_VOLUME_SLOT, 1, -1);
        ang =
            getAngle(
                ((GameObject*)obj)->anim.localPosX - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                ((GameObject*)obj)->anim.localPosZ - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ) &
            0xffff;
        diff = (f32)(int)(ang - ((int)*(s16*)obj & 0xffffu));
        if (diff > lbl_803E2B2C)
        {
            diff = lbl_803E2B28 + diff;
        }
        if (diff < lbl_803E2B34)
        {
            diff = lbl_803E2B30 + diff;
        }
        turnRaw = diff;
        {
            int t = (s16)turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        ObjHits_EnableObject((int)obj);
        grabbed = ((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN;
        if (grabbed != 0 && ((GameObject*)obj)->anim.currentMove == 6)
        {
            Baddie_SetMove((int*)obj, state, 4, lbl_803DBCE0, 0, 1);
        }
        else
        {
            if (grabbed != 0 ||
                (mag < 1000 && ((GameObject*)obj)->anim.currentMove != 2 && ((GameObject*)obj)->anim.currentMove != 4 &&
                 ((GameObject*)obj)->anim.currentMove != 6))
            {
                if (mag < 1000)
                {
                    if (((BaddieState*)state)->speedScale < lbl_803E2B60)
                    {
                        Baddie_SetMove((int*)obj, state, 2, lbl_803E2B44, 0, 0);
                    }
                    else
                    {
                        Baddie_SetMove((int*)obj, state, 6, lbl_803DBCE4, 0, 0);
                    }
                    ((FCVars*)state)->turnDelta = 0;
                }
                else
                {
                    Baddie_SetMove((int*)obj, state, 1, lbl_803E2B44, 0, 0);
                    if ((s16)turnRaw < 0)
                    {
                        ((FCVars*)state)->turnDelta = 0xfed4;
                    }
                    else
                    {
                        ((FCVars*)state)->turnDelta = 300;
                    }
                }
            }
            ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
            ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
        }
    }
}

void hoodedZyck_init(int* obj, int* st)
{
    f32 ratio;
    f32 base_v;
    u32 v;
    u32 amt;
    amt = *((u8*)((int*)*(int*)&((GameObject*)obj)->anim.placementData) + 0x2f);
    ratio = amt;
    if (lbl_803E2B18 == amt)
    {
        ratio = lbl_803E2B38;
    }
    ratio = ratio / lbl_803E2B38;
    ((BaddieState*)st)->speedScale = lbl_803E2B64;
    *(u32*)&((BaddieState*)st)->unk2E4 = 0x8b;
    v = *(u32*)&((BaddieState*)st)->unk2E4;
    *(u32*)&((BaddieState*)st)->unk2E4 = v | 0x20;
    ((BaddieState*)st)->unk308 = lbl_803E2B68 * ratio;
    base_v = lbl_803E2B40;
    ((BaddieState*)st)->animDeltaScale = base_v;
    ((BaddieState*)st)->unk304 = lbl_803E2B6C;
    *((u8*)st + 0x320) = 0;
    *(f32*)&((BaddieState*)st)->eventFlags = lbl_803E2B70;
    *((u8*)st + 0x321) = 3;
    {
        f32 d2 = lbl_803E2B4C;
        ((BaddieState*)st)->unk318 = d2;
        *((u8*)st + 0x322) = 5;
        ((BaddieState*)st)->unk31C = d2;
    }
    ((FCVars*)st)->turnDelta = 0;
    ((FCVars*)st)->engineTimer = lbl_803E2B74;
    ((FCVars*)st)->emergeTimer = base_v;
    ((GameObject*)obj)->anim.alpha = 0;
    ((BaddieState*)st)->pathStep = lbl_803E2B78 * ratio;
    ((BaddieState*)st)->reactionFlags = 0;
    ObjHits_EnableObject((int)obj);
}
