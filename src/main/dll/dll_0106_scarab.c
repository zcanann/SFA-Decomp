/*
 * Scarab (DLL 0x106) - GreenScarab/RedScarab/GoldScarab/RainScarab money
 * beetles. TU = 0x801843C0..0x80185868.
 */
#include "main/dll/CF/CFguardian.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/track_bbox_api.h"
#include "main/obj_message.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_render_legacy.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/dll/dll_0106_scarab.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/track_dolphin_api.h"

u8 gScarabColorVariantsA[4] = {2, 0x13, 0x16, 0};
u8 gScarabColorVariantsB[4] = {0x14, 0x17, 0, 0};
u8 gScarabColorVariantsC[4] = {0, 0, 0, 0x0C};
u8 gScarabColorVariantsD[8] = {0x14, 0, 6, 0x13, 5, 7, 4, 0};
f32 lbl_803DBDC4 = 0.707f;
f32 lbl_803DBDC8 = 10.0f;
f32 lbl_803DBDCC = 1.0f;
f32 lbl_803DBDD0 = 1.0f;

f32 gScarabSweptHitInfo[4];

typedef struct ScarabPlacement
{
    ObjPlacement head;
    u8 pad18[0x1a - 0x18];
    s16 mode; /* 0x1a: ScarabState.mode selector */
} ScarabPlacement;

typedef struct ScarabVec3
{
    f32 x;
    f32 y;
    f32 z;
} ScarabVec3;

STATIC_ASSERT(sizeof(ScarabVec3) == 0xC);

/* shared item-pickup ObjMsg protocol (see dll_00ED_collectible / dll_00FF_magicgem) */
#define SCARAB_MSG_IN_RANGE     0x7000a /* sent to player when the scarab is in grab range */
#define SCARAB_MSG_PICKUP       0x7000b /* player collected: award money and despawn */
#define SCARAB_MSG_PLAYER_BURST 0x60004 /* knock the player back with a burst hit */

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

extern u32 gScarabMoneyValues;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E39FC;
extern f32 lbl_803E3A00;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern f32 lbl_803E3A1C;
extern f32 lbl_803E3A20;
extern f32 lbl_803E3A24;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A2C;
extern f32 lbl_803E3A30;
extern f32 lbl_803E3A34;
extern f32 lbl_803E3A38;
extern f32 lbl_803E3A3C;
extern f32 lbl_803E3A40;
extern f32 lbl_803DBDD0;
extern f32 lbl_803DBDC4;
extern f32 lbl_803DBDC8;
extern f32 lbl_803DBDCC;
const ScarabVec3 sScarabStartInit = {0.0f, 0.0f, 0.0f};
const ScarabVec3 sScarabEndInit = {0.0f, 0.0f, 0.0f};
void Scarab_update(GameObject* obj)
{
    typedef struct
    {
        s16 ang;
        s16 b;
        s16 c;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } ScarabRot;
    typedef struct
    {
        f32 vals[4];
        s8 a;
        u8 pad[3];
        u8 b;
        u8 pad2[27];
    } ScarabSphere;

    struct
    {
        u8 hitResults[84];
        u8 hitBuf[64];
        ScarabSphere sph;
    } bufs;
    ScarabRot rot;
    TrackQueryBounds bounds;
    ScarabVec3 start;
    ScarabVec3 end;
    f32 vsub[3];
    TrackGroundHit** list;
    int msg;
    f32 phase;
    u32 money1;
    u32 money2;
    u32 money3;
    int player;
    int state;
    int best[1];
    int flag;
    int phaseState;
    s16 mode;
    f32 bestDist;
    f32 deltaY;
    f32 angleF;
    f32 speed;
    u32 ang;
    int yawDelta;
    int count;
    int i;
    f32** p;
    u8 hits;

    best[0] = 0;
    list = NULL;
    start = sScarabStartInit;
    end = sScarabEndInit;
    flag = best[0];
    state = *(int*)&obj->extra;
    player = (int)Obj_GetPlayerObject();
    if ((((ScarabState*)state)->flags28 & 1) != 0)
    {
        while (ObjMsg_Pop(obj, (u32*)&msg, 0, 0) != 0)
        {
            switch (msg)
            {
            case SCARAB_MSG_PICKUP:
                money1 = gScarabMoneyValues;
                playerAddMoney((GameObject*)player, *((u8*)&money1 + ((ScarabState*)state)->moneyKind));
                ((ScarabState*)state)->despawnTimer = 0x50;
                ((ScarabState*)state)->mode = 0;
                ((ScarabState*)state)->flags28 &= ~1;
                break;
            }
        }
        if ((((ScarabState*)state)->flags28 & 1) != 0)
        {
            return;
        }
    }
    Sfx_KeepAliveLoopedObjectSoundLimited((u32)obj, SFXTRIG_scarab_runloop, 3);
    mode = ((ScarabState*)state)->mode;
    if (mode == 0)
    {
        ((ScarabState*)state)->despawnTimer -= framesThisStep;
        if (((ScarabState*)state)->despawnTimer <= 0)
        {
            ((ScarabState*)state)->despawnTimer = 0;
            Obj_FreeObject((GameObject*)obj);
        }
    }
    else
    {
        phaseState = ((ScarabState*)state)->phase;
        if ((s8)phaseState == 0)
        {
            if (obj->anim.hitReactState != NULL)
            {
                ObjHits_EnableObject((u32)obj);
            }
            obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
            if (obj->anim.velocityY > lbl_803E3A08)
            {
                obj->anim.velocityY = lbl_803E3A0C * timeDelta + obj->anim.velocityY;
            }
            obj->anim.rotZ = obj->anim.rotZ + ((ScarabState*)state)->yawSpeed * framesThisStep;
            if (scarab_sweptCollide(obj) != 0)
            {
                flag = 1;
            }
            if (flag == 0)
            {
                flag = objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, lbl_803E3A00, 0,
                                          (TrackBBoxHit*)bufs.hitResults, obj, 8, -1, 0, 0);
            }
            if (flag != 0)
            {
                obj->anim.rotZ = 0;
                ((ScarabState*)state)->phase = 1;
                ((ScarabState*)state)->spawnYaw = obj->anim.rotX;
                if (obj->anim.seqId == 0x3d3)
                {
                    {
                        f32 k = lbl_803E3A10;
                        ((ScarabState*)state)->velX = k * obj->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == 0x3d4)
                {
                    {
                        f32 k = lbl_803E3A14;
                        ((ScarabState*)state)->velX = k * obj->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == 0x3d5)
                {
                    {
                        f32 k = lbl_803E3A18;
                        ((ScarabState*)state)->velX = k * obj->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == 0x3d6)
                {
                    {
                        f32 k = lbl_803E3A1C;
                        ((ScarabState*)state)->velX = k * obj->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == 0x3df)
                {
                    f32 fz = lbl_803E39F8;
                    ((ScarabState*)state)->velX = fz;
                    ((ScarabState*)state)->velZ = fz;
                }
            }
        }
        else if ((s8)phaseState == 2 && mode != 0)
        {
            if (((ScarabState*)state)->riseAmount < (f32)((ScarabState*)state)->riseLimit)
            {
                f32 spd = lbl_803E3A20;
                ((ScarabState*)state)->riseAmount = spd * timeDelta + ((ScarabState*)state)->riseAmount;
                end.x = spd * (obj->anim.velocityX * timeDelta) + obj->anim.localPosX;
                end.y = spd * timeDelta + obj->anim.localPosY;
                end.z = spd * (obj->anim.velocityZ * timeDelta) + obj->anim.localPosZ;
                start.x = obj->anim.localPosX;
                start.y = obj->anim.localPosY;
                start.z = obj->anim.localPosZ;
                {
                    ScarabSphere* sp;
                    *(f32*)(sp = &bufs.sph) = lbl_803E39F8;
                    sp->a = -1;
                    sp->b = 0;
                    hitDetect_calcSweptSphereBounds(&bounds, (f32*)&start, (f32*)&end, (f32*)sp, 1);
                }
                hitDetectFn_800691c0(obj, &bounds, 0, 1);
                count = hitDetectFn_80067958(obj, (f32*)&start, (f32*)&end, 1, bufs.hitBuf, 0);
                obj->anim.localPosX = end.x;
                obj->anim.localPosY = end.y;
                obj->anim.localPosZ = end.z;
                if (count != 0)
                {
                    fn_801845FC((u8*)obj, 0, 0, (f32*)((u8*)&bufs + 84));
                }
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
            {
                ((ScarabState*)state)->fleeTimer = 0xfa;
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c);
                obj->anim.velocityX = ((GameObject*)player)->anim.localPosX - obj->anim.localPosX;
                obj->anim.velocityZ = ((GameObject*)player)->anim.localPosZ - obj->anim.localPosZ;
                obj->anim.rotX = 0;
                speed = obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ;
                if (speed != lbl_803E39F8)
                {
                    speed = sqrtf(speed);
                }
                obj->anim.velocityX = obj->anim.velocityX / (deltaY = lbl_803E39FC * speed);
                obj->anim.velocityZ = obj->anim.velocityZ / deltaY;
                obj->anim.rotY = 0;
                obj->anim.velocityY = lbl_803E3A24;
                rot.x = lbl_803E39F8;
                rot.y = lbl_803E39F8;
                rot.z = lbl_803E39F8;
                rot.scale = lbl_803E3A00;
                rot.c = 0;
                rot.b = 0;
                rot.ang = randomGetRange(-10000, 10000);
                vecRotateZXY(&rot.ang, &obj->anim.velocityX);
                ang = (u16)getAngle(obj->anim.velocityX, -obj->anim.velocityZ);
                yawDelta = obj->anim.rotX - ang;
                if (yawDelta > 0x8000)
                {
                    yawDelta += -0xffff;
                }
                if (yawDelta < -0x8000)
                {
                    yawDelta += 0xffff;
                }
                obj->anim.rotX = yawDelta;
                ((ScarabState*)state)->phase = 0;
                ((ScarabState*)state)->riseAmount = lbl_803E39F8;
                {
                    f32 k = lbl_803E39F4;
                    obj->anim.localPosX = k * (obj->anim.velocityX * timeDelta) + obj->anim.localPosX;
                    obj->anim.localPosY = k * (obj->anim.velocityY * timeDelta) + obj->anim.localPosY;
                    obj->anim.localPosZ = k * (obj->anim.velocityZ * timeDelta) + obj->anim.localPosZ;
                }
            }
        }
        else if ((s8)phaseState == 1 && mode != 0)
        {
            if (((ScarabState*)state)->fleeTimer == 0)
            {
                best[0] = 0;
                bestDist = lbl_803E3A28;
                count = hitDetectFn_80065e50(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &list,
                                             1, 0);
                for (i = 0; i < count; i++)
                {
                    deltaY = list[i]->height - obj->anim.localPosY;
                    if (deltaY > lbl_803DBDC8)
                    {
                    }
                    else
                    {
                        deltaY = (deltaY >= *(f32*)&lbl_803E39F8) ? deltaY : -deltaY;
                        if (deltaY < bestDist)
                        {
                            best[0] = i;
                            bestDist = deltaY;
                        }
                    }
                }
                if (list != NULL)
                {
                    obj->anim.localPosY = list[best[0]]->height;
                    deltaY = list[best[0]]->normalY;
                    deltaY = (deltaY >= lbl_803E39F8) ? deltaY : -deltaY;
                    if (deltaY < lbl_803DBDC4)
                    {
                        flag = 1;
                    }
                    else
                    {
                        fn_801845FC((u8*)obj, (f32*)list[best[0]], 1, (f32*)bufs.hitBuf);
                    }
                }
                else
                {
                    obj->anim.localPosY = ((ScarabState*)state)->baseY;
                }
                if (obj->anim.seqId != 0x3d6)
                {
                    obj->anim.rotX = (s16)(obj->anim.rotX + randomGetRange(-1460, 1460));
                }
                obj->anim.velocityX = ((ScarabState*)state)->velX;
                {
                    f32 fz = lbl_803E39F8;
                    obj->anim.velocityY = fz;
                    obj->anim.velocityZ = ((ScarabState*)state)->velZ;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = lbl_803E3A00;
                rot.c = 0;
                rot.b = 0;
                rot.ang = obj->anim.rotX - ((ScarabState*)state)->spawnYaw;
                vecRotateZXY(&rot.ang, &obj->anim.velocityX);
                ((ScarabState*)state)->mode -= framesThisStep;
                if (((ScarabState*)state)->mode <= 0)
                {
                    if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX,
                                                    obj->anim.hitboxScale * obj->anim.rootMotionScale) == 0)
                    {
                        ((ScarabState*)state)->mode = 0;
                    }
                    else
                    {
                        ((ScarabState*)state)->mode = 1;
                    }
                }
                if (flag != 0)
                {
                    f32 k;
                    ang = (u16)getAngle(list[best[0]]->normalX, list[best[0]]->normalZ);
                    angleF = ang;
                    angleF = lbl_803DBDCC * angleF + lbl_803E3A2C;
                    obj->anim.rotX = angleF;
                    obj->anim.localPosX = timeDelta * ((k = lbl_803E39F4) * list[best[0]]->normalX) + obj->anim.localPosX;
                    obj->anim.localPosZ = timeDelta * (k * list[best[0]]->normalZ) + obj->anim.localPosZ;
                    obj->anim.velocityX = list[best[0]]->normalX;
                    obj->anim.velocityZ = list[best[0]]->normalZ;
                }
                if (flag == 0)
                {
                    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
                    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
                    speed = sqrtf(obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ);
                    ObjAnim_SampleRootCurvePhase(speed, (ObjAnimComponent*)obj, &phase);
                    ObjAnim_AdvanceCurrentMove((int)obj, phase, timeDelta, NULL);
                }
                flag = objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, lbl_803E3A00, 0,
                                          (TrackBBoxHit*)bufs.hitResults, obj, 8, -1, 0, 0);
                {
                    ScarabSphere* sp;
                    *(f32*)(sp = &bufs.sph) = lbl_803E3A00;
                    sp->a = -1;
                    sp->b = 10;
                    hitDetect_calcSweptSphereBounds(&bounds, &obj->anim.previousLocalPosX, &obj->anim.localPosX,
                                                     (f32*)sp, 1);
                }
                hitDetectFn_800691c0(obj, &bounds, 0, 1);
                hits = hitDetectFn_80067958(obj, &obj->anim.previousLocalPosX, &obj->anim.localPosX, 1, bufs.hitBuf, 0);
                if (flag != 0 ||
                    Vec_distance(&obj->anim.worldPosX, &((ObjPlacement*)obj->anim.placementData)->posX) > lbl_803E3A30 ||
                    ((hits & 1) != 0 && (hits & 0x10) == 0))
                {
                    PSVECSubtract(&((ObjPlacement*)obj->anim.placementData)->posX, &obj->anim.localPosX, vsub);
                    ang = (u16)getAngle(vsub[0], vsub[2]);
                    angleF = ang;
                    angleF = lbl_803DBDD0 * angleF + lbl_803E3A2C;
                    obj->anim.rotX = angleF;
                }
            }
            else
            {
                bestDist = lbl_803E3A28;
                count = hitDetectFn_80065e50(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &list,
                                             1, 0);
                for (i = 0; i < count; i++)
                {
                    deltaY = list[i]->height - obj->anim.localPosY;
                    if (deltaY < *(f32*)&lbl_803E39F8)
                    {
                        deltaY = deltaY * *(f32*)&lbl_803E3A34;
                    }
                    if (deltaY < bestDist)
                    {
                        best[0] = i;
                        bestDist = deltaY;
                    }
                }
                if (list != NULL)
                {
                    obj->anim.localPosY = list[best[0]]->height;
                    fn_801845FC((u8*)obj, (f32*)list[best[0]], 1, (f32*)bufs.hitBuf);
                }
                else
                {
                    obj->anim.localPosY = ((ScarabState*)state)->baseY;
                }
                ((ScarabState*)state)->fleeTimer -= framesThisStep;
                if (((ScarabState*)state)->fleeTimer <= 0)
                {
                    ((ScarabState*)state)->fleeTimer = 0;
                }
            }
            if ((((ScarabState*)state)->fleeTimer != 0 || obj->anim.seqId != 0x3d6) &&
                Vec_xzDistance(&((GameObject*)player)->anim.worldPosX, &obj->anim.worldPosX) < lbl_803E3A38)
            {
                deltaY = obj->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                deltaY = (deltaY >= lbl_803E39F8) ? deltaY : -deltaY;
                if (deltaY < lbl_803E3A3C)
                {
                    if (mainGetBit(GAMEBIT_SawScarab) == 0)
                    {
                        ((ScarabState*)state)->msgParamA = -1;
                        ((ScarabState*)state)->msgParamB = 0;
                        ((ScarabState*)state)->msgParamC = lbl_803E3A00;
                        ObjMsg_SendToObject((void*)player, SCARAB_MSG_IN_RANGE, obj, state + 0x2c);
                        mainSetBits(GAMEBIT_SawScarab, 1);
                        ((ScarabState*)state)->flags28 |= 1;
                    }
                    else
                    {
                        money2 = gScarabMoneyValues;
                        playerAddMoney((GameObject*)player, *((u8*)&money2 + ((ScarabState*)state)->moneyKind));
                        ((ScarabState*)state)->despawnTimer = 0x50;
                        ((ScarabState*)state)->mode = 0;
                    }
                    if (obj->anim.hitReactState != NULL)
                    {
                        ObjHits_DisableObject((u32)obj);
                    }
                    Sfx_PlayFromObject((int)obj, (u16)((ScarabState*)state)->pickupSfx);
                    itemPickupDoParticleFxLegacy(obj, lbl_803E3A00, ((ScarabState*)state)->particleId, 0x28);
                }
            }
            if (((ScarabState*)state)->fleeTimer == 0 && obj->anim.seqId == 0x3d6)
            {
                if (Vec_xzDistance(&((GameObject*)player)->anim.worldPosX, &obj->anim.worldPosX) < lbl_803E3A3C)
                {
                    deltaY = obj->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                    deltaY = (deltaY >= lbl_803E39F8) ? deltaY : -deltaY;
                    if (deltaY < *(f32*)&lbl_803E3A3C)
                    {
                        if (mainGetBit(0x1d9) == 0)
                        {
                            ObjMsg_SendToObject((void*)player, SCARAB_MSG_PLAYER_BURST, obj, 1);
                        }
                        {
                            f32 k = lbl_803E3A40;
                            obj->anim.localPosX = k * -obj->anim.velocityX + obj->anim.localPosX;
                            obj->anim.localPosZ = k * -obj->anim.velocityZ + obj->anim.localPosZ;
                        }
                        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_45);
                    }
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
                {
                    ((ScarabState*)state)->fleeTimer = 0xfa;
                    Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c);
                }
            }
            else if (((ScarabState*)state)->fleeTimer != 0 && obj->anim.seqId == 0x3d6 &&
                     ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_46);
                money3 = gScarabMoneyValues;
                playerAddMoney((GameObject*)player, *((u8*)&money3 + ((ScarabState*)state)->moneyKind));
                ((ScarabState*)state)->despawnTimer = 0x50;
                ((ScarabState*)state)->mode = 0;
            }
        }
    }
}


void Scarab_init(int* obj, u8* def)
{
    ScarabState* state = ((GameObject*)obj)->extra;
    int* model;
    state->phase = 0;
    state->mode = ((ScarabPlacement*)def)->mode;
    state->yawSpeed = randomGetRange(0x3e8, 0xfa0);
    state->riseLimit = randomGetRange(0x32, 0x64);
    state->baseY = ((ObjPlacement*)def)->posY;
    model = (int*)Obj_GetActiveModel((GameObject*)obj);
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x3d3:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = (gScarabColorVariantsA)[randomGetRange(0, 2)];
        state->pickupSfx = 0x41;
        state->particleId = 4;
        state->burstModel = 2;
        state->moneyKind = 0;
        break;
    case 0x3d4:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = (gScarabColorVariantsB)[randomGetRange(0, 1)];
        state->pickupSfx = 0x42;
        state->particleId = 1;
        state->burstModel = 5;
        state->moneyKind = 1;
        break;
    case 0x3d5:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = (gScarabColorVariantsC)[randomGetRange(0, 3)];
        state->pickupSfx = 0x43;
        state->particleId = 2;
        state->burstModel = 4;
        state->moneyKind = 2;
        break;
    case 0x3d6:
    default:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = 5;
        state->pickupSfx = 0x44;
        state->particleId = 6;
        state->burstModel = 1;
        state->moneyKind = 3;
        break;
    }
    ObjMsg_AllocQueue(obj, 2);
}

extern f32 lbl_803E3A04;

typedef struct GuardianAngleParams
{
    s16 a, b, c;
    f32 w;
    f32 x, y, z;
} GuardianAngleParams;

void fn_801845FC(u8* obj, f32* p2, u8 mode, f32* p3)
{
    f32* velCache = ((GameObject*)obj)->extra;
    GuardianAngleParams rotParams;
    f32 buf[3];

    if (mode == 1)
    {
        buf[0] = p2[1];
        buf[1] = p2[2];
        buf[2] = p2[3];
    }
    else if (mode == 0)
    {
        buf[0] = p3[0];
        buf[1] = p3[1];
        buf[2] = p3[2];
    }
    else if (mode == 2)
    {
        f32 sq, d;
        ((GameObject*)obj)->anim.velocityX = p3[0];
        ((GameObject*)obj)->anim.velocityZ = p3[2];
        sq = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
             ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
        if (sq != lbl_803E39F8)
        {
            sq = sqrtf(sq);
        }
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX / (d = lbl_803E39FC * sq);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ / d;
        velCache[0] = ((GameObject*)obj)->anim.velocityX;
        velCache[1] = ((GameObject*)obj)->anim.velocityZ;
        ((GameObject*)obj)->anim.rotX = (u16)getAngle(-p3[0], -p3[2]);
        return;
    }

    rotParams.x = lbl_803E39F8;
    rotParams.y = lbl_803E39F8;
    rotParams.z = lbl_803E39F8;
    rotParams.w = lbl_803E3A00;
    rotParams.c = 0;
    rotParams.b = 0;
    rotParams.a = ((GameObject*)obj)->anim.rotX;

    vecRotateZXY(&rotParams.a, buf);

    if (p2)
    {
        u16 a = getAngle(buf[0], buf[1]);
        ((GameObject*)obj)->anim.rotY = (u16)getAngle(buf[2], buf[1]);
        ((GameObject*)obj)->anim.rotZ = a;
    }
    else
    {
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rotY = getAngle(p3[0] + p3[2], p3[1]);
        if (((GameObject*)obj)->anim.rotY < 0)
        {
            ((GameObject*)obj)->anim.rotY *= -1;
        }
        ((GameObject*)obj)->anim.rotX = getAngle(p3[0], p3[2]);
    }
}

int Scarab_getExtraSize(void)
{
    return 0x34;
}

void Scarab_free(void)
{
}

void Scarab_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state;
    int model;
    u8* shellColors;
    int i;

    state = *(int*)&obj->extra;
    model = ((int (*)(void*))Obj_GetActiveModel)(obj);
    if (obj->anim.seqId == 0x3d6)
    {
        i = 0;
        shellColors = gScarabColorVariantsD;
        for (; i < 7; i++)
        {
            if (*shellColors == *(u8*)(*(int*)(model + 0x34) + 8))
            {
                i++;
                if (i == 7)
                {
                    i = 0;
                }
                *(u8*)(*(int*)(model + 0x34) + 8) = (gScarabColorVariantsD)[i];
                break;
            }
            shellColors++;
        }
    }

    if (((ScarabState*)state)->despawnTimer == 0)
    {
        if (obj->unkF8 != 0)
        {
            if (visible != -1)
            {
                return;
            }
        }
        else if (visible == 0)
        {
            return;
        }

        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E3A00);
        if ((visible != 0) && (obj->anim.alpha != 0))
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3A00, (u8)((ScarabState*)state)->burstModel, 1, 0x14,
                                        lbl_803E3A04, 0, 0);
        }
    }
}

int scarab_sweptCollide(GameObject* obj)
{
    typedef struct HitDetectResults
    {
        f32 hitInfo[4][4];
        f32 radii[4];
        u8 axisTable[12];
        u32 solidFlags[4];
    } HitDetectResults;

    u8* state;
    TrackQueryBounds sweptBounds;
    f32 endPoints[12];
    f32 startPoints[12];
    HitDetectResults results;
    int idx;
    u8 hit;

    state = *(u8**)&(obj)->anim.hitReactState;
    if (state != 0)
    {
        endPoints[0] = (obj)->anim.localPosX;
        endPoints[1] = (obj)->anim.localPosY;
        endPoints[2] = (obj)->anim.localPosZ;
        startPoints[0] = (obj)->anim.previousLocalPosX;
        startPoints[1] = (obj)->anim.previousLocalPosY;
        startPoints[2] = (obj)->anim.previousLocalPosZ;
        results.radii[0] = lbl_803E39F4;
        *(s8*)&results.axisTable[0] = -1;
        results.axisTable[4] = 0x3;
    }
    else
    {
        return 0;
    }

    hitDetect_calcSweptSphereBounds(&sweptBounds, startPoints, endPoints, results.radii, 1);
    hitDetectFn_800691c0(obj, &sweptBounds, ((ObjHitsPriorityState*)state)->trackContactMask, 1);
    hit = hitDetectFn_80067958(obj, startPoints, endPoints, 1, &results, 0);
    if (hit != 0)
    {
        if ((hit & 1) != 0)
        {
            idx = 0;
        }
        else if ((hit & 2) != 0)
        {
            idx = 1;
        }
        else if ((hit & 4) != 0)
        {
            idx = 2;
        }
        else
        {
            idx = 3;
        }

        *(u8*)&((ObjHitsPriorityState*)state)->contactHitVolume = results.axisTable[idx];
        ((ObjHitsPriorityState*)state)->contactPosX = endPoints[idx * 3];
        ((ObjHitsPriorityState*)state)->contactPosY = endPoints[idx * 3 + 1];
        ((ObjHitsPriorityState*)state)->contactPosZ = endPoints[idx * 3 + 2];
        gScarabSweptHitInfo[0] = results.hitInfo[idx][0];
        gScarabSweptHitInfo[1] = results.hitInfo[idx][1];
        gScarabSweptHitInfo[2] = results.hitInfo[idx][2];
        gScarabSweptHitInfo[3] = results.hitInfo[idx][3];

        if (results.solidFlags[idx] != 0)
        {
            ((ObjHitsPriorityState*)state)->contactFlags =
                *(u8*)&((ObjHitsPriorityState*)state)->contactFlags | OBJHITS_CONTACT_FLAG_KIND_NONZERO;
            (obj)->anim.localPosX = ((ObjHitsPriorityState*)state)->contactPosX;
            (obj)->anim.localPosY = ((ObjHitsPriorityState*)state)->contactPosY;
            (obj)->anim.localPosZ = ((ObjHitsPriorityState*)state)->contactPosZ;
            ((ObjHitsPriorityState*)state)->localPosX = (obj)->anim.previousLocalPosX;
            ((ObjHitsPriorityState*)state)->localPosY = (obj)->anim.previousLocalPosY;
            ((ObjHitsPriorityState*)state)->localPosZ = (obj)->anim.previousLocalPosZ;
            return 1;
        }
        ((ObjHitsPriorityState*)state)->contactFlags =
            *(u8*)&((ObjHitsPriorityState*)state)->contactFlags | OBJHITS_CONTACT_FLAG_KIND0;
        (obj)->anim.localPosX = ((ObjHitsPriorityState*)state)->contactPosX;
        (obj)->anim.localPosY = ((ObjHitsPriorityState*)state)->contactPosY;
        (obj)->anim.localPosZ = ((ObjHitsPriorityState*)state)->contactPosZ;
        ((ObjHitsPriorityState*)state)->localPosX = (obj)->anim.previousLocalPosX;
        ((ObjHitsPriorityState*)state)->localPosY = (obj)->anim.previousLocalPosY;
        ((ObjHitsPriorityState*)state)->localPosZ = (obj)->anim.previousLocalPosZ;
        return 1;
    }
    return 0;
}
