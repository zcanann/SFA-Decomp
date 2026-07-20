/*
 * Scarab (DLL 0x106) - GreenScarab/RedScarab/GoldScarab/RainScarab money
 * beetles. TU = 0x801843C0..0x80185868.
 */
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
#include "main/model.h"
#include "main/dll/player_api.h"
#include "main/track_bbox_api.h"
#include "main/obj_message.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/dll/dll_0106_scarab.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/track_dolphin_api.h"

/* the scarab pickup variants this DLL drives; retail OBJECTS.bin names, all DLL 0x106 */
#define SCARAB_OBJ_GREEN 0x3d3 /* GreenScarab */
#define SCARAB_OBJ_RED   0x3d4 /* RedScarab */
#define SCARAB_OBJ_GOLD  0x3d5 /* GoldScarab */
#define SCARAB_OBJ_RAIN  0x3d6 /* RainScarab */
#define SCARAB_OBJ_BEAN  0x3df /* Blue_bean */

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
extern f32 gScarabZero;
extern f32 gScarabNormScale;
extern f32 gScarabScaleOne;
extern f32 gScarabBurstScale;
extern f32 gScarabFallVelCap;
extern f32 gScarabGravity;
extern f32 gScarabGreenBounce;
extern f32 gScarabRedBounce;
extern f32 gScarabGoldBounce;
extern f32 gScarabRainBounce;
extern f32 gScarabRiseSpeed;
extern f32 gScarabFleeRiseVel;
extern f32 gScarabGroundSearchInit;
extern f32 gScarabHeadingYawOffset;
extern f32 gScarabLeashDist;
extern f32 gScarabBelowGroundWeight;
extern f32 gScarabPickupXZDist;
extern f32 gScarabPickupRange;
extern f32 gScarabRainKnockback;
const ScarabVec3 sScarabStartInit = {0.0f, 0.0f, 0.0f};
const ScarabVec3 sScarabEndInit = {0.0f, 0.0f, 0.0f};
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
        results.radii[0] = 8.0f;
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

typedef struct GuardianAngleParams
{
    s16 a, b, c;
    f32 w;
    f32 x, y, z;
} GuardianAngleParams;

void scarab_applyOrientation(GameObject* obj, TrackGroundHit* groundHit, u8 mode, f32* p3)
{
    f32* velCache = obj->extra;
    GuardianAngleParams rotParams;
    f32 buf[3];

    if (mode == 1)
    {
        buf[0] = groundHit->normalX;
        buf[1] = groundHit->normalY;
        buf[2] = groundHit->normalZ;
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
        obj->anim.velocityX = p3[0];
        obj->anim.velocityZ = p3[2];
        sq = obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ;
        if (sq != gScarabZero)
        {
            sq = sqrtf(sq);
        }
        obj->anim.velocityX = obj->anim.velocityX / (d = gScarabNormScale * sq);
        obj->anim.velocityZ = obj->anim.velocityZ / d;
        velCache[0] = obj->anim.velocityX;
        velCache[1] = obj->anim.velocityZ;
        obj->anim.rotX = (u16)getAngle(-p3[0], -p3[2]);
        return;
    }

    rotParams.x = gScarabZero;
    rotParams.y = gScarabZero;
    rotParams.z = gScarabZero;
    rotParams.w = gScarabScaleOne;
    rotParams.c = 0;
    rotParams.b = 0;
    rotParams.a = obj->anim.rotX;

    vecRotateZXY(&rotParams.a, buf);

    if (groundHit)
    {
        u16 a = getAngle(buf[0], buf[1]);
        obj->anim.rotY = (u16)getAngle(buf[2], buf[1]);
        obj->anim.rotZ = a;
    }
    else
    {
        obj->anim.rotZ = 0;
        obj->anim.rotY = getAngle(p3[0] + p3[2], p3[1]);
        if (obj->anim.rotY < 0)
        {
            obj->anim.rotY *= -1;
        }
        obj->anim.rotX = getAngle(p3[0], p3[2]);
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
    ObjModel* model;
    u8* shellColors;
    int i;

    state = *(int*)&obj->extra;
    model = Obj_GetActiveModel(obj);
    if (obj->anim.seqId == SCARAB_OBJ_RAIN)
    {
        i = 0;
        shellColors = gScarabColorVariantsD;
        for (; i < 7; i++)
        {
            if (*shellColors == model->textureRefs->unk08)
            {
                i++;
                if (i == 7)
                {
                    i = 0;
                }
                model->textureRefs->unk08 = (gScarabColorVariantsD)[i];
                break;
            }
            shellColors++;
        }
    }

    if (((ScarabState*)state)->despawnTimer == 0)
    {
        if (obj->userData2 != 0)
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

        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, gScarabScaleOne);
        if ((visible != 0) && (obj->anim.alpha != 0))
        {
            objfx_spawnDirectionalBurst(obj, 5, gScarabScaleOne, ((ScarabState*)state)->burstModel, 1, 0x14,
                                        gScarabBurstScale, 0, 0);
        }
    }
}

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
    typedef union
    {
        u32 packed;
        u8 values[4];
    } ScarabMoney;

    struct
    {
        TrackBBoxHit bboxHit;
        u8 hitBuf[64];
        ScarabSphere sph;
    } bufs;
    ScarabRot rot;
    TrackQueryBounds bounds;
    ScarabVec3 start;
    ScarabVec3 end;
    f32 vsub[3];
    TrackGroundHit** list;
    u32 msg;
    f32 phase;
    ScarabMoney money1;
    ScarabMoney money2;
    ScarabMoney money3;
    GameObject* player;
    ScarabState* state;
    int best[1];
    int flag;
    s8 phaseState;
    s16 mode;
    f32 bestDist;
    f32 deltaY;
    f32 angleF;
    f32 speed;
    u32 ang;
    int yawDelta;
    int count;
    int i;
    u8 hits;

    best[0] = 0;
    list = NULL;
    start = sScarabStartInit;
    end = sScarabEndInit;
    flag = best[0];
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if ((state->flags28 & 1) != 0)
    {
        while (ObjMsg_Pop(obj, &msg, 0, 0) != 0)
        {
            switch (msg)
            {
            case SCARAB_MSG_PICKUP:
                money1.packed = gScarabMoneyValues;
                playerAddMoney(player, money1.values[state->moneyKind]);
                state->despawnTimer = 0x50;
                state->mode = 0;
                state->flags28 &= ~1;
                break;
            }
        }
        if ((state->flags28 & 1) != 0)
        {
            return;
        }
    }
    Sfx_KeepAliveLoopedObjectSoundLimited((u32)obj, SFXTRIG_scarab_runloop, 3);
    mode = state->mode;
    if (mode == 0)
    {
        state->despawnTimer -= framesThisStep;
        if (state->despawnTimer <= 0)
        {
            state->despawnTimer = 0;
            Obj_FreeObject(obj);
        }
    }
    else
    {
        phaseState = state->phase;
        if (phaseState == 0)
        {
            if (obj->anim.hitReactState != NULL)
            {
                ObjHits_EnableObject(obj);
            }
            obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
            if (obj->anim.velocityY > gScarabFallVelCap)
            {
                obj->anim.velocityY = gScarabGravity * timeDelta + obj->anim.velocityY;
            }
            obj->anim.rotZ = obj->anim.rotZ + state->yawSpeed * framesThisStep;
            if (scarab_sweptCollide(obj) != 0)
            {
                flag = 1;
            }
            if (flag == 0)
            {
                flag = objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, gScarabScaleOne, 0,
                                          &bufs.bboxHit, obj, 8, -1, 0, 0);
            }
            if (flag != 0)
            {
                obj->anim.rotZ = 0;
                state->phase = 1;
                state->spawnYaw = obj->anim.rotX;
                if (obj->anim.seqId == SCARAB_OBJ_GREEN)
                {
                    {
                        f32 k = gScarabGreenBounce;
                        state->velX = k * obj->anim.velocityX;
                        state->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == SCARAB_OBJ_RED)
                {
                    {
                        f32 k = gScarabRedBounce;
                        state->velX = k * obj->anim.velocityX;
                        state->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == SCARAB_OBJ_GOLD)
                {
                    {
                        f32 k = gScarabGoldBounce;
                        state->velX = k * obj->anim.velocityX;
                        state->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == SCARAB_OBJ_RAIN)
                {
                    {
                        f32 k = gScarabRainBounce;
                        state->velX = k * obj->anim.velocityX;
                        state->velZ = k * obj->anim.velocityZ;
                    }
                }
                else if (obj->anim.seqId == SCARAB_OBJ_BEAN)
                {
                    f32 fz = gScarabZero;
                    state->velX = fz;
                    state->velZ = fz;
                }
            }
        }
        else if (phaseState == 2 && mode != 0)
        {
            if (state->riseAmount < state->riseLimit)
            {
                f32 spd = gScarabRiseSpeed;
                state->riseAmount = spd * timeDelta + state->riseAmount;
                end.x = spd * (obj->anim.velocityX * timeDelta) + obj->anim.localPosX;
                end.y = spd * timeDelta + obj->anim.localPosY;
                end.z = spd * (obj->anim.velocityZ * timeDelta) + obj->anim.localPosZ;
                start.x = obj->anim.localPosX;
                start.y = obj->anim.localPosY;
                start.z = obj->anim.localPosZ;
                {
                    ScarabSphere* sp;
                    (sp = &bufs.sph)->vals[0] = gScarabZero;
                    sp->a = -1;
                    sp->b = 0;
                    hitDetect_calcSweptSphereBounds(&bounds, &start.x, &end.x, sp->vals, 1);
                }
                hitDetectFn_800691c0(obj, &bounds, 0, 1);
                count = hitDetectFn_80067958(obj, (f32*)&start, (f32*)&end, 1, bufs.hitBuf, 0);
                obj->anim.localPosX = end.x;
                obj->anim.localPosY = end.y;
                obj->anim.localPosZ = end.z;
                if (count != 0)
                {
                    scarab_applyOrientation(obj, 0, 0, (f32*)((u8*)&bufs + 84));
                }
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
            {
                state->fleeTimer = 0xfa;
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c);
                obj->anim.velocityX = player->anim.localPosX - obj->anim.localPosX;
                obj->anim.velocityZ = player->anim.localPosZ - obj->anim.localPosZ;
                obj->anim.rotX = 0;
                speed = obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ;
                if (speed != gScarabZero)
                {
                    speed = sqrtf(speed);
                }
                obj->anim.velocityX = obj->anim.velocityX / (deltaY = gScarabNormScale * speed);
                obj->anim.velocityZ = obj->anim.velocityZ / deltaY;
                obj->anim.rotY = 0;
                obj->anim.velocityY = gScarabFleeRiseVel;
                rot.x = gScarabZero;
                rot.y = gScarabZero;
                rot.z = gScarabZero;
                rot.scale = gScarabScaleOne;
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
                state->phase = 0;
                state->riseAmount = gScarabZero;
                {
                    f32 k = 8.0f;
                    obj->anim.localPosX = k * (obj->anim.velocityX * timeDelta) + obj->anim.localPosX;
                    obj->anim.localPosY = k * (obj->anim.velocityY * timeDelta) + obj->anim.localPosY;
                    obj->anim.localPosZ = k * (obj->anim.velocityZ * timeDelta) + obj->anim.localPosZ;
                }
            }
        }
        else if (phaseState == 1 && mode != 0)
        {
            if (state->fleeTimer == 0)
            {
                best[0] = 0;
                bestDist = gScarabGroundSearchInit;
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
                        deltaY = (deltaY >= *(f32*)&gScarabZero) ? deltaY : -deltaY;
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
                    deltaY = (deltaY >= gScarabZero) ? deltaY : -deltaY;
                    if (deltaY < lbl_803DBDC4)
                    {
                        flag = 1;
                    }
                    else
                    {
                        scarab_applyOrientation(obj, list[best[0]], 1, (f32*)bufs.hitBuf);
                    }
                }
                else
                {
                    obj->anim.localPosY = state->baseY;
                }
                if (obj->anim.seqId != SCARAB_OBJ_RAIN)
                {
                    obj->anim.rotX = (s16)(obj->anim.rotX + randomGetRange(-1460, 1460));
                }
                obj->anim.velocityX = state->velX;
                {
                    f32 fz = gScarabZero;
                    obj->anim.velocityY = fz;
                    obj->anim.velocityZ = state->velZ;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = gScarabScaleOne;
                rot.c = 0;
                rot.b = 0;
                rot.ang = obj->anim.rotX - state->spawnYaw;
                vecRotateZXY(&rot.ang, &obj->anim.velocityX);
                state->mode -= framesThisStep;
                if (state->mode <= 0)
                {
                    if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX,
                                                    obj->anim.hitboxScale * obj->anim.rootMotionScale) == 0)
                    {
                        state->mode = 0;
                    }
                    else
                    {
                        state->mode = 1;
                    }
                }
                if (flag != 0)
                {
                    f32 k;
                    ang = (u16)getAngle(list[best[0]]->normalX, list[best[0]]->normalZ);
                    angleF = ang;
                    angleF = lbl_803DBDCC * angleF + gScarabHeadingYawOffset;
                    obj->anim.rotX = angleF;
                    obj->anim.localPosX = timeDelta * ((k = 8.0f) * list[best[0]]->normalX) + obj->anim.localPosX;
                    obj->anim.localPosZ = timeDelta * (k * list[best[0]]->normalZ) + obj->anim.localPosZ;
                    obj->anim.velocityX = list[best[0]]->normalX;
                    obj->anim.velocityZ = list[best[0]]->normalZ;
                }
                if (flag == 0)
                {
                    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
                    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
                    speed = sqrtf(obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ);
                    ObjAnim_SampleRootCurvePhase(&obj->anim, speed, &phase);
                    ObjAnim_AdvanceCurrentMove((int)obj, phase, timeDelta, NULL);
                }
                flag = objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, gScarabScaleOne, 0,
                                          &bufs.bboxHit, obj, 8, -1, 0, 0);
                {
                    ScarabSphere* sp;
                    (sp = &bufs.sph)->vals[0] = gScarabScaleOne;
                    sp->a = -1;
                    sp->b = 10;
                    hitDetect_calcSweptSphereBounds(&bounds, &obj->anim.previousLocalPosX, &obj->anim.localPosX,
                                                     sp->vals, 1);
                }
                hitDetectFn_800691c0(obj, &bounds, 0, 1);
                hits = hitDetectFn_80067958(obj, &obj->anim.previousLocalPosX, &obj->anim.localPosX, 1, bufs.hitBuf, 0);
                if (flag != 0 ||
                    Vec_distance(&obj->anim.worldPosX, &((ObjPlacement*)obj->anim.placementData)->posX) > gScarabLeashDist ||
                    ((hits & 1) != 0 && (hits & 0x10) == 0))
                {
                    PSVECSubtract(&((ObjPlacement*)obj->anim.placementData)->posX, &obj->anim.localPosX, vsub);
                    ang = (u16)getAngle(vsub[0], vsub[2]);
                    angleF = ang;
                    angleF = lbl_803DBDD0 * angleF + gScarabHeadingYawOffset;
                    obj->anim.rotX = angleF;
                }
            }
            else
            {
                bestDist = gScarabGroundSearchInit;
                count = hitDetectFn_80065e50(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &list,
                                             1, 0);
                for (i = 0; i < count; i++)
                {
                    deltaY = list[i]->height - obj->anim.localPosY;
                    if (deltaY < *(f32*)&gScarabZero)
                    {
                        deltaY = deltaY * *(f32*)&gScarabBelowGroundWeight;
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
                    scarab_applyOrientation(obj, list[best[0]], 1, (f32*)bufs.hitBuf);
                }
                else
                {
                    obj->anim.localPosY = state->baseY;
                }
                state->fleeTimer -= framesThisStep;
                if (state->fleeTimer <= 0)
                {
                    state->fleeTimer = 0;
                }
            }
            if ((state->fleeTimer != 0 || obj->anim.seqId != SCARAB_OBJ_RAIN) &&
                Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < gScarabPickupXZDist)
            {
                deltaY = obj->anim.localPosY - player->anim.localPosY;
                deltaY = (deltaY >= gScarabZero) ? deltaY : -deltaY;
                if (deltaY < gScarabPickupRange)
                {
                    if (mainGetBit(GAMEBIT_SawScarab) == 0)
                    {
                        state->msgParamA = -1;
                        state->msgParamB = 0;
                        state->msgParamC = gScarabScaleOne;
                        ObjMsg_SendToObject(player, SCARAB_MSG_IN_RANGE, obj, (u32)&state->msgParamA);
                        mainSetBits(GAMEBIT_SawScarab, 1);
                        state->flags28 |= 1;
                    }
                    else
                    {
                        money2.packed = gScarabMoneyValues;
                        playerAddMoney(player, money2.values[state->moneyKind]);
                        state->despawnTimer = 0x50;
                        state->mode = 0;
                    }
                    if (obj->anim.hitReactState != NULL)
                    {
                        ObjHits_DisableObject(obj);
                    }
                    Sfx_PlayFromObject((int)obj, (u16)state->pickupSfx);
                    itemPickupDoParticleFx(obj, gScarabScaleOne, state->particleId, 0x28);
                }
            }
            if (state->fleeTimer == 0 && obj->anim.seqId == SCARAB_OBJ_RAIN)
            {
                if (Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < gScarabPickupRange)
                {
                    deltaY = obj->anim.localPosY - player->anim.localPosY;
                    deltaY = (deltaY >= gScarabZero) ? deltaY : -deltaY;
                    if (deltaY < *(f32*)&gScarabPickupRange)
                    {
                        if (mainGetBit(0x1d9) == 0)
                        {
                            ObjMsg_SendToObject(player, SCARAB_MSG_PLAYER_BURST, obj, 1);
                        }
                        {
                            f32 k = gScarabRainKnockback;
                            obj->anim.localPosX = k * -obj->anim.velocityX + obj->anim.localPosX;
                            obj->anim.localPosZ = k * -obj->anim.velocityZ + obj->anim.localPosZ;
                        }
                        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_45);
                    }
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
                {
                    state->fleeTimer = 0xfa;
                    Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c);
                }
            }
            else if (state->fleeTimer != 0 && obj->anim.seqId == SCARAB_OBJ_RAIN &&
                     ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_46);
                money3.packed = gScarabMoneyValues;
                playerAddMoney(player, money3.values[state->moneyKind]);
                state->despawnTimer = 0x50;
                state->mode = 0;
            }
        }
    }
}

void Scarab_init(int* obj, u8* def)
{
    ScarabState* state = ((GameObject*)obj)->extra;
    ObjModel* model;
    state->phase = 0;
    state->mode = ((ScarabPlacement*)def)->mode;
    state->yawSpeed = randomGetRange(0x3e8, 0xfa0);
    state->riseLimit = randomGetRange(0x32, 0x64);
    state->baseY = ((ObjPlacement*)def)->posY;
    model = Obj_GetActiveModel((GameObject*)obj);
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x3d3:
        model->textureRefs->unk08 = (gScarabColorVariantsA)[randomGetRange(0, 2)];
        state->pickupSfx = 0x41;
        state->particleId = 4;
        state->burstModel = 2;
        state->moneyKind = 0;
        break;
    case 0x3d4:
        model->textureRefs->unk08 = (gScarabColorVariantsB)[randomGetRange(0, 1)];
        state->pickupSfx = 0x42;
        state->particleId = 1;
        state->burstModel = 5;
        state->moneyKind = 1;
        break;
    case 0x3d5:
        model->textureRefs->unk08 = (gScarabColorVariantsC)[randomGetRange(0, 3)];
        state->pickupSfx = 0x43;
        state->particleId = 2;
        state->burstModel = 4;
        state->moneyKind = 2;
        break;
    case 0x3d6:
    default:
        model->textureRefs->unk08 = 5;
        state->pickupSfx = 0x44;
        state->particleId = 6;
        state->burstModel = 1;
        state->moneyKind = 3;
        break;
    }
    ObjMsg_AllocQueue(obj, 2);
}
