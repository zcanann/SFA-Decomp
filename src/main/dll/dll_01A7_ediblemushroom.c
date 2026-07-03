#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/SH/SHthorntail_internal.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/ediblemushroom.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"
#define EDIBLEMUSHROOM_OBJFLAG_HIDDEN 0x4000
#define EDIBLEMUSHROOM_OBJFLAG_PARENT_SLACK 0x1000
#define EDIBLEMUSHROOM_OBJFLAG_RENDERED 0x800
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern int hitDetectFn_80065e50(void* obj, f32 x, f32 y, f32 z, void* hitsOut, int p6, int p7);
extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, void* obj,
                              int p7, int p8, int p9, int p10);

extern int getAngle(float y, float x);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern void itemPickupDoParticleFx(u8* obj, f32 scale, int mode, int count);
extern void ObjMsg_SendToObject(u8* obj, int msg, u8* sender, void* data);
extern int objMove(u8* obj, f32 dx, f32 dy, f32 dz);
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern const f32 lbl_803E5288;
extern f32 lbl_803E528C;
extern f32 lbl_803E5290;
extern f32 lbl_803E5294;
extern f32 lbl_803E5298;
extern f32 lbl_803E529C;
extern f32 lbl_803E52A0;
extern f32 lbl_803E52A4;
extern f32 lbl_803E52A8;
extern f32 lbl_803E52AC;
extern f32 lbl_803E52B0;
extern f32 gEdibleMushroomPi;
extern f32 gEdibleMushroomAngleToRadDivisor;
extern f32 lbl_803E52D0;
extern f32 lbl_803E52D4;
extern f32 lbl_803E52D8;
extern f32 lbl_803E52DC;
extern s16 gEdibleMushroomMoveIdTable[];
extern f32 gEdibleMushroomAnimEventTable[];

s16 fn_801D129C(u8* obj, u8* player, u8* state, f32 dist);

extern int objIsFrozen(u8* obj);
extern int gameBitIncrement(int bit);
extern int ObjMsg_Pop(u8* obj, int* outMsg, int a, int b);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void Obj_StartModelFadeIn(u8* obj, int frames);
extern void Obj_SetModelColorFadeRecursive(u8* obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf);
extern f32 sqrtf(f32 x);
extern void ObjGroup_AddObject(u32 obj, int group);
extern int ObjMsg_Pop();
extern void ObjMsg_AllocQueue();
extern f32 Vec_distance(int a, int b);
extern f32 lbl_803E52E0;
extern f32 lbl_803E52E4;
extern f32 gEdibleMushroomByteNormScale;
extern f32 lbl_803E52EC;
extern f32 lbl_803E52F0;
extern f32 lbl_803E52F4;

#pragma optimization_level 2
void edibleMushroomFn_801d083c(u8* obj, u8* state, u8* other)
{
    u8* player;
    int sval;
    u32 k;
    int curMove;
    int moveId;
    int bit;
    f32 dz;
    f32 dx;
    f32 speed;
    f32 rangeSq;
    f32 t;
    s16 ang;
    f32 animOut[7];
    struct
    {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } fx;
    f32 sunTime;

    player = Obj_GetPlayerObject();

    if (((EdibleMushroomState*)state)->flags & 4)
    {
        ((EdibleMushroomState*)state)->animState = 6;
    }

    speed = oneOverTimeDelta * (((EdibleMushroomState*)state)->previousTargetDistance - ((EdibleMushroomState*)state)->
        currentTargetDistance);

    sval = ((EdibleMushroomState*)state)->animState;
    switch (sval)
    {
    case 0:
        if (((EdibleMushroomState*)state)->flags & 0x10)
        {
            ((EdibleMushroomState*)state)->animState = 9;
        }
        else if ((*gSkyInterface)->getSunPosition(&sunTime) == 0)
        {
            if (((EdibleMushroomState*)state)->currentTargetDistance < other[0x19])
            {
                if (((EdibleMushroomState*)state)->flags & 2)
                {
                    rangeSq = ((EdibleMushroomState*)state)->lungeRange * ((EdibleMushroomState*)state)->lungeRange;
                    while (1)
                    {
                        dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                        dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                        if (dx * dx + dz * dz < rangeSq)
                        {
                            if (Curve_AdvanceAlongPath(((RomCurveWalker*)state), ((EdibleMushroomState*)state)->curveAdvanceStep) != 0 ||
                                ((RomCurveWalker*)state)->atSegmentEnd != 0)
                            {
                                (*gRomCurveInterface)->goNextPoint(((RomCurveWalker*)state));
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    ang = getAngle(-dx, -dz);
                    ((EdibleMushroomState*)state)->moveAngle = ang;
                }
                else
                {
                    ((EdibleMushroomState*)state)->moveAngle =
                        fn_801D129C(obj, player, state, ((EdibleMushroomState*)state)->lungeRange);
                }
                ((EdibleMushroomState*)state)->animState = 1;
                Sfx_PlayFromObject((u32)obj, SFXTRIG_mushrele16);
                ((GameObject*)obj)->anim.rotX = (s16)(((EdibleMushroomState*)state)->moveAngle - 0x4000);
            }
            else if (((EdibleMushroomState*)state)->currentTargetDistance < other[0x1f])
            {
                ((EdibleMushroomState*)state)->animState = 3;
            }
        }
        else
        {
            t = (((EdibleMushroomState*)state)->tailSwingFxTimer -= timeDelta);
            if (t <= lbl_803E5288)
            {
                if (((GameObject*)obj)->objectFlags & EDIBLEMUSHROOM_OBJFLAG_RENDERED)
                {
                    fx.x = ((GameObject*)obj)->anim.worldPosX;
                    fx.y = lbl_803E528C + ((GameObject*)obj)->anim.worldPosY;
                    fx.z = ((GameObject*)obj)->anim.worldPosZ;
                    (*gPartfxInterface)->spawnObject(obj, 0x7f0, &fx,
                                                     0x200001, -1, NULL);
                }
                ((EdibleMushroomState*)state)->tailSwingFxTimer = lbl_803E5290;
            }
        }
        break;
    case 1:
        if (((EdibleMushroomState*)state)->flags & 0x10)
        {
            ((EdibleMushroomState*)state)->animState = 9;
        }
        else if (((EdibleMushroomState*)state)->flags & 1)
        {
            ((EdibleMushroomState*)state)->animState = 0;
        }
        break;
    case 3:
    case 7:
        if (((EdibleMushroomState*)state)->flags & 0x10)
        {
            ((EdibleMushroomState*)state)->animState = 9;
            break;
        }
        if (((EdibleMushroomState*)state)->flags & 1)
        {
            if (sval == 3u)
            {
                ((EdibleMushroomState*)state)->animState = 4;
            }
            else
            {
                ((EdibleMushroomState*)state)->animState = 0;
            }
            break;
        }
        /* fall through */
    case 4:
        if (((EdibleMushroomState*)state)->flags & 0x10)
        {
            ((EdibleMushroomState*)state)->animState = 9;
        }
        else
        {
            ang = getAngle(-(((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX),
                           -(((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ));
            ((GameObject*)obj)->anim.rotX = ang;
            if (((EdibleMushroomState*)state)->currentTargetDistance > lbl_803E5294 + other[0x1f])
            {
                ((EdibleMushroomState*)state)->animState = 7;
            }
            else if (((EdibleMushroomState*)state)->currentTargetDistance < other[0x19])
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_mushrele16);
                if (speed >= lbl_803E5298)
                {
                    if (((EdibleMushroomState*)state)->flags & 2)
                    {
                        rangeSq = ((EdibleMushroomState*)state)->lungeRange * ((EdibleMushroomState*)state)->
                            lungeRange;
                        while (1)
                        {
                            dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                            dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                            if (dx * dx + dz * dz < rangeSq)
                            {
                                if (Curve_AdvanceAlongPath(((RomCurveWalker*)state), ((EdibleMushroomState*)state)->curveAdvanceStep) != 0 ||
                                    ((RomCurveWalker*)state)->atSegmentEnd != 0)
                                {
                                    (*gRomCurveInterface)->goNextPoint(((RomCurveWalker*)state));
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        ((EdibleMushroomState*)state)->moveAngle = ang;
                    }
                    else
                    {
                        ((EdibleMushroomState*)state)->moveAngle =
                            fn_801D129C(obj, player, state, ((EdibleMushroomState*)state)->lungeRange);
                    }
                    ((EdibleMushroomState*)state)->animState = 1;
                    ((GameObject*)obj)->anim.rotX = (s16)(((EdibleMushroomState*)state)->moveAngle - 0x4000);
                }
                else
                {
                    if (((EdibleMushroomState*)state)->flags & 2)
                    {
                        rangeSq = ((EdibleMushroomState*)state)->retreatRange * ((EdibleMushroomState*)state)->retreatRange;
                        while (1)
                        {
                            dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                            dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                            if (dx * dx + dz * dz < rangeSq)
                            {
                                if (Curve_AdvanceAlongPath(((RomCurveWalker*)state), ((EdibleMushroomState*)state)->curveAdvanceStep) != 0 ||
                                    ((RomCurveWalker*)state)->atSegmentEnd != 0)
                                {
                                    (*gRomCurveInterface)->goNextPoint(((RomCurveWalker*)state));
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        ((EdibleMushroomState*)state)->moveAngle = ang;
                    }
                    else
                    {
                        ((EdibleMushroomState*)state)->moveAngle =
                            fn_801D129C(obj, player, state, ((EdibleMushroomState*)state)->retreatRange);
                    }
                    ((EdibleMushroomState*)state)->animState = 5;
                    ((GameObject*)obj)->anim.rotX = ((EdibleMushroomState*)state)->moveAngle;
                }
            }
        }
        break;
    case 5:
        if ((((EdibleMushroomState*)state)->flags & 0x11) == 0x11)
        {
            ((EdibleMushroomState*)state)->animState = 9;
        }
        if (((EdibleMushroomState*)state)->currentTargetDistance > lbl_803E5294 + other[0x19] && (((EdibleMushroomState
            *)state)->flags & 1))
        {
            ((EdibleMushroomState*)state)->animState = 4;
        }
        else if (speed >= lbl_803E5298)
        {
            if (((EdibleMushroomState*)state)->flags & 2)
            {
                rangeSq = ((EdibleMushroomState*)state)->lungeRange * ((EdibleMushroomState*)state)->lungeRange;
                while (1)
                {
                    dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                    dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                    if (dx * dx + dz * dz < rangeSq)
                    {
                        if (Curve_AdvanceAlongPath(((RomCurveWalker*)state), ((EdibleMushroomState*)state)->curveAdvanceStep) != 0 ||
                            ((RomCurveWalker*)state)->atSegmentEnd != 0)
                        {
                            (*gRomCurveInterface)->goNextPoint(((RomCurveWalker*)state));
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                ang = getAngle(-dx, -dz);
                ((EdibleMushroomState*)state)->moveAngle = ang;
            }
            else
            {
                ((EdibleMushroomState*)state)->moveAngle = fn_801D129C(obj, player, state,
                                                                    ((EdibleMushroomState*)state)->lungeRange);
            }
            ((EdibleMushroomState*)state)->animState = 1;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_mushrele16);
            ((GameObject*)obj)->anim.rotX = (s16)(((EdibleMushroomState*)state)->moveAngle - 0x4000);
        }
        break;
    case 9:
        ObjHits_ClearSourceMask((int)obj, 1);
        Sfx_KeepAliveLoopedObjectSound((u32)obj, SFXTRIG_cagelp_c);
        if (((EdibleMushroomState*)state)->burrowAttackTimer <= lbl_803E5288)
        {
            ((EdibleMushroomState*)state)->burrowAttackTimer = (f32)(int)
            randomGetRange(0xf0, 0x12c);
        }
        t = ((EdibleMushroomState*)state)->burrowAttackTimer - timeDelta;
        ((EdibleMushroomState*)state)->burrowAttackTimer = t;
        if (t <= lbl_803E5288)
        {
            ObjHits_SetSourceMask((int)obj, 1);
            (*gExpgfxInterface)->freeSource((int)obj);
            ((EdibleMushroomState*)state)->animState = 0;
            ((EdibleMushroomState*)state)->flags &= ~0x10;
        }
        else
        {
            t = ((EdibleMushroomState*)state)->sporePuffTimer - timeDelta;
            ((EdibleMushroomState*)state)->sporePuffTimer = t;
            if (t <= lbl_803E5288)
            {
                fx.x = lbl_803E5294;
                fx.y = lbl_803E529C;
                if (((GameObject*)obj)->objectFlags & EDIBLEMUSHROOM_OBJFLAG_RENDERED)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x51d, &fx, 2, -1,
                                                     NULL);
                }
                ((EdibleMushroomState*)state)->sporePuffTimer = lbl_803E52A0;
            }
            if (GameBit_Get(0x12e) == 0)
            {
                if (!(((GameObject*)player)->objectFlags & EDIBLEMUSHROOM_OBJFLAG_PARENT_SLACK))
                {
                    if (Vec_xzDistance((f32*)(player + 0x18), &((GameObject*)obj)->anim.worldPosX) <
                        lbl_803E52A4)
                    {
                        (*gExpgfxInterface)->freeSource((int)obj);
                        if (((GameObject*)obj)->anim.seqId == 0x658)
                        {
                            ((EdibleMushroomState*)state)->pickupMsgBitId = 0x18a;
                            itemPickupDoParticleFx(obj, lbl_803E52A8, 0xff, 0x28);
                        }
                        else
                        {
                            ((EdibleMushroomState*)state)->pickupMsgBitId = 0x119;
                            itemPickupDoParticleFx(obj, lbl_803E52A8, 6, 0x28);
                        }
                        ((EdibleMushroomState*)state)->pickupMsgValue = 0;
                        ((EdibleMushroomState*)state)->pickupMsgDelay = lbl_803E52AC;
                        ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x13c);
                        bit = *(s16*)(other + 0x1a);
                        if (bit != -1)
                        {
                            GameBit_Set(bit, 1);
                        }
                        ((EdibleMushroomState*)state)->animState = 8;
                        GameBit_Set(0x12e, 1);
                    }
                }
            }
        }
        break;
    case 6:
        if (((EdibleMushroomState*)state)->flags & 0x10)
        {
            ((EdibleMushroomState*)state)->animState = 9;
        }
        break;
    case 2:
    case 8:
    case 10:
        break;
    }

    curMove = ((GameObject*)obj)->anim.currentMove;
    moveId = gEdibleMushroomMoveIdTable[((EdibleMushroomState*)state)->animState];
    if (curMove != moveId && moveId != -1)
    {
        ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E52B0, 0);
    }

    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, gEdibleMushroomAnimEventTable[((EdibleMushroomState*)state)->animState], timeDelta, (ObjAnimEventList*)animOut) != 0)
    {
        ((EdibleMushroomState*)state)->flags |= 1;
    }
    else
    {
        ((EdibleMushroomState*)state)->flags &= ~1;
    }

    k = ((EdibleMushroomState*)state)->animState;
    if (k == 1)
    {
        speed = ((EdibleMushroomState*)state)->lungeRootSpeedScale * (animOut[0] * oneOverTimeDelta);
    }
    else if (k == 5)
    {
        speed = animOut[2] * oneOverTimeDelta;
    }
    else
    {
        speed = lbl_803E5288;
    }

    if (lbl_803E5288 != speed)
    {
        ((EdibleMushroomState*)state)->flags |= 8;
    }
    else
    {
        ((EdibleMushroomState*)state)->flags &= ~8;
    }

    ((GameObject*)obj)->anim.velocityX =
        speed * mathSinf((gEdibleMushroomPi * (f32)((EdibleMushroomState*)state)->moveAngle) / gEdibleMushroomAngleToRadDivisor);
    ((GameObject*)obj)->anim.velocityZ =
        speed * mathCosf((gEdibleMushroomPi * (f32)((EdibleMushroomState*)state)->moveAngle) / gEdibleMushroomAngleToRadDivisor);

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, lbl_803E5288,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
}
#pragma optimization_level reset

s16 fn_801D129C(u8* obj, u8* player, u8* state, f32 dist)
{
    s16 angle;
    s16 anglePlus;
    s16 angleMinus;
    int i;
    f32 rad;
    f32 c;
    f32 s;
    f32 cosM;
    f32 cosP;
    f32 sinM;
    f32 sinP;
    f32 cosStepP;
    f32 cosStepM;
    f32 sinStepP;
    f32 sinStepM;
    f32 vec[3];

    angle = getAngle(-(((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX),
                     -(((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ));
    rad = (gEdibleMushroomPi * angle) / gEdibleMushroomAngleToRadDivisor;
    c = mathSinf(rad);
    s = mathCosf(rad);
    vec[0] = ((GameObject*)obj)->anim.localPosX - dist * c;
    vec[1] = ((GameObject*)obj)->anim.localPosY;
    vec[2] = ((GameObject*)obj)->anim.localPosZ - dist * s;
    if (objBboxFn_800640cc(obj + 0xc, vec, lbl_803E52D0, 3, 0, obj, 8, -1, 0xff, 0) != 0)
    {
        anglePlus = angle;
        angleMinus = angle;
        cosM = c;
        cosP = c;
        cosStepP = mathSinf(lbl_803E52D4);
        cosStepM = mathSinf(lbl_803E52D8);
        sinP = s;
        sinM = s;
        sinStepP = mathCosf(lbl_803E52D4);
        sinStepM = mathCosf(lbl_803E52D8);
        for (i = 0; i < 8; i++)
        {
            f32 t;

            anglePlus += 0xe38;
            t = cosP * sinStepP + sinP * cosStepP;
            sinP = sinP * sinStepP - cosP * cosStepP;
            cosP = t;
            vec[0] = ((GameObject*)obj)->anim.localPosX - dist * t;
            vec[2] = ((GameObject*)obj)->anim.localPosZ - dist * sinP;
            if (objBboxFn_800640cc(obj + 0xc, vec, lbl_803E52D0, 1, 0, obj, 8, -1, 0xff, 0) == 0)
            {
                return anglePlus;
            }
            angleMinus -= 0xe38;
            t = cosM * sinStepM + sinM * cosStepM;
            sinM = sinM * sinStepM - cosM * cosStepM;
            cosM = t;
            vec[0] = ((GameObject*)obj)->anim.localPosX - dist * t;
            vec[2] = ((GameObject*)obj)->anim.localPosZ - dist * sinM;
            if (objBboxFn_800640cc(obj + 0xc, vec, lbl_803E52D0, 1, 0, obj, 8, -1, 0xff, 0) == 0)
            {
                return angleMinus;
            }
        }
    }
    return angle;
}

void ediblemushroom_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x47);
    ObjGroup_RemoveObject(obj, 0x31);
}

int ediblemushroom_getExtraSize(void)
{
    return 0x144;
}

void ediblemushroom_hitDetect(u8* obj)
{
    u8* state;
    u8* mapObj;
    int hitCount;
    f32** hits;
    int i;
    u8 bboxHit[0x54];

    state = ((GameObject*)obj)->extra;
    mapObj = *(u8**)&((GameObject*)obj)->anim.placementData;

    if (((((GameObject*)obj)->objectFlags & EDIBLEMUSHROOM_OBJFLAG_PARENT_SLACK) == 0) &&
        (((((EdibleMushroomState*)state)->flags & 8) != 0) ||
         ((((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags & 8) != 0)))
    {
        hitCount = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ, &hits, 0, 0);
        for (i = 0; i < hitCount; i++)
        {
            if (*hits[i] < *(f32*)&lbl_803E5294 + ((GameObject*)obj)->anim.localPosY)
            {
                ((GameObject*)obj)->anim.localPosY = *hits[i];
                break;
            }
        }

        hitCount = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E52DC, 2, bboxHit, obj, 8,
                                      -1, 0xff, 0x14);
        if ((mapObj[0x18] == 4) && (hitCount != 0) && ((s8)bboxHit[0x50] == 13))
        {
            ((EdibleMushroomState*)state)->flags |= 4;
        }
    }
}

#pragma opt_loop_invariants off
void ediblemushroom_update(u8* self)
{
    extern void edibleMushroomFn_801d083c(u8 * self, u8 * state, u8 * other); /* #57 */
    u8* state;
    u8* other;
    u8* player;
    u8* enemy;
    int hitObj;
    int msg;
    int hitKind;
    f32 distState;
    f32 distEnemy;

    state = (u8*)*(int*)&((GameObject*)self)->extra;
    other = (u8*)*(int*)&((GameObject*)self)->anim.placementData;
    player = Obj_GetPlayerObject();
    enemy = getTrickyObject();

    if (objIsFrozen(self) != 0) goto end;

    if (((EdibleMushroomState*)state)->animState == 8)
    {
        while (ObjMsg_Pop(self, &msg, 0, 0) != 0)
        {
            if (((u32)msg - 0x70000) != 0xB) continue;
            ((GameObject*)self)->anim.flags = (s16)(((GameObject*)self)->anim.flags | OBJANIM_FLAG_HIDDEN);
            ObjHits_DisableObject((u32)(int)self);
            gameBitIncrement(((EdibleMushroomState*)state)->collectedGameBitId);
            GameBit_Set(0x12E, 0);
            if (((GameObject*)self)->anim.seqId == 0x658)
            {
                itemPickupDoParticleFx(self, lbl_803E52A8, 0xFF, 0x28);
            }
            else
            {
                itemPickupDoParticleFx(self, lbl_803E52A8, 6, 0x28);
            }
            Sfx_PlayFromObject((u32)self, SFXen_waterblock_stop);
        }
        goto end;
    }

    if (((EdibleMushroomState*)state)->seqResetPending != 0)
    {
        ((GameObject*)self)->anim.localPosX = ((EnemyMushroomMapData*)other)->posX;
        ((GameObject*)self)->anim.localPosY = ((EnemyMushroomMapData*)other)->posY;
        ((GameObject*)self)->anim.localPosZ = ((EnemyMushroomMapData*)other)->posZ;
        ((GameObject*)self)->anim.alpha = 0xFF;
        ((EdibleMushroomState*)state)->seqResetPending = 0;
    }

    ((EdibleMushroomState*)state)->previousTargetDistance = ((EdibleMushroomState*)state)->currentTargetDistance;
    distState = vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(self + 0x18));
    if (enemy == NULL)
    {
        ((EdibleMushroomState*)state)->currentTargetDistance = sqrtf(distState);
    }
    else
    {
        distEnemy = vec3f_distanceSquared((f32*)(enemy + 0x18), (f32*)(self + 0x18));
        if (distState < distEnemy)
        {
            ((EdibleMushroomState*)state)->currentTargetDistance = sqrtf(distState);
        }
        else
        {
            ((EdibleMushroomState*)state)->currentTargetDistance = sqrtf(distEnemy);
        }
        if (((EdibleMushroomState*)state)->currentTargetDistance < (f32)(u32)other[0x1F]
        )
        {
            (*(void (**)(u8*, u8*, int, int))(*(int*)*(int*)&((GameObject*)enemy)->anim.dll + 0x28))
                (enemy, self, 0, 1);
        }
    }

    hitKind = ObjHits_GetPriorityHit((int)self, &hitObj, 0, 0);
    if (hitKind != 0)
    {
        if (hitKind == 0x10)
        {
            Obj_StartModelFadeIn(self, 0x12C);
        }
        else
        {
            Obj_SetModelColorFadeRecursive(self, 0xF, 0xC8, 0, 0, 1);
            if (((GameObject*)hitObj)->anim.seqId != 0x416)
            {
                if ((((EdibleMushroomState*)state)->flags & 0x10) == 0)
                {
                    Sfx_PlayFromObject((u32)self, SFXmv_curtainloop16);
                }
                ((EdibleMushroomState*)state)->flags = (u8)(((EdibleMushroomState*)state)->flags | 0x10);
            }
        }
    }
    edibleMushroomFn_801d083c(self, state, other);

end:
    ;
}
#pragma opt_loop_invariants reset

void ediblemushroom_init(int obj, int aux)
{
    int state;
    int player;
    int curveInitParam;
    ObjAnimEventList animEvents;
    f32 dist;

    state = *(int*)&((GameObject*)obj)->extra;
    curveInitParam = 0x19;
    player = (int)Obj_GetPlayerObject();

    ((GameObject*)obj)->animEventCallback = EdibleMushroom_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | EDIBLEMUSHROOM_OBJFLAG_HIDDEN);

    if (GameBit_Get(((EdibleMushroomPlacement*)aux)->gameBitId) != 0)
    {
        ((EdibleMushroomState*)state)->animState = 8;
        ObjHits_DisableObject((u32)obj);
        ((GameObject*)obj)->anim.flags = (short)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }

    ((GameObject*)obj)->anim.modelState->flags |= 0x810;

    ((EdibleMushroomState*)state)->lungeRootSpeedScale = lbl_803E52E0;
    ((EdibleMushroomState*)state)->mapParamScale = lbl_803E52E4 *
        ((f32)((EdibleMushroomPlacement*)aux)->paramByte / gEdibleMushroomByteNormScale);

    ObjAnim_SetCurrentMove(obj, 1, lbl_803E5288, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E52A8, *(f32*)&lbl_803E52A8, &animEvents);
    ((EdibleMushroomState*)state)->lungeRange = animEvents.rootDeltaX;
    if (((EdibleMushroomState*)state)->lungeRange < lbl_803E5288)
    {
        ((EdibleMushroomState*)state)->lungeRange = -((EdibleMushroomState*)state)->lungeRange;
    }
    ((EdibleMushroomState*)state)->lungeRange = ((EdibleMushroomState*)state)->lungeRange * ((EdibleMushroomState*)state)->
        lungeRootSpeedScale;
    ((EdibleMushroomState*)state)->lungeRange = ((EdibleMushroomState*)state)->lungeRange + lbl_803E52A0;

    ObjAnim_SetCurrentMove(obj, 4, lbl_803E5288, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E52A8, *(f32*)&lbl_803E52A8, &animEvents);
    ((EdibleMushroomState*)state)->retreatRange = animEvents.rootDeltaZ;
    if (((EdibleMushroomState*)state)->retreatRange < lbl_803E5288)
    {
        ((EdibleMushroomState*)state)->retreatRange = -((EdibleMushroomState*)state)->retreatRange;
    }
    ((EdibleMushroomState*)state)->retreatRange = ((EdibleMushroomState*)state)->retreatRange + lbl_803E52A0;

    ObjMsg_AllocQueue(obj, 1);

    {
        int v = ((EdibleMushroomPlacement*)aux)->objectTypeParam;
        switch (v)
        {
        case 4:
        case 5:
            ((EdibleMushroomState*)state)->flags |= 2;
            (*gRomCurveInterface)->initCurve((void*)state, (void*)obj, lbl_803E52EC, &curveInitParam, -1);
            ((GameObject*)obj)->anim.localPosX = ((EdibleMushroomState*)state)->curve.posX;
            ((GameObject*)obj)->anim.localPosZ = ((EdibleMushroomState*)state)->curve.posZ;
            break;
        }
    }

    ((EdibleMushroomState*)state)->curveAdvanceStep = lbl_803E52F0;

    if ((void*)player != NULL)
    {
        dist = Vec_distance(player + 0x18, obj + 0x18);
        ((EdibleMushroomState*)state)->currentTargetDistance = dist;
        ((EdibleMushroomState*)state)->previousTargetDistance = dist;
    }
    else
    {
        f32 z = lbl_803E52F4;
        ((EdibleMushroomState*)state)->currentTargetDistance = z;
        ((EdibleMushroomState*)state)->previousTargetDistance = z;
    }

    ObjGroup_AddObject(obj, 0x31);
    ObjGroup_AddObject(obj, 0x47);

    if (((GameObject*)obj)->anim.seqId == 0x658)
    {
        ((EdibleMushroomState*)state)->collectedGameBitId = 0x66d;
    }
    else
    {
        ((EdibleMushroomState*)state)->collectedGameBitId = 0xc1;
    }
}

f32 gEdibleMushroomAnimEventTable[] =
{
    0.005f, 0.01f, 0.005f, 0.01f, 0.01f, 0.015f, 0.005f, 0.01f, 0.005f, 0.012f, 0.0f
};

ObjectDescriptor gEdibleMushroomObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ediblemushroom_init,
    (ObjectDescriptorCallback)ediblemushroom_update,
    (ObjectDescriptorCallback)ediblemushroom_hitDetect,
    0,
    (ObjectDescriptorCallback)ediblemushroom_free,
    0,
    ediblemushroom_getExtraSize,
};
