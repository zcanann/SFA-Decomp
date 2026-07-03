/*
 * Scarab (DLL 0x106) - GreenScarab/RedScarab/GoldScarab/RainScarab money
 * beetles. TU = 0x801843C0..0x80185868.
 */
#include "main/dll/CF/CFguardian.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/dll_0106_scarab.h"
#include "main/audio/sfx_trigger_ids.h"

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern f32 timeDelta;
extern u8 framesThisStep;
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
extern u32 lbl_802C2298[3];
extern u32 lbl_802C22A4[3];
extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern int randomGetRange(int lo, int hi);
extern void vecRotateZXY(void* rotation, f32* outVec);
extern f32 Vec_distance(f32* a, f32* b);
extern void playerAddMoney(int obj, int amount);

extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, void* p5, int obj, int p7, int p8, int p9, int p10);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern int hitDetect_calcSweptSphereBounds(void* bounds, void* start, void* end, void* sphere, int n);
extern int hitDetectFn_800691c0(int obj, void* p2, int p3, int p4);
extern int hitDetectFn_80067958(int obj, void* p2, void* p3, int p4, void* p5, int p6);
void scarab_update(int obj)
{
    extern f32 Vec_xzDistance(f32* a, f32* b);
    extern void PSVECSubtract(void* a, void* b, void* out);
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b);
    typedef struct
    {
        f32 x, y, z;
    } ScarabVec3;
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
    u8 bounds[24];
    ScarabVec3 start;
    ScarabVec3 end;
    f32 vsub[3];
    f32** list;
    int msg;
    f32 phase;
    u32 money1;
    u32 money2;
    u32 money3;
    int player;
    int state;
    int best;
    int flag;
    int ph;
    s16 mode;
    f32 bestDist;
    f32 dy;
    f32 fang;
    f32 sumsq;
    u32 ang;
    int diff;
    int count;
    int i;
    f32** p;
    u8 hits;

    best = 0;
    list = NULL;
    start = *(ScarabVec3*)lbl_802C2298;
    end = *(ScarabVec3*)lbl_802C22A4;
    flag = best;
    state = *(int*)&((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if ((((ScarabState*)state)->flags28 & 1) != 0)
    {
        while (ObjMsg_Pop(obj, &msg, 0, 0) != 0)
        {
            switch (msg)
            {
            case 0x7000b:
                money1 = gScarabMoneyValues;
                playerAddMoney(player, *((u8*)&money1 + ((ScarabState*)state)->moneyKind));
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
            Obj_FreeObject(obj);
        }
    }
    else
    {
        ph = ((ScarabState*)state)->phase;
        if ((s8)ph == 0)
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_EnableObject((u32)obj);
            }
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->
                anim.localPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->
                anim.localPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->
                anim.localPosZ;
            if (((GameObject*)obj)->anim.velocityY > lbl_803E3A08)
            {
                ((GameObject*)obj)->anim.velocityY = lbl_803E3A0C * timeDelta + ((GameObject*)obj)->anim.velocityY;
            }
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + ((ScarabState*)state)->yawSpeed * framesThisStep;
            if (scarab_sweptCollide(obj) != 0)
            {
                flag = 1;
            }
            if (flag == 0)
            {
                flag = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E3A00, 0, bufs.hitResults, obj, 8, -1, 0, 0);
            }
            if (flag != 0)
            {
                ((GameObject*)obj)->anim.rotZ = 0;
                ((ScarabState*)state)->phase = 1;
                ((ScarabState*)state)->spawnYaw = ((GameObject*)obj)->anim.rotX;
                if (((GameObject*)obj)->anim.seqId == 0x3d3)
                {
                    {
                        f32 k = lbl_803E3A10;
                        ((ScarabState*)state)->velX = k * ((GameObject*)obj)->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * ((GameObject*)obj)->anim.velocityZ;
                    }
                }
                else if (((GameObject*)obj)->anim.seqId == 0x3d4)
                {
                    {
                        f32 k = lbl_803E3A14;
                        ((ScarabState*)state)->velX = k * ((GameObject*)obj)->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * ((GameObject*)obj)->anim.velocityZ;
                    }
                }
                else if (((GameObject*)obj)->anim.seqId == 0x3d5)
                {
                    {
                        f32 k = lbl_803E3A18;
                        ((ScarabState*)state)->velX = k * ((GameObject*)obj)->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * ((GameObject*)obj)->anim.velocityZ;
                    }
                }
                else if (((GameObject*)obj)->anim.seqId == 0x3d6)
                {
                    {
                        f32 k = lbl_803E3A1C;
                        ((ScarabState*)state)->velX = k * ((GameObject*)obj)->anim.velocityX;
                        ((ScarabState*)state)->velZ = k * ((GameObject*)obj)->anim.velocityZ;
                    }
                }
                else if (((GameObject*)obj)->anim.seqId == 0x3df)
                {
                    f32 fz = lbl_803E39F8;
                    ((ScarabState*)state)->velX = fz;
                    ((ScarabState*)state)->velZ = fz;
                }
            }
        }
        else if ((s8)ph == 2 && mode != 0)
        {
            if (((ScarabState*)state)->riseAmount < (f32)((ScarabState*)state)->riseLimit)
            {
                f32 spd = lbl_803E3A20;
                ((ScarabState*)state)->riseAmount = spd * timeDelta + ((ScarabState*)state)->riseAmount;
                end.x = spd * (((GameObject*)obj)->anim.velocityX * timeDelta) + ((GameObject*)obj)->anim.localPosX;
                end.y = spd * timeDelta + ((GameObject*)obj)->anim.localPosY;
                end.z = spd * (((GameObject*)obj)->anim.velocityZ * timeDelta) + ((GameObject*)obj)->anim.localPosZ;
                start.x = ((GameObject*)obj)->anim.localPosX;
                start.y = ((GameObject*)obj)->anim.localPosY;
                start.z = ((GameObject*)obj)->anim.localPosZ;
                {
                    ScarabSphere* sp;
                    *(f32*)(sp = &bufs.sph) = lbl_803E39F8;
                    sp->a = -1;
                    sp->b = 0;
                    hitDetect_calcSweptSphereBounds(bounds, &start, &end, sp, 1);
                }
                hitDetectFn_800691c0(obj, bounds, 0, 1);
                count = hitDetectFn_80067958(obj, &start, &end, 1, bufs.hitBuf, 0);
                ((GameObject*)obj)->anim.localPosX = end.x;
                ((GameObject*)obj)->anim.localPosY = end.y;
                ((GameObject*)obj)->anim.localPosZ = end.z;
                if (count != 0)
                {
                    fn_801845FC((u8*)obj, 0, 0, (f32*)((u8*)&bufs + 84));
                }
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
            {
                ((ScarabState*)state)->fleeTimer = 0xfa;
                Sfx_PlayFromObject(obj, SFXen_firlp6);
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.
                    localPosX;
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.
                    localPosZ;
                ((GameObject*)obj)->anim.rotX = 0;
                sumsq = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->
                    anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
                if (sumsq != lbl_803E39F8)
                {
                    sumsq = sqrtf(sumsq);
                }
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX / (dy = lbl_803E39FC * sumsq);
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ / dy;
                ((GameObject*)obj)->anim.rotY = 0;
                ((GameObject*)obj)->anim.velocityY = lbl_803E3A24;
                rot.x = lbl_803E39F8;
                rot.y = lbl_803E39F8;
                rot.z = lbl_803E39F8;
                rot.scale = lbl_803E3A00;
                rot.c = 0;
                rot.b = 0;
                rot.ang = randomGetRange(-10000, 10000);
                vecRotateZXY(&rot, (f32*)(obj + 0x24));
                ang = (u16)getAngle(((GameObject*)obj)->anim.velocityX, -((GameObject*)obj)->anim.velocityZ);
                diff = ((GameObject*)obj)->anim.rotX - ang;
                if (diff > 0x8000)
                {
                    diff += -0xffff;
                }
                if (diff < -0x8000)
                {
                    diff += 0xffff;
                }
                ((GameObject*)obj)->anim.rotX = diff;
                ((ScarabState*)state)->phase = 0;
                ((ScarabState*)state)->riseAmount = lbl_803E39F8;
                {
                    f32 k = lbl_803E39F4;
                    ((GameObject*)obj)->anim.localPosX = k * (((GameObject*)obj)->anim.velocityX * timeDelta) + ((
                        GameObject*)obj)->anim.localPosX;
                    ((GameObject*)obj)->anim.localPosY = k * (((GameObject*)obj)->anim.velocityY * timeDelta) + ((
                        GameObject*)obj)->anim.localPosY;
                    ((GameObject*)obj)->anim.localPosZ = k * (((GameObject*)obj)->anim.velocityZ * timeDelta) + ((
                        GameObject*)obj)->anim.localPosZ;
                }
            }
        }
        else if ((s8)ph == 1 && mode != 0)
        {
            if (((ScarabState*)state)->fleeTimer == 0)
            {
                best = 0;
                bestDist = lbl_803E3A28;
                count = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                             &list, 1, 0);
                for (i = 0; i < count; i++)
                {
                    dy = *list[i] - ((GameObject*)obj)->anim.localPosY;
                    if (dy > lbl_803DBDC8)
                    {
                    }
                    else
                    {
                        dy = (dy >= *(f32*)&lbl_803E39F8) ? dy : -dy;
                        if (dy < bestDist)
                        {
                            best = i;
                            bestDist = dy;
                        }
                    }
                }
                if (list != NULL)
                {
                    ((GameObject*)obj)->anim.localPosY = *list[best];
                    dy = list[best][2];
                    dy = (dy >= lbl_803E39F8) ? dy : -dy;
                    if (dy < lbl_803DBDC4)
                    {
                        flag = 1;
                    }
                    else
                    {
                        fn_801845FC((u8*)obj, list[best], 1, (f32*)bufs.hitBuf);
                    }
                }
                else
                {
                    ((GameObject*)obj)->anim.localPosY = ((ScarabState*)state)->baseY;
                }
                if (((GameObject*)obj)->anim.seqId != 0x3d6)
                {
                    ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + randomGetRange(-1460, 1460));
                }
                *(f32*)((int)obj + 0x24) = ((ScarabState*)state)->velX;
                {
                    f32 fz = lbl_803E39F8;
                    *(f32*)((int)obj + 0x28) = fz;
                    *(f32*)((int)obj + 0x2c) = ((ScarabState*)state)->velZ;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = lbl_803E3A00;
                rot.c = 0;
                rot.b = 0;
                rot.ang = ((GameObject*)obj)->anim.rotX - ((ScarabState*)state)->spawnYaw;
                vecRotateZXY(&rot, (f32*)(obj + 0x24));
                ((ScarabState*)state)->mode -= framesThisStep;
                if (((ScarabState*)state)->mode <= 0)
                {
                    if (ViewFrustum_IsSphereVisible((f32*)(obj + 0xc),
                                                    ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.
                                                    rootMotionScale) == 0)
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
                    ang = (u16)getAngle(list[best][1], list[best][3]);
                    fang = ang;
                    fang = lbl_803DBDCC * fang + lbl_803E3A2C;
                    ((GameObject*)obj)->anim.rotX = fang;
                    ((GameObject*)obj)->anim.localPosX = timeDelta * ((k = lbl_803E39F4) * list[best][1]) + ((GameObject*)obj)
                        ->anim.localPosX;
                    ((GameObject*)obj)->anim.localPosZ = timeDelta * (k * list[best][3]) + ((GameObject*)obj)
                        ->anim.localPosZ;
                    ((GameObject*)obj)->anim.velocityX = list[best][1];
                    ((GameObject*)obj)->anim.velocityZ = list[best][3];
                }
                if (flag == 0)
                {
                    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)
                        obj)->anim.localPosX;
                    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)
                        obj)->anim.localPosZ;
                    sumsq = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                        ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
                    ObjAnim_SampleRootCurvePhase(sumsq, (ObjAnimComponent*)obj, &phase);
                    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, phase, timeDelta, NULL);
                }
                flag = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E3A00, 0, bufs.hitResults, obj, 8, -1, 0, 0);
                {
                    ScarabSphere* sp;
                    *(f32*)(sp = &bufs.sph) = lbl_803E3A00;
                    sp->a = -1;
                    sp->b = 10;
                    hitDetect_calcSweptSphereBounds(bounds, (void*)(obj + 0x80), (void*)(obj + 0xc), sp, 1);
                }
                hitDetectFn_800691c0(obj, bounds, 0, 1);
                hits = hitDetectFn_80067958(obj, (void*)(obj + 0x80), (void*)(obj + 0xc), 1, bufs.hitBuf, 0);
                if (flag != 0 ||
                    Vec_distance((void*)(obj + 0x18), (void*)(*(int*)&((GameObject*)obj)->anim.placementData + 8)) >
                    lbl_803E3A30 ||
                    ((hits & 1) != 0 && (hits & 0x10) == 0))
                {
                    PSVECSubtract((void*)(*(int*)&((GameObject*)obj)->anim.placementData + 8), (void*)(obj + 0xc),
                                  vsub);
                    ang = (u16)getAngle(vsub[0], vsub[2]);
                    fang = ang;
                    fang = lbl_803DBDD0 * fang + lbl_803E3A2C;
                    ((GameObject*)obj)->anim.rotX = fang;
                }
            }
            else
            {
                bestDist = lbl_803E3A28;
                count = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                             &list, 1, 0);
                for (i = 0; i < count; i++)
                {
                    dy = *list[i] - ((GameObject*)obj)->anim.localPosY;
                    if (dy < *(f32*)&lbl_803E39F8)
                    {
                        dy = dy * *(f32*)&lbl_803E3A34;
                    }
                    if (dy < bestDist)
                    {
                        best = i;
                        bestDist = dy;
                    }
                }
                if (list != NULL)
                {
                    ((GameObject*)obj)->anim.localPosY = *list[best];
                    fn_801845FC((u8*)obj, list[best], 1, (f32*)bufs.hitBuf);
                }
                else
                {
                    ((GameObject*)obj)->anim.localPosY = ((ScarabState*)state)->baseY;
                }
                ((ScarabState*)state)->fleeTimer -= framesThisStep;
                if (((ScarabState*)state)->fleeTimer <= 0)
                {
                    ((ScarabState*)state)->fleeTimer = 0;
                }
            }
            if ((((ScarabState*)state)->fleeTimer != 0 || ((GameObject*)obj)->anim.seqId != 0x3d6) &&
                Vec_xzDistance(&((GameObject*)player)->anim.worldPosX, (f32*)(obj + 0x18)) < lbl_803E3A38)
            {
                dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                dy = (dy >= lbl_803E39F8) ? dy : -dy;
                if (dy < lbl_803E3A3C)
                {
                    if (GameBit_Get(0x910) == 0)
                    {
                        ((ScarabState*)state)->msgParamA = -1;
                        ((ScarabState*)state)->msgParamB = 0;
                        ((ScarabState*)state)->msgParamC = lbl_803E3A00;
                        ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x2c);
                        GameBit_Set(0x910, 1);
                        ((ScarabState*)state)->flags28 |= 1;
                    }
                    else
                    {
                        money2 = gScarabMoneyValues;
                        playerAddMoney(player, *((u8*)&money2 + ((ScarabState*)state)->moneyKind));
                        ((ScarabState*)state)->despawnTimer = 0x50;
                        ((ScarabState*)state)->mode = 0;
                    }
                    if (((GameObject*)obj)->anim.hitReactState != NULL)
                    {
                        ObjHits_DisableObject((u32)obj);
                    }
                    Sfx_PlayFromObject(obj, (u16)((ScarabState*)state)->pickupSfx);
                    itemPickupDoParticleFx(obj, lbl_803E3A00, ((ScarabState*)state)->particleId, 0x28);
                }
            }
            if (((ScarabState*)state)->fleeTimer == 0 && ((GameObject*)obj)->anim.seqId == 0x3d6)
            {
                if (Vec_xzDistance(&((GameObject*)player)->anim.worldPosX, (f32*)(obj + 0x18)) < lbl_803E3A3C)
                {
                    dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                    dy = (dy >= lbl_803E39F8) ? dy : -dy;
                    if (dy < *(f32*)&lbl_803E3A3C)
                    {
                        if (GameBit_Get(0x1d9) == 0)
                        {
                            ObjMsg_SendToObject(player, 0x60004, obj, 1);
                        }
                        {
                            f32 k = lbl_803E3A40;
                            ((GameObject*)obj)->anim.localPosX = k * -((GameObject*)obj)->anim.velocityX + ((GameObject
                                *)obj)->anim.localPosX;
                            ((GameObject*)obj)->anim.localPosZ = k * -((GameObject*)obj)->anim.velocityZ + ((GameObject
                                *)obj)->anim.localPosZ;
                        }
                        Sfx_PlayFromObject(obj, SFXen_lwfl1_c);
                    }
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
                {
                    ((ScarabState*)state)->fleeTimer = 0xfa;
                    Sfx_PlayFromObject(obj, SFXen_firlp6);
                }
            }
            else if (((ScarabState*)state)->fleeTimer != 0 && ((GameObject*)obj)->anim.seqId == 0x3d6 &&
                ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
            {
                Sfx_PlayFromObject(obj, SFXen_mossyloop16);
                money3 = gScarabMoneyValues;
                playerAddMoney(player, *((u8*)&money3 + ((ScarabState*)state)->moneyKind));
                ((ScarabState*)state)->despawnTimer = 0x50;
                ((ScarabState*)state)->mode = 0;
            }
        }
    }
}

extern u8 gScarabColorVariantsA;
extern u8 gScarabColorVariantsB;
extern u8 gScarabColorVariantsC;

void scarab_init(int* obj, u8* def)
{
    ScarabState* state = ((GameObject*)obj)->extra;
    int* model;
    state->phase = 0;
    state->mode = *(s16*)((char*)def + 0x1a);
    state->yawSpeed = randomGetRange(0x3e8, 0xfa0);
    state->riseLimit = randomGetRange(0x32, 0x64);
    state->baseY = ((ObjPlacement*)def)->posY;
    model = (int*)Obj_GetActiveModel(obj);
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x3d3:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = (&gScarabColorVariantsA)[randomGetRange(0, 2)];
        state->pickupSfx = 0x41;
        state->particleId = 4;
        state->unk22 = 2;
        state->moneyKind = 0;
        break;
    case 0x3d4:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = (&gScarabColorVariantsB)[randomGetRange(0, 1)];
        state->pickupSfx = 0x42;
        state->particleId = 1;
        state->unk22 = 5;
        state->moneyKind = 1;
        break;
    case 0x3d5:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = (&gScarabColorVariantsC)[randomGetRange(0, 3)];
        state->pickupSfx = 0x43;
        state->particleId = 2;
        state->unk22 = 4;
        state->moneyKind = 2;
        break;
    case 0x3d6:
    default:
        *(u8*)((char*)*(int*)((char*)model + 0x34) + 8) = 5;
        state->pickupSfx = 0x44;
        state->particleId = 6;
        state->unk22 = 1;
        state->moneyKind = 3;
        break;
    }
    ObjMsg_AllocQueue(obj, 2);
}

extern int Obj_GetActiveModel(int obj);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objfx_spawnDirectionalBurst(int obj, u8 idx, f32 scale, int model, int mode, u8 chance,
                                        f32 alpha, int flags, int unused);

extern u8 gScarabColorVariantsD;
extern f32 lbl_803E3A04;

typedef struct GuardianAngleParams
{
    s16 a, b, c;
    f32 w;
    f32 x, y, z;
} GuardianAngleParams;

void fn_801845FC(u8* obj, f32* p2, u8 mode, f32* p3)
{
    extern int getAngle(f32, f32);
    extern f32 sqrtf(f32);
    extern void vecRotateZXY(void*, f32*);
    extern f32 lbl_803E39F8;
    extern f32 lbl_803E39FC;
    extern f32 lbl_803E3A00;
    f32* sub = ((GameObject*)obj)->extra;
    GuardianAngleParams st;
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
        sq = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX
            + ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
        if (sq != lbl_803E39F8)
        {
            sq = sqrtf(sq);
        }
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX / (d = lbl_803E39FC * sq);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ / d;
        sub[0] = ((GameObject*)obj)->anim.velocityX;
        sub[1] = ((GameObject*)obj)->anim.velocityZ;
        ((GameObject*)obj)->anim.rotX = (u16)getAngle(-p3[0], -p3[2]);
        return;
    }

    st.x = lbl_803E39F8;
    st.y = lbl_803E39F8;
    st.z = lbl_803E39F8;
    st.w = lbl_803E3A00;
    st.c = 0;
    st.b = 0;
    st.a = ((GameObject*)obj)->anim.rotX;

    vecRotateZXY(&st, buf);

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

int scarab_getExtraSize(void)
{
    return 0x34;
}

void scarab_free(void)
{
}

void scarab_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state;
    int model;
    u8* shellColors;
    int i;

    state = *(int*)&((GameObject*)obj)->extra;
    model = Obj_GetActiveModel(obj);
    if (((GameObject*)obj)->anim.seqId == 0x3d6)
    {
        i = 0;
        shellColors = &gScarabColorVariantsD;
        for (; i < 7; i++)
        {
            if (*shellColors == *(u8*)(*(int*)(model + 0x34) + 8))
            {
                i++;
                if (i == 7)
                {
                    i = 0;
                }
                *(u8*)(*(int*)(model + 0x34) + 8) = (&gScarabColorVariantsD)[i];
                break;
            }
            shellColors++;
        }
    }

    if (((ScarabState*)state)->despawnTimer == 0)
    {
        if (((GameObject*)obj)->unkF8 != 0)
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

        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3A00);
        if ((visible != 0) && (((GameObject*)obj)->anim.alpha != 0))
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3A00, (u8)((ScarabState*)state)->unk22, 1, 0x14,
                                        lbl_803E3A04, 0, 0);
        }
    }
}

int scarab_sweptCollide(int obj)
{
    extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, f32* startPoints, f32* endPoints, f32* radii, int pointCount);
    extern void hitDetectFn_800691c0(int obj, void* bounds, u32 mask, int flags);
    extern u8 hitDetectFn_80067958(int obj, f32* startPoints, f32* endPoints, int pointCount, void* outHits, int flags);
    extern f32 gScarabSweptHitInfo[4];

    typedef struct HitDetectResults
    {
        f32 hitInfo[4][4];
        f32 radii[4];
        u8 axisTable[12];
        u32 solidFlags[4];
    } HitDetectResults;

    u8* state;
    u32 sweptBounds[6];
    f32 endPoints[12];
    f32 startPoints[12];
    HitDetectResults results;
    int idx;
    u8 hit;

    state = *(u8**)&((GameObject*)obj)->anim.hitReactState;
    if (state != 0)
    {
        endPoints[0] = ((GameObject*)obj)->anim.localPosX;
        endPoints[1] = ((GameObject*)obj)->anim.localPosY;
        endPoints[2] = ((GameObject*)obj)->anim.localPosZ;
        startPoints[0] = ((GameObject*)obj)->anim.previousLocalPosX;
        startPoints[1] = ((GameObject*)obj)->anim.previousLocalPosY;
        startPoints[2] = ((GameObject*)obj)->anim.previousLocalPosZ;
        results.radii[0] = lbl_803E39F4;
        *(s8*)&results.axisTable[0] = -1;
        results.axisTable[4] = 0x3;
    }
    else
    {
        return 0;
    }

    hitDetect_calcSweptSphereBounds(sweptBounds, startPoints, endPoints, results.radii, 1);
    hitDetectFn_800691c0(obj, sweptBounds, ((ObjHitsPriorityState*)state)->trackContactMask, 1);
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
            ((ObjHitsPriorityState*)state)->contactFlags = *(u8*)&((ObjHitsPriorityState*)state)->contactFlags | 2;
            ((GameObject*)obj)->anim.localPosX = ((ObjHitsPriorityState*)state)->contactPosX;
            ((GameObject*)obj)->anim.localPosY = ((ObjHitsPriorityState*)state)->contactPosY;
            ((GameObject*)obj)->anim.localPosZ = ((ObjHitsPriorityState*)state)->contactPosZ;
            ((ObjHitsPriorityState*)state)->localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
            ((ObjHitsPriorityState*)state)->localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
            ((ObjHitsPriorityState*)state)->localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
            return 1;
        }
        ((ObjHitsPriorityState*)state)->contactFlags = *(u8*)&((ObjHitsPriorityState*)state)->contactFlags | 1;
        ((GameObject*)obj)->anim.localPosX = ((ObjHitsPriorityState*)state)->contactPosX;
        ((GameObject*)obj)->anim.localPosY = ((ObjHitsPriorityState*)state)->contactPosY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjHitsPriorityState*)state)->contactPosZ;
        ((ObjHitsPriorityState*)state)->localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
        ((ObjHitsPriorityState*)state)->localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
        ((ObjHitsPriorityState*)state)->localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
        return 1;
    }
    return 0;
}
