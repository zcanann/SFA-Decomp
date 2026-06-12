#include "main/dll/NW/NWsfx.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/SH/SHthorntail_internal.h"
#include "main/objanim.h"
#include "main/objhits_types.h"

extern undefined8 ObjGroup_RemoveObject();
extern int hitDetectFn_80065e50(void* obj, f32 x, f32 y, f32 z, void* hitsOut, int p6, int p7);
extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, void* obj,
                              int p7, int p8, int p9, int p10);

extern void* Obj_GetPlayerObject(void);
extern int getAngle(f32 dx, f32 dz);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int Curve_AdvanceAlongPath(u8* curve, f32 t);
extern void Sfx_PlayFromObject(u8* obj, int sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(u8* obj, int sfxId);
extern void ObjHits_ClearSourceMask(u8* obj, int mask);
extern void ObjHits_SetSourceMask(u8* obj, int mask);
extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void itemPickupDoParticleFx(u8* obj, f32 scale, int mode, int count);
extern undefined4 ObjMsg_SendToObject(u8* obj, int msg, u8* sender, void* data);
extern void objMove(u8* obj, f32 vx, f32 vy, f32 vz);

extern EffectInterface** gPartfxInterface;

extern f32 timeDelta;
extern f32 oneOverTimeDelta;

extern f32 lbl_803E5288;
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
extern f32 lbl_803E52B4;
extern f32 lbl_803E52B8;
extern f32 lbl_803E52D0;
extern f32 lbl_803E52D4;
extern f32 lbl_803E52D8;
extern f32 lbl_803E52DC;

extern s16 lbl_80326BD0[];
extern f32 lbl_80326BE8[];

/* ediblemushroom extra block (size 0x144 = ediblemushroom_getExtraSize).
 * Head embeds the rom-curve walker record - those offsets stay raw pending
 * the shared RomCurveWalker/curves.h lift. */
typedef struct EdibleMushroomState
{
    u8 curve00[0x108];
    f32 distanceToTarget;
    f32 prevDistance;
    f32 unk110;
    u8 pad114[4];
    f32 detectRadius;
    f32 unk11C;
    f32 unk120;
    f32 unk124;
    f32 unk128;
    f32 unk12C;
    s16 unk130;
    u8 pad132[4];
    u8 unk136;
    u8 unk137;
    u8 pad138[4];
    s16 itemId;
    s16 unk13E;
    f32 unk140;
} EdibleMushroomState;

STATIC_ASSERT(offsetof(EdibleMushroomState, distanceToTarget) == 0x108);
STATIC_ASSERT(offsetof(EdibleMushroomState, unk136) == 0x136);
STATIC_ASSERT(offsetof(EdibleMushroomState, unk140) == 0x140);
STATIC_ASSERT(sizeof(EdibleMushroomState) == 0x144);

s16 fn_801D129C(u8* obj, u8* player, u8* state, f32 dist);

/*
 * --INFO--
 *
 * Function: edibleMushroomFn_801d083c
 * EN v1.0 Address: 0x801D083C
 * EN v1.0 Size: 2656b
 */
void edibleMushroomFn_801d083c(u8* obj, u8* state, u8* other)
{
    u8 sval;
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
    int thorntailOut;
    u8* player;

    player = Obj_GetPlayerObject();

    if (((EdibleMushroomState*)state)->unk137 & 4)
    {
        ((EdibleMushroomState*)state)->unk136 = 6;
    }

    speed = oneOverTimeDelta * (((EdibleMushroomState*)state)->prevDistance - ((EdibleMushroomState*)state)->
        distanceToTarget);

    sval = ((EdibleMushroomState*)state)->unk136;
    switch (sval)
    {
    case 0:
        if (((EdibleMushroomState*)state)->unk137 & 0x10)
        {
            ((EdibleMushroomState*)state)->unk136 = 9;
        }
        else if ((*gSHthorntailAnimationInterface)->isTailSwingQueued(&thorntailOut) == 0)
        {
            if (((EdibleMushroomState*)state)->distanceToTarget < (f32)other[0x19])
            {
                if (((EdibleMushroomState*)state)->unk137 & 2)
                {
                    rangeSq = ((EdibleMushroomState*)state)->detectRadius * ((EdibleMushroomState*)state)->detectRadius;
                    while (1)
                    {
                        dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                        dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                        if (dx * dx + dz * dz < rangeSq)
                        {
                            if (Curve_AdvanceAlongPath(state, ((EdibleMushroomState*)state)->unk120) != 0 ||
                                ((RomCurveWalker*)state)->atSegmentEnd != 0)
                            {
                                (*gRomCurveInterface)->goNextPoint(state);
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    ang = getAngle(-dx, -dz);
                    ((EdibleMushroomState*)state)->unk130 = ang;
                }
                else
                {
                    ((EdibleMushroomState*)state)->unk130 =
                        fn_801D129C(obj, player, state, ((EdibleMushroomState*)state)->detectRadius);
                }
                ((EdibleMushroomState*)state)->unk136 = 1;
                Sfx_PlayFromObject(obj, 0xa0);
                *(s16*)obj = (s16)(((EdibleMushroomState*)state)->unk130 - 0x4000);
            }
            else if (((EdibleMushroomState*)state)->distanceToTarget < (f32)other[0x1f])
            {
                ((EdibleMushroomState*)state)->unk136 = 3;
            }
        }
        else
        {
            t = ((EdibleMushroomState*)state)->unk12C - timeDelta;
            ((EdibleMushroomState*)state)->unk12C = t;
            if (t <= lbl_803E5288)
            {
                if (((GameObject*)obj)->objectFlags & 0x800)
                {
                    fx.x = ((GameObject*)obj)->anim.worldPosX;
                    fx.y = lbl_803E528C + ((GameObject*)obj)->anim.worldPosY;
                    fx.z = ((GameObject*)obj)->anim.worldPosZ;
                    (*gPartfxInterface)->spawnObject(obj, 0x7f0, &fx,
                                                     0x200001, -1, NULL);
                }
                ((EdibleMushroomState*)state)->unk12C = lbl_803E5290;
            }
        }
        break;
    case 1:
        if (((EdibleMushroomState*)state)->unk137 & 0x10)
        {
            ((EdibleMushroomState*)state)->unk136 = 9;
        }
        else if (((EdibleMushroomState*)state)->unk137 & 1)
        {
            ((EdibleMushroomState*)state)->unk136 = 0;
        }
        break;
    case 3:
    case 7:
        if (((EdibleMushroomState*)state)->unk137 & 0x10)
        {
            ((EdibleMushroomState*)state)->unk136 = 9;
        }
        else if (((EdibleMushroomState*)state)->unk137 & 1)
        {
            if (sval == 3)
            {
                ((EdibleMushroomState*)state)->unk136 = 4;
            }
            else
            {
                ((EdibleMushroomState*)state)->unk136 = 0;
            }
        }
        break;
    case 4:
        if (((EdibleMushroomState*)state)->unk137 & 0x10)
        {
            ((EdibleMushroomState*)state)->unk136 = 9;
        }
        else
        {
            ang = getAngle(-(((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX),
                           -(((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ));
            *(s16*)obj = ang;
            if (((EdibleMushroomState*)state)->distanceToTarget > lbl_803E5294 + (f32)other[0x1f])
            {
                ((EdibleMushroomState*)state)->unk136 = 7;
            }
            else if (((EdibleMushroomState*)state)->distanceToTarget < (f32)other[0x19])
            {
                Sfx_PlayFromObject(obj, 0xa0);
                if (speed >= lbl_803E5298)
                {
                    if (((EdibleMushroomState*)state)->unk137 & 2)
                    {
                        rangeSq = ((EdibleMushroomState*)state)->detectRadius * ((EdibleMushroomState*)state)->
                            detectRadius;
                        while (1)
                        {
                            dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                            dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                            if (dx * dx + dz * dz < rangeSq)
                            {
                                if (Curve_AdvanceAlongPath(state, ((EdibleMushroomState*)state)->unk120) != 0 ||
                                    ((RomCurveWalker*)state)->atSegmentEnd != 0)
                                {
                                    (*gRomCurveInterface)->goNextPoint(state);
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        ((EdibleMushroomState*)state)->unk130 = ang;
                    }
                    else
                    {
                        ((EdibleMushroomState*)state)->unk130 =
                            fn_801D129C(obj, player, state, ((EdibleMushroomState*)state)->detectRadius);
                    }
                    ((EdibleMushroomState*)state)->unk136 = 1;
                    *(s16*)obj = (s16)(((EdibleMushroomState*)state)->unk130 - 0x4000);
                }
                else
                {
                    if (((EdibleMushroomState*)state)->unk137 & 2)
                    {
                        rangeSq = ((EdibleMushroomState*)state)->unk11C * ((EdibleMushroomState*)state)->unk11C;
                        while (1)
                        {
                            dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                            dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                            if (dx * dx + dz * dz < rangeSq)
                            {
                                if (Curve_AdvanceAlongPath(state, ((EdibleMushroomState*)state)->unk120) != 0 ||
                                    ((RomCurveWalker*)state)->atSegmentEnd != 0)
                                {
                                    (*gRomCurveInterface)->goNextPoint(state);
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        ((EdibleMushroomState*)state)->unk130 = ang;
                    }
                    else
                    {
                        ((EdibleMushroomState*)state)->unk130 =
                            fn_801D129C(obj, player, state, ((EdibleMushroomState*)state)->unk11C);
                    }
                    ((EdibleMushroomState*)state)->unk136 = 5;
                    *(s16*)obj = ((EdibleMushroomState*)state)->unk130;
                }
            }
        }
        break;
    case 5:
        if ((((EdibleMushroomState*)state)->unk137 & 0x11) == 0x11)
        {
            ((EdibleMushroomState*)state)->unk136 = 9;
        }
        if (((EdibleMushroomState*)state)->distanceToTarget > lbl_803E5294 + (f32)other[0x19] && (((EdibleMushroomState
            *)state)->unk137 & 1))
        {
            ((EdibleMushroomState*)state)->unk136 = 4;
        }
        else if (speed >= lbl_803E5298)
        {
            if (((EdibleMushroomState*)state)->unk137 & 2)
            {
                rangeSq = ((EdibleMushroomState*)state)->detectRadius * ((EdibleMushroomState*)state)->detectRadius;
                while (1)
                {
                    dx = ((RomCurveWalker*)state)->posX - ((GameObject*)obj)->anim.localPosX;
                    dz = ((RomCurveWalker*)state)->posZ - ((GameObject*)obj)->anim.localPosZ;
                    if (dx * dx + dz * dz < rangeSq)
                    {
                        if (Curve_AdvanceAlongPath(state, ((EdibleMushroomState*)state)->unk120) != 0 ||
                            ((RomCurveWalker*)state)->atSegmentEnd != 0)
                        {
                            (*gRomCurveInterface)->goNextPoint(state);
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                ang = getAngle(-dx, -dz);
                ((EdibleMushroomState*)state)->unk130 = ang;
            }
            else
            {
                ((EdibleMushroomState*)state)->unk130 = fn_801D129C(obj, player, state,
                                                                    ((EdibleMushroomState*)state)->detectRadius);
            }
            ((EdibleMushroomState*)state)->unk136 = 1;
            Sfx_PlayFromObject(obj, 0xa0);
            *(s16*)obj = (s16)(((EdibleMushroomState*)state)->unk130 - 0x4000);
        }
        break;
    case 9:
        ObjHits_ClearSourceMask(obj, 1);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9b);
        if (((EdibleMushroomState*)state)->unk124 <= lbl_803E5288)
        {
            ((EdibleMushroomState*)state)->unk124 = (f32)(int)
            randomGetRange(0xf0, 0x12c);
        }
        t = ((EdibleMushroomState*)state)->unk124 - timeDelta;
        ((EdibleMushroomState*)state)->unk124 = t;
        if (t <= lbl_803E5288)
        {
            ObjHits_SetSourceMask(obj, 1);
            (*gExpgfxInterface)->freeSource((u32)obj);
            ((EdibleMushroomState*)state)->unk136 = 0;
            ((EdibleMushroomState*)state)->unk137 &= ~0x10;
        }
        else
        {
            t = ((EdibleMushroomState*)state)->unk128 - timeDelta;
            ((EdibleMushroomState*)state)->unk128 = t;
            if (t <= lbl_803E5288)
            {
                fx.x = lbl_803E5294;
                fx.y = lbl_803E529C;
                if (((GameObject*)obj)->objectFlags & 0x800)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x51d, &fx, 2, -1,
                                                     NULL);
                }
                ((EdibleMushroomState*)state)->unk128 = lbl_803E52A0;
            }
            if (GameBit_Get(0x12e) == 0)
            {
                if (!(((GameObject*)player)->objectFlags & 0x1000))
                {
                    if (Vec_xzDistance((f32*)(player + 0x18), &((GameObject*)obj)->anim.worldPosX) <
                        lbl_803E52A4)
                    {
                        (*gExpgfxInterface)->freeSource((u32)obj);
                        if (((GameObject*)obj)->anim.seqId == 0x658)
                        {
                            ((EdibleMushroomState*)state)->itemId = 0x18a;
                            itemPickupDoParticleFx(obj, lbl_803E52A8, 0xff, 0x28);
                        }
                        else
                        {
                            ((EdibleMushroomState*)state)->itemId = 0x119;
                            itemPickupDoParticleFx(obj, lbl_803E52A8, 6, 0x28);
                        }
                        ((EdibleMushroomState*)state)->unk13E = 0;
                        ((EdibleMushroomState*)state)->unk140 = lbl_803E52AC;
                        ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x13c);
                        bit = *(s16*)(other + 0x1a);
                        if (bit != -1)
                        {
                            GameBit_Set(bit, 1);
                        }
                        ((EdibleMushroomState*)state)->unk136 = 8;
                        GameBit_Set(0x12e, 1);
                    }
                }
            }
        }
        break;
    case 6:
        if (((EdibleMushroomState*)state)->unk137 & 0x10)
        {
            ((EdibleMushroomState*)state)->unk136 = 9;
        }
        break;
    case 2:
    case 8:
    case 10:
        break;
    }

    curMove = ((GameObject*)obj)->anim.currentMove;
    moveId = lbl_80326BD0[((EdibleMushroomState*)state)->unk136];
    if (curMove != moveId && moveId != -1)
    {
        ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E52B0, 0);
    }

    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, lbl_80326BE8[((EdibleMushroomState*)state)->unk136], timeDelta, (ObjAnimEventList*)animOut) != 0)
    {
        ((EdibleMushroomState*)state)->unk137 |= 1;
    }
    else
    {
        ((EdibleMushroomState*)state)->unk137 &= ~1;
    }

    if (((EdibleMushroomState*)state)->unk136 == 1)
    {
        speed = ((EdibleMushroomState*)state)->unk110 * (animOut[0] * oneOverTimeDelta);
    }
    else if (((EdibleMushroomState*)state)->unk136 == 5)
    {
        speed = animOut[2] * oneOverTimeDelta;
    }
    else
    {
        speed = lbl_803E5288;
    }

    if (lbl_803E5288 != speed)
    {
        ((EdibleMushroomState*)state)->unk137 |= 8;
    }
    else
    {
        ((EdibleMushroomState*)state)->unk137 &= ~8;
    }

    ((GameObject*)obj)->anim.velocityX =
        speed * mathSinf((lbl_803E52B4 * (f32)((EdibleMushroomState*)state)->unk130) / lbl_803E52B8);
    ((GameObject*)obj)->anim.velocityZ =
        speed * mathCosf((lbl_803E52B4 * (f32)((EdibleMushroomState*)state)->unk130) / lbl_803E52B8);

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, lbl_803E5288,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
}

/*
 * --INFO--
 *
 * Function: fn_801D129C
 * EN v1.0 Address: 0x801D129C
 * EN v1.0 Size: 704b
 */
s16 fn_801D129C(u8* obj, u8* player, u8* state, f32 dist)
{
    s16 angle;
    int anglePlus;
    int angleMinus;
    int i;
    f32 rad;
    f32 c;
    f32 s;
    f32 cosP;
    f32 cosM;
    f32 sinM;
    f32 cosStepP;
    f32 cosStepM;
    f32 sinStepP;
    f32 sinStepM;
    f32 vec[3];

    angle = getAngle(-(((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX),
                     -(((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ));
    rad = (lbl_803E52B4 * (f32)angle) / lbl_803E52B8;
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
        sinM = s;
        sinStepP = mathCosf(lbl_803E52D4);
        sinStepM = mathCosf(lbl_803E52D8);
        for (i = 0; i < 8; i++)
        {
            f32 t;

            anglePlus += 0xe38;
            t = cosP * sinStepP + s * cosStepP;
            s = s * sinStepP - cosP * cosStepP;
            cosP = t;
            vec[0] = ((GameObject*)obj)->anim.localPosX - dist * t;
            vec[2] = ((GameObject*)obj)->anim.localPosZ - dist * s;
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

/*
 * --INFO--
 *
 * Function: ediblemushroom_free
 * EN v1.0 Address: 0x801D1564
 * EN v1.0 Size: 60b
 */
void ediblemushroom_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x47);
    ObjGroup_RemoveObject(obj, 0x31);
}

/*
 * --INFO--
 *
 * Function: ediblemushroom_getExtraSize
 * EN v1.0 Address: 0x801D155C
 * EN v1.0 Size: 8b
 */
int ediblemushroom_getExtraSize(void)
{
    return 0x144;
}

/*
 * --INFO--
 *
 * Function: ediblemushroom_hitDetect
 * EN v1.0 Address: 0x801D15A0
 * EN v1.0 Size: 332b
 */
void ediblemushroom_hitDetect(u8* obj)
{
    u8* state;
    u8* mapObj;
    int hitCount;
    f32** hitIter;
    f32** hits;
    int i;
    u8 bboxHit[0x54];

    state = ((GameObject*)obj)->extra;
    mapObj = *(u8**)&((GameObject*)obj)->anim.placementData;

    if (((((GameObject*)obj)->objectFlags & 0x1000) == 0) &&
        (((((EdibleMushroomState*)state)->unk137 & 8) != 0) || (((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.
            hitReactState)->flags & 8) != 0)))
    {
        hitCount = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ, &hits, 0, 0);
        for (i = 0; i < hitCount; i++)
        {
            if (*hits[i] < lbl_803E5294 + ((GameObject*)obj)->anim.localPosY)
            {
                ((GameObject*)obj)->anim.localPosY = *hits[i];
                break;
            }
        }

        hitCount = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E52DC, 2, bboxHit, obj, 8,
                                      -1, 0xff, 0x14);
        if ((mapObj[0x18] == 4) && (hitCount != 0) && ((s8)bboxHit[0x50] == 13))
        {
            ((EdibleMushroomState*)state)->unk137 |= 4;
        }
    }
}
