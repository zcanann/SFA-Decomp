#include "main/dll/NW/dll_01A7_ediblemushroom.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/SH/SHthorntail_internal.h"

extern undefined8 ObjGroup_RemoveObject();
extern int hitDetectFn_80065e50(void* obj, f32 x, f32 y, f32 z, void* hitsOut, int p6, int p7);
extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, void* obj,
                              int p7, int p8, int p9, int p10);

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
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
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

#include "main/audio/sfx_ids.h"
#include "main/game_object.h"

typedef struct EdiblemushroomPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
} EdiblemushroomPlacement;

#include "main/dll/NW/ediblemushroom_state.h"

extern u8* getTrickyObject(void);
extern int objIsFrozen(u8 * self);
extern void gameBitIncrement(s16 bit);
extern int ObjMsg_Pop(u8* obj, int* outMsg, int a, int b);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern void Obj_StartModelFadeIn(u8* obj, int frames);
extern void Obj_SetModelColorFadeRecursive(u8* obj, int a, int b, int c, int d, int e);
extern int ObjHits_GetPriorityHit(u8* obj, int* outOther, int a, int b);
extern f32 sqrtf(f32 x);

/*
 * --INFO--
 *
 * Function: ediblemushroom_update
 * EN v1.0 Address: 0x801D16EC
 * EN v1.0 Size: 652b
 */
void ediblemushroom_update(u8* self)
{
    extern void edibleMushroomFn_801d083c(u8 * self, u8 * state, u8 * other); /* #57 */
    extern void ObjHits_DisableObject(u8 * obj); /* #57 */
    extern void GameBit_Set(int bit, int value); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
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

    if (state[0x136] == 8)
    {
        while (ObjMsg_Pop(self, &msg, 0, 0) != 0)
        {
            if (((u32)msg - 0x70000) != 0xB) continue;
            ((GameObject*)self)->anim.flags = (s16)(((GameObject*)self)->anim.flags | 0x4000);
            ObjHits_DisableObject(self);
            gameBitIncrement(((EdiblemushroomState*)state)->eventId);
            GameBit_Set(0x12E, 0);
            if (((GameObject*)self)->anim.seqId == 0x658)
            {
                itemPickupDoParticleFx(self, lbl_803E52A8, 0xFF, 0x28);
            }
            else
            {
                itemPickupDoParticleFx(self, lbl_803E52A8, 6, 0x28);
            }
            Sfx_PlayFromObject(self, SFXen_waterblock_stop);
        }
        goto end;
    }

    if (state[0x139] != 0)
    {
        ((GameObject*)self)->anim.localPosX = ((EdiblemushroomPlacement*)other)->unk8;
        ((GameObject*)self)->anim.localPosY = ((EdiblemushroomPlacement*)other)->unkC;
        ((GameObject*)self)->anim.localPosZ = ((EdiblemushroomPlacement*)other)->unk10;
        ((GameObject*)self)->anim.alpha = 0xFF;
        state[0x139] = 0;
    }

    ((EdiblemushroomState*)state)->unk10C = ((EdiblemushroomState*)state)->unk108;
    distState = vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(self + 0x18));
    if (enemy == NULL)
    {
        ((EdiblemushroomState*)state)->unk108 = sqrtf(distState);
    }
    else
    {
        distEnemy = vec3f_distanceSquared((f32*)(enemy + 0x18), (f32*)(self + 0x18));
        if (distState < distEnemy)
        {
            ((EdiblemushroomState*)state)->unk108 = sqrtf(distState);
        }
        else
        {
            ((EdiblemushroomState*)state)->unk108 = sqrtf(distEnemy);
        }
        if (((EdiblemushroomState*)state)->unk108 < (f32)(u32)other[0x1F]
        )
        {
            (*(void (**)(u8*, u8*, int, int))(*(int*)*(int*)(enemy + 0x68) + 0x28))
                (enemy, self, 0, 1);
        }
    }

    hitKind = ObjHits_GetPriorityHit(self, &hitObj, 0, 0);
    if (hitKind != 0)
    {
        if (hitKind == 0x10)
        {
            Obj_StartModelFadeIn(self, 0x12C);
        }
        else
        {
            Obj_SetModelColorFadeRecursive(self, 0xF, 0xC8, 0, 0, 1);
            if (*(s16*)((u8*)hitObj + 0x46) != 0x416)
            {
                if ((state[0x137] & 0x10) == 0)
                {
                    Sfx_PlayFromObject(self, SFXmv_curtainloop16);
                }
                state[0x137] = (u8)(state[0x137] | 0x10);
            }
        }
    }
    edibleMushroomFn_801d083c(self, state, other);

end:
    ;
}

#include "main/dll/ediblemushroom.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"

#include "main/dll/NW/ediblemushroom_state.h"

extern undefined4 FUN_80006824();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();

extern u32 GameBit_Get(int bit);
extern f32 Vec_distance(int a, int b);

extern f32 lbl_803E52E0;
extern f32 lbl_803E52E4;
extern f32 lbl_803E52E8;
extern f32 lbl_803E52EC;
extern f32 lbl_803E52F0;
extern f32 lbl_803E52F4;

/*
 * --INFO--
 *
 * Function: ediblemushroom_init
 * EN v1.0 Address: 0x801D1978
 * EN v1.0 Size: 644b
 */
void ediblemushroom_init(int obj, int aux)
{
    extern undefined4 ObjHits_DisableObject(); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    int state;
    int player;
    int local_x;
    ObjAnimEventList animEvents;
    f32 dist;

    state = *(int*)&((GameObject*)obj)->extra;
    local_x = 0x19;
    player = (int)Obj_GetPlayerObject();

    ((GameObject*)obj)->animEventCallback = (void*)EdibleMushroom_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);

    if (GameBit_Get(*(short*)(aux + 0x1a)) != 0)
    {
        ((EdiblemushroomState*)state)->unk136 = 8;
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (short)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }

    ((GameObject*)obj)->anim.modelState->flags |= 0x810;

    ((EdiblemushroomState*)state)->unk110 = lbl_803E52E0;
    ((EdiblemushroomState*)state)->unk114 = lbl_803E52E4 *
        ((f32) * (u8*)(aux + 0x1c) / lbl_803E52E8);

    ObjAnim_SetCurrentMove(obj, 1, lbl_803E5288, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E52A8, *(f32*)&lbl_803E52A8, &animEvents);
    ((EdiblemushroomState*)state)->unk118 = animEvents.rootDeltaX;
    if (((EdiblemushroomState*)state)->unk118 < lbl_803E5288)
    {
        ((EdiblemushroomState*)state)->unk118 = -((EdiblemushroomState*)state)->unk118;
    }
    ((EdiblemushroomState*)state)->unk118 = ((EdiblemushroomState*)state)->unk118 * ((EdiblemushroomState*)state)->
        unk110;
    ((EdiblemushroomState*)state)->unk118 = ((EdiblemushroomState*)state)->unk118 + lbl_803E52A0;

    ObjAnim_SetCurrentMove(obj, 4, lbl_803E5288, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E52A8, *(f32*)&lbl_803E52A8, &animEvents);
    ((EdiblemushroomState*)state)->unk11C = animEvents.rootDeltaZ;
    if (((EdiblemushroomState*)state)->unk11C < lbl_803E5288)
    {
        ((EdiblemushroomState*)state)->unk11C = -((EdiblemushroomState*)state)->unk11C;
    }
    ((EdiblemushroomState*)state)->unk11C = ((EdiblemushroomState*)state)->unk11C + lbl_803E52A0;

    ObjMsg_AllocQueue(obj, 1);

    {
        int v = *(u8*)(aux + 0x18);
        switch (v)
        {
        case 4:
        case 5:
            ((EdiblemushroomState*)state)->unk137 |= 2;
            (*gRomCurveInterface)->initCurve((void*)state, (void*)obj, lbl_803E52EC, &local_x, -1);
            ((GameObject*)obj)->anim.localPosX = ((EdiblemushroomState*)state)->unk68;
            ((GameObject*)obj)->anim.localPosZ = ((EdiblemushroomState*)state)->unk70;
            break;
        }
    }

    ((EdiblemushroomState*)state)->unk120 = lbl_803E52F0;

    if ((void*)player != NULL)
    {
        dist = Vec_distance(player + 0x18, obj + 0x18);
        ((EdiblemushroomState*)state)->unk108 = dist;
        ((EdiblemushroomState*)state)->unk10C = dist;
    }
    else
    {
        {
            f32 z = lbl_803E52F4;
            ((EdiblemushroomState*)state)->unk108 = z;
            ((EdiblemushroomState*)state)->unk10C = z;
        }
    }

    ObjGroup_AddObject(obj, 0x31);
    ObjGroup_AddObject(obj, 0x47);

    if (((GameObject*)obj)->anim.seqId == 0x658)
    {
        *(short*)(state + 0x134) = 0x66d;
    }
    else
    {
        *(short*)(state + 0x134) = 0xc1;
    }
}

/* Keep the cross-TU bl: target calls this; once it lands in the
 * EnemyMushroom TU (dim_bossgut.c) alongside its callers, dont_inline stops
 * MWCC auto-inlining it into enemymushroom_init/update. */
#pragma dont_inline on
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: enemymushroom_getExtraSize
 * EN v1.0 Address: 0x801D1D58
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: enemymushroom_getObjectTypeId
 * EN v1.0 Address: 0x801D1D60
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern void objRenderFn_8003b8f4(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);

/*
 * --INFO--
 *
 * Function: enemymushroom_hitDetect
 * EN v1.0 Address: 0x801D1E20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
