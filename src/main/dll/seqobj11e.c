/*
 * seqObj11E - shared baddie-behavior handlers dispatched from the
 * enemy DLL (dll_00C9_enemy) by object type id. Each handler operates on
 * a GameObject plus its BaddieState scratch block; the pairs below are
 * (init, update) sets plus hit/reaction callbacks selected per type:
 *
 *   fn_801522E0 / fn_80152514: a child-zapping curve-follower. Init seeds
 *     speed/scale/state flags from the placement row; update runs a child-
 *     zap timer, advances along a rom curve, steps heading from the curve
 *     tangent, plays landing/laser sfx, emits light-pulse + masked-hit fx
 *     while the active flag (objectFlags 0x800) is set, clamps vertical
 *     velocity, and spawns/parents a spark child object.
 *   fn_80152A94 / fn_80152B90: a firefly hover. Init seeds state; update
 *     drives a circular drift, bobs between two heights, periodically
 *     spawns a dropped object, and runs ambient sfx timers.
 *   fn_80152040: a 12-byte-row state-table driver (gSeq11EStateTable) that
 *     advances on GameBit + sequence flags and kicks the matching anim.
 *   fn_80152370: spawns and sets up a child object at the parent's pos.
 *   fn_80152440 / fn_80152B2C: hit/reaction message callbacks.
 *
 * Object type ids handled (from the enemy dispatch table): 0xd8/0x281
 * (state-table), 0x613 (curve-follower update), 0x642 (firefly).
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/baddie_state.h"
#include "main/objtexture.h"
#include "main/gameplay_runtime.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
extern u32 ObjLink_DetachChild();
extern u32 ObjLink_AttachChild();

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void fn_80152440(GameObject* obj, int p, int p3, int msg)
{
    extern void fn_8014D08C(GameObject* obj, int p, int type, f32 t, int a, int b);
    extern f32 lbl_803E2810;
    extern f32 lbl_803E2814;
    int sub;
    f32 fz;

    sub = *(int*)&obj->anim.placementData;
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((u32)obj, SFXen_cavedirt22);
    Sfx_PlayFromObject((u32)obj, SFXspirit_voice2);
    ((BaddieState*)p)->reactionFlags |= 0x8;
    *(f32*)(p + 0x32c) = (f32)(u32)(u16) * (s16*)(sub + 0x2c);
    fn_8014D08C(obj, p, 1, lbl_803E2810, 0, 0);
    *(u32*)&((BaddieState*)p)->unk2E4 &= ~0x20LL;
    fz = lbl_803E2814;
    obj->anim.velocityZ = lbl_803E2814;
    obj->anim.velocityY = fz;
    obj->anim.velocityX = fz;
}
#pragma opt_common_subs reset

/* EN v1.0 0x80152514  size: 1408b  main update: child-zap timer, curve
 * follow, heading steps, landing sfx, light-pulse fx, child spark spawn. */


extern void Obj_FreeObject(int* obj);

extern u8 lbl_803DBCA8;
extern int fn_801A0174(int* obj);
extern void fn_8014CF7C(void* p1, void* p2, f32 f1, f32 f2, int p5, int p6);
extern void fn_8014D08C(void* p1, void* p2, int p3, f32 f1, int p5, int p6);
extern void objfx_spawnLightPulse(int* obj, f32 scale, int a, int b, int c, f32 v, void* params);
extern void objfx_spawnMaskedHitEffect(int* obj, f32 scale, int a, int b, int c, void* params);
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803DBCB0;
extern f32 lbl_803DBCB4;
extern f32 lbl_803E2814;
extern f32 lbl_803E2820;
extern f32 lbl_803E2824;
extern f32 lbl_803E2828;
extern f32 lbl_803E282C;
extern f32 lbl_803E2830;
extern f32 lbl_803E2834;
extern f32 lbl_803E2838;
extern f32 lbl_803E283C;
extern f32 lbl_803E2840;
extern f32 lbl_803E2844;
extern f32 lbl_803E2848;
extern f32 lbl_803E284C;

typedef struct
{
    u8 pad[8];
    f32 a;
    f32 b;
    f32 c;
    f32 d;
} SeqFxParams;

void fn_80152514(int* obj, u8* state)
{
    int* def;
    RomCurveWalker* path;
    int attached;
    s16 spd;
    SeqFxParams fx;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    path = *(RomCurveWalker**)state;
    if (*(f32*)(state + 0x32c) > lbl_803E2814)
    {
        int* child = ((GameObject*)obj)->childObjs[0];
        if (child != 0)
        {
            Obj_FreeObject(child);
            ObjLink_DetachChild(obj, ((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
        }
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= *(f32*)&lbl_803E2814)
        {
            *(f32*)(state + 0x32c) = lbl_803E2814;
            *(u32*)&((BaddieState*)state)->unk2E4 |= 0x20;
            Sfx_StopObjectChannel((u32)obj, 4);
            fn_8014D08C(obj, state, 0, lbl_803E2820, 0, 0);
        }
        else if (!(*(u32*)&((BaddieState*)state)->unk2E4 & 0x20))
        {
            return;
        }
    }
    if (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
    {
        int step;

        if (Curve_AdvanceAlongPath(path, ((BaddieState*)state)->pathStep) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, lbl_803E2824,
                                                     (int*)&lbl_803DBCA8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        ((GameObject*)obj)->anim.velocityX = (path->posX - ((GameObject*)obj)->anim.localPosX) / timeDelta;
        ((GameObject*)obj)->anim.velocityZ = (path->posZ - ((GameObject*)obj)->anim.localPosZ) / timeDelta;
        step = (s8) * ((u8*)def + 0x2a);
        if (step == 0)
        {
            fn_8014CF7C(obj, state, path->posX, path->posZ, 0xf, 0);
        }
        else if (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
        {
            spd = step << 8;
            if ((int)(lbl_803E2828 * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX - step;
            fn_8014CF7C(obj, state, path->posX, path->posZ, 0xf, 0);
            if ((int)(lbl_803E2828 * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            ((GameObject*)obj)->anim.rotX += step;
        }
        else
        {
            step = ((int)(lbl_803E2828 * path->tangentY) >= 0) ? step : -step;
            ((GameObject*)obj)->anim.rotX += step;
        }
        if (((GameObject*)obj)->anim.localPosY - path->posY < lbl_803E282C)
        {
            if (Sfx_IsPlayingFromObject((u32)obj, SFXar_laser216) == 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXar_laser216);
            }
            ((BaddieState*)state)->seqEntryIndex = 1;
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
    }
    else
    {
        if (((GameObject*)obj)->anim.localPosY - ((ObjPlacement*)def)->posY < lbl_803E2830)
        {
            if (Sfx_IsPlayingFromObject((u32)obj, SFXar_laser216) == 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXar_laser216);
            }
            ((BaddieState*)state)->seqEntryIndex = 1;
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
        ((GameObject*)obj)->anim.rotX += *(s8*)((char*)def + 0x2a);
    }
    if (((BaddieState*)state)->seqEntryIndex != 0)
    {
        ((GameObject*)obj)->anim.velocityY += lbl_803DBCB0 * timeDelta;
    }
    if (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_RENDERED)
    {
        f32 z = lbl_803E2814;
        fx.b = z;
        fx.c = z;
        fx.d = z;
        fx.a = lbl_803E2820;
        objfx_spawnLightPulse(obj, lbl_803E2834, 2, 0, 6, lbl_803E2838, &fx);
        fx.c = lbl_803E283C;
        objfx_spawnMaskedHitEffect(obj, lbl_803E2840, 1, 6, 0x20, &fx);
        fx.b = lbl_803E2814;
        z = lbl_803E2844;
        fx.c = z;
        fx.d = z;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E2848)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2848;
    }
    else if (((GameObject*)obj)->anim.velocityY > lbl_803E2834)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2834;
    }
    if (lbl_803E2814 == *(f32*)(state + 0x32c))
    {
        int* child2;

        if (*(s8*)((char*)def + 0x2e) != -1 &&
            (child2 = ((GameObject*)obj)->childObjs[0]) != 0 && fn_801A0174(child2) != 0)
        {
            ObjHits_RecordObjectHit((int)Obj_GetPlayerObject(), (int)obj, 0x16, 2, 0);
            fn_80152370((int)obj, 0x3b2);
            Sfx_PlayFromObject((u32)obj, SFXsp_literun116);
            *(f32*)(state + 0x32c) = lbl_803DBCB4;
        }
        if ((int)randomGetRange(0, (int)(lbl_803E284C * oneOverTimeDelta)) == 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXsp_literun114);
        }
        child2 = ((GameObject*)obj)->childObjs[0];
        if (child2 != 0)
        {
            ObjTextureRuntimeSlot* tex = objFindTexture(child2, 0, 0);
            int v;
            if (tex != 0)
            {
                v = tex->offsetS - 0x3c;
                if (v < 0)
                {
                    v += 0x2710;
                }
                tex->offsetS = v;
            }
        }
        else
        {
            int* newObj;
            int flag;

            if (*(s8*)((char*)def + 0x2a) != 0)
            {
                attached = 1;
            }
            else
            {
                attached = 0;
            }
            newObj = (int*)fn_80152370((int)obj, 0x639);
            flag = 0;
            if (*(s8*)((char*)def + 0x2a) != 0 && !(((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW))
            {
                flag = 1;
            }
            *(int*)((u8*)newObj + 0xf4) = flag;
            ObjLink_AttachChild(obj, newObj, attached);
        }
    }
}

/* EN v1.0 0x80152B90  size: 816b  firefly hover update: circle drift, bob
 * between heights, periodically drop a spawned object, ambient sfx timers. */

extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* loadObjectAtObject(int* obj, u8* setup);
extern void fn_8014CD1C(int* obj, u8* state, int p3, f32 a, f32 b, int p6);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E2868;
extern f32 lbl_803E286C;
extern f32 lbl_803E2878;
extern f32 lbl_803E287C;
extern f32 lbl_803E2880;
extern f32 lbl_803E2884;
extern f32 lbl_803E2888;
extern f32 lbl_803E288C;
extern f32 lbl_803E2890;
extern f32 lbl_803E2894;

void fn_80152B90(int* obj, u8* state)
{
    f32 y;
    f32 sinOut;
    f32 cosOut;

    *(u16*)(state + 0x338) = lbl_803E287C * timeDelta + (f32)(u32) * (u16*)(state + 0x338);
    fn_80293018(*(u16*)(state + 0x338), &sinOut, &cosOut);
    sinOut = sinOut * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x324);
    cosOut = cosOut * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x32c);
    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        f32 dx;
        f32 dz;

        y = ((GameObject*)obj)->anim.localPosY;
        dx = *(f32*)(state + 0x324) - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX;
        dz = *(f32*)(state + 0x32c) - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ;
        if (sqrtf(dx * dx + dz * dz) <= lbl_803E2880 * ((BaddieState*)state)->unk2A8)
        {
            ((BaddieState*)state)->seqEntryIndex = 1;
            ((BaddieState*)state)->inWhirlpoolGroup = 0;
        }
    }
    else if (((BaddieState*)state)->seqEntryIndex == 1)
    {
        y = ((GameObject*)obj)->anim.localPosY - lbl_803E2884 * timeDelta;
        if (y <= *(f32*)(state + 0x328) - lbl_803E2888)
        {
            ((BaddieState*)state)->seqEntryIndex = 2;
        }
        else
        {
            ((BaddieState*)state)->inWhirlpoolGroup = (f32)(u32)((BaddieState*)state)->inWhirlpoolGroup + timeDelta;
            if (((BaddieState*)state)->inWhirlpoolGroup > 0x64)
            {
                ((BaddieState*)state)->inWhirlpoolGroup = 0;
                if (Obj_IsLoadingLocked() != 0)
                {
                    u8* setup;
                    int* spawned;

                    setup = Obj_AllocObjectSetup(0x24, 0x6b5);
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                    ((ObjPlacement*)setup)->posY = lbl_803E2878 + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                    ((ObjPlacement*)setup)->color[0] = 1;
                    ((ObjPlacement*)setup)->color[1] = 1;
                    ((ObjPlacement*)setup)->color[2] = 0xff;
                    ((ObjPlacement*)setup)->color[3] = 0xff;
                    spawned = loadObjectAtObject(obj, setup);
                    if (spawned != 0)
                    {
                        *(int**)((char*)spawned + 0xc4) = obj;
                        Sfx_PlayFromObject((u32)obj, 0x249);
                    }
                }
            }
        }
    }
    else
    {
        y = lbl_803E288C * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (y >= *(f32*)(state + 0x328))
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
    }
    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (sinOut - ((GameObject*)obj)->anim.localPosX);
    ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (y - ((GameObject*)obj)->anim.localPosY);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (cosOut - ((GameObject*)obj)->anim.localPosZ);
    fn_8014CD1C(obj, state, 0xf, lbl_803E2890, lbl_803E2894, 0);
    *(f32*)(state + 0x334) = *(f32*)(state + 0x334) - timeDelta;
    if (*(f32*)(state + 0x334) <= lbl_803E2868)
    {
        *(f32*)(state + 0x334) = (f32)(int)
        randomGetRange(0x3c, 0x78);
        Sfx_PlayFromObject((u32)obj, 0x31);
    }
    *(f32*)(state + 0x330) = *(f32*)(state + 0x330) - timeDelta;
    if (*(f32*)(state + 0x330) <= lbl_803E2868)
    {
        *(f32*)(state + 0x330) = lbl_803E286C;
        Sfx_PlayFromObject((u32)obj, 0x24a);
    }
}

int fn_80152370(int obj, int p2)
{
    extern u8*Obj_SetupObject(u8* obj, int a, int b, int c, int d);
    int sub;
    u8* setup;

    sub = *(int*)&((GameObject*)obj)->anim.placementData;
    Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() == 0) return 0;
    setup = Obj_AllocObjectSetup(36, p2);
    *(s16*)(setup + 0) = p2;
    ((ObjPlacement*)setup)->color[0] = ((ObjPlacement*)sub)->color[0];
    ((ObjPlacement*)setup)->color[2] = ((ObjPlacement*)sub)->color[2];
    ((ObjPlacement*)setup)->color[1] = 1;
    ((ObjPlacement*)setup)->color[3] = ((ObjPlacement*)sub)->color[3];
    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
    ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
    ((Seq11EChildSetup*)setup)->unk19 = 0;
    ((Seq11EChildSetup*)setup)->unk20 = 149;
    return (int)Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
}

#pragma scheduling on
#pragma peephole on
#pragma scheduling off
void fn_80152A94(int obj, int p)
{
    extern f32 lbl_803E2850;
    extern f32 lbl_803E2854;
    extern f32 lbl_803E2858;
    extern f32 lbl_803E285C;
    extern f32 lbl_803E2860;
    f32 fz;

    ((BaddieState*)p)->speedScale = lbl_803E2850;
    *(u32*)&((BaddieState*)p)->unk2E4 = 41;
    *(u32*)&((BaddieState*)p)->unk2E4 |= 0x7000;
    *(u32*)&((BaddieState*)p)->unk2E4 |= 0x20000LL;
    ((BaddieState*)p)->unk308 = lbl_803E2854;
    ((BaddieState*)p)->animDeltaScale = lbl_803E2858;
    ((BaddieState*)p)->unk304 = lbl_803E285C;
    ((BaddieState*)p)->unk320 = 0;
    fz = lbl_803E2820;
    *(f32*)&((BaddieState*)p)->eventFlags = fz;
    ((BaddieState*)p)->unk321 = 0;
    ((BaddieState*)p)->unk318 = fz;
    ((BaddieState*)p)->unk322 = 0;
    ((BaddieState*)p)->unk31C = fz;
    *(f32*)(p + 0x32c) = lbl_803E2814;
    ((GameObject*)obj)->anim.hitboxScale = lbl_803E2860;
    Sfx_AddLoopedObjectSound((u32)obj, SFXsp_literun115);
}

void fn_80152B2C(int obj, int p, int param3, int msg)
{
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((u32)obj, SFXfox_cough1);
    *(s16*)&((BaddieState*)p)->hitCounter = 0;
    *(u32*)&((BaddieState*)p)->unk2E4 |= 0x20;
    ((BaddieState*)p)->reactionFlags |= 0x8;
}

extern f32 lbl_803E27F8;
extern f32 lbl_803E27FC;
extern f32 lbl_803E2800;
extern f32 lbl_803E2804;
extern f32 lbl_803E2808;
extern f32 lbl_803E280C;

#pragma scheduling off
#pragma peephole off
void fn_801522E0(int* obj, u8* state)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    f32 fz;
    ((BaddieState*)state)->speedScale = lbl_803E27F8;
    ((BaddieState*)state)->unk2A8 = lbl_803E27FC;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk2E4 |= 0xC80;
    ((BaddieState*)state)->unk308 = lbl_803E2800;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2804;
    ((BaddieState*)state)->unk304 = lbl_803E2808;
    ((BaddieState*)state)->unk320 = 0;
    fz = lbl_803E280C;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 0;
    ((BaddieState*)state)->unk318 = fz;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    if ((s8) * ((s8*)sub + 46) != -1)
    {
        *(int*)&((BaddieState*)state)->controlFlags |= 1;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
}

/* EN v1.0 0x80152040  size: 672b  state-table driver: walks the 12-byte
 * gSeq11EStateTable state rows, advancing on GameBit + sequence flags and kicking
 * the matching anim. */

typedef struct
{
    f32 animSpeed; /* 0x0 */
    u32 unk4; /* 0x4 */
    u8 anim; /* 0x8 */
    u8 next; /* 0x9 */
    u8 alt; /* 0xa */
    u8 flagB; /* 0xb */
} Seq11ERow;

extern Seq11ERow gSeq11EStateTable[];
extern void fn_80151C68(int* obj, u8* state);
extern void fn_80151DB8(int* obj, u8* state);

void fn_80152040(int* obj, u8* state)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    u32 flags;

    if (((BaddieState*)state)->seqEntryIndex == 2 && GameBit_Get(*(s16*)((char*)def + 0x1c)) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
        {
            fn_80151C68(obj, state);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_JUST_TRIGGERED)
    {
        if (gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].unk4 != 0)
        {
            ((BaddieState*)state)->controlFlags = flags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
        }
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_SEQUENCE_DRIVEN)
    {
        int anim;
        u8* animTbl;

        if (((BaddieState*)state)->seqEntryIndex == 0)
        {
            if (flags & 0x20000000)
            {
                if (GameBit_Get(*(s16*)((char*)def + 0x1c)) != 0)
                {
                    ((BaddieState*)state)->seqEntryIndex = gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].alt;
                }
                else
                {
                    ((BaddieState*)state)->seqEntryIndex = gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].next;
                }
            }
        }
        else if (((BaddieState*)state)->seqEntryIndex == 2)
        {
            if (GameBit_Get(*(s16*)((char*)def + 0x1c)) != 0 ||
                !(((BaddieState*)state)->controlFlags & 0x20000000))
            {
                ((BaddieState*)state)->seqEntryIndex = gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].next;
            }
        }
        else if (((BaddieState*)state)->seqEntryIndex == 3)
        {
            if (GameBit_Get(*(s16*)((char*)def + 0x1c)) != 0)
            {
                ((BaddieState*)state)->seqEntryIndex = gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].alt;
            }
            else
            {
                ((BaddieState*)state)->seqEntryIndex = gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].next;
            }
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].next;
        }
        anim = ((GameObject*)obj)->anim.currentMove;
        if (anim != (animTbl = (u8*)gSeq11EStateTable + 8)[((BaddieState*)state)->seqEntryIndex * 12])
        {
            if (animTbl[((BaddieState*)state)->seqEntryIndex * 12] != 0 && animTbl[((BaddieState*)state)->seqEntryIndex
                * 12] != 4)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_eggsnatch_carry3);
            }
            fn_8014D08C(obj, state, animTbl[((BaddieState*)state)->seqEntryIndex * 12],
                        *(f32*)((u8*)gSeq11EStateTable + ((BaddieState*)state)->seqEntryIndex * 12), 0, 0xf);
        }
    }
    if (gSeq11EStateTable[((BaddieState*)state)->seqEntryIndex].flagB != 0)
    {
        fn_80151DB8(obj, state);
    }
}

Seq11ERow gSeq11EStateTable[6] = {
    { 3.0f, 0x1, 0, 1, 4, 1 },
    { 2.0f, 0x0, 1, 2, 2, 1 },
    { 3.0f, 0x1, 2, 3, 3, 1 },
    { 2.0f, 0x0, 7, 0, 4, 1 },
    { 2.0f, 0x0, 3, 5, 5, 0 },
    { 3.5f, 0x1, 4, 5, 5, 0 },
};
