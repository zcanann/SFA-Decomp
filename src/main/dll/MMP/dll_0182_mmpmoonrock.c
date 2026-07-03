/*
 * mmpmoonrock (DLL 0x182) - Moon Mountain Pass carryable moon rock.
 *
 * A gCarryableInterface-backed object the player picks up and places on
 * pedestals. State tracks a "kind" gamebit (0..6) and a flag word driving
 * pickup/placement, throw physics, and a sink-and-respawn cycle when the
 * rock lands in lava (fn_801A7B10 integrates the throw + lava probe via
 * fn_801A78C8; fn_801A79E0 handles the impact/respawn). fn_801A7CC4
 * launches the rock from the player; fn_801A7D74 reconciles the
 * pedestal/inventory gamebit counts (0x88C / 0x894) when the rock is
 * placed or removed. update floats placed rocks with a sine wobble and
 * spawns ambient particles.
 */

#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/carryable_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/dll/MMP/dll_0182_mmpmoonrock.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"

STATIC_ASSERT(sizeof(MmpMoonrockState) == 0x30);

typedef struct MmpMoonrockPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 kindGameBit;   /* 0x1A: gamebit whose value selects the moonrock kind */
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 gateBit;       /* 0x20: gamebit gating pickup (cleared = grabbable) */
    u8 pad22[0x28 - 0x22];
} MmpMoonrockPlacement;

extern f32 Vec_xzDistance(f32* a, f32* b);
extern void objRenderFn_8003b8f4(int* obj);
extern f32 timeDelta;

#pragma scheduling on
#pragma peephole on

void mmp_moonrock_hitDetect(void)
{
}

void mmp_moonrock_release(void)
{
}

void mmp_moonrock_initialise(void)
{
}

int mmp_moonrock_getExtraSize(void) { return 0x30; }
int mmp_moonrock_getObjectTypeId(void) { return 0x0; }


extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32* out1, int* out2);
extern f32 lbl_803E4554;
extern f32 gMoonRockGravity;
extern f32 gMoonRockVelClampMin;
extern f32 gMoonRockVelClampMax;
extern f32 lbl_803E4568;

#pragma scheduling off
#pragma peephole off
void fn_801A7B10(int obj)
{
    extern int fn_801A78C8(int obj, f32 x, f32 y, f32 z, f32 y2, f32* out1, int* out2);
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    int hitTypeOut[1];
    f32 floorYOut;
    int idx;
    f32 v;
    int ret;
    idx = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                              ((GameObject*)obj)->anim.localPosZ);
    if (idx == -1) return;
    ObjHits_SetHitVolumeSlot(obj, 14, 1, 0);
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - gMoonRockGravity * timeDelta;
    {
        f32 v1 = ((GameObject*)obj)->anim.velocityX;
        f32 v2;
        if (v1 < gMoonRockVelClampMin)
        {
            v2 = gMoonRockVelClampMin;
        }
        else if (v1 > gMoonRockVelClampMax)
        {
            v2 = gMoonRockVelClampMax;
        }
        else
        {
            v2 = v1;
        }
        ((GameObject*)obj)->anim.velocityX = v2;
    }
    {
        f32 v1 = ((GameObject*)obj)->anim.velocityY;
        f32 v2;
        if (v1 < gMoonRockVelClampMin)
        {
            v2 = gMoonRockVelClampMin;
        }
        else if (v1 > gMoonRockVelClampMax)
        {
            v2 = gMoonRockVelClampMax;
        }
        else
        {
            v2 = v1;
        }
        ((GameObject*)obj)->anim.velocityY = v2;
    }
    {
        f32 v1 = ((GameObject*)obj)->anim.velocityX;
        f32 v2;
        if (v1 < gMoonRockVelClampMin)
        {
            v2 = gMoonRockVelClampMin;
        }
        else if (v1 > gMoonRockVelClampMax)
        {
            v2 = gMoonRockVelClampMax;
        }
        else
        {
            v2 = v1;
        }
        ((GameObject*)obj)->anim.velocityX = v2;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    state->flags &= ~0x80;
    v = ((GameObject*)obj)->anim.localPosY;
    ret = fn_801A78C8(obj, ((GameObject*)obj)->anim.localPosX, v, ((GameObject*)obj)->anim.localPosZ, lbl_803E4568 + v,
                      &floorYOut, hitTypeOut);
    if (ret == 0) return;
    if (ret == 2)
    {
        f32 c;
        state->flags |= 0x100;
        c = lbl_803E4554;
        ((GameObject*)obj)->anim.velocityX = c;
        ((GameObject*)obj)->anim.velocityY = c;
        ((GameObject*)obj)->anim.velocityZ = c;
    }
    else
    {
        f32 c;
        state->flags |= 0x180;
        ((GameObject*)obj)->anim.localPosY = floorYOut;
        c = lbl_803E4554;
        ((GameObject*)obj)->anim.velocityX = c;
        ((GameObject*)obj)->anim.velocityY = c;
        ((GameObject*)obj)->anim.velocityZ = c;
    }
}

extern void saveGame_saveObjectPos(int obj);
extern int objBboxFn_800640cc(int* from, int* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern f32 lbl_803E454C;
extern f32 lbl_803E4550;
extern const f32 gMoonRockRespawnTime;

#pragma dont_inline on
void fn_801A79E0(int obj)
{
    extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
    int hitScratch[21];
    int hitObjOut;
    MmpMoonrockState * state;
    int ret;
    state = ((GameObject*)obj)->extra;
    ret = ObjHits_GetPriorityHit(obj, &hitObjOut, 0, 0);
    if (ret == 0)
    {
        ret = objBboxFn_800640cc((int*)&((GameObject*)obj)->anim.previousLocalPosX,
                                 (int*)&((GameObject*)obj)->anim.localPosX, lbl_803E454C, 1, hitScratch, obj, 1, -1,
                                 0xff, 0);
    }
    if ((ret != 0) ||
        ((((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0 && (state->flags & 0x40) != 0) ||
            (state->flags & 0x100) != 0))
    {
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E4550;
        spawnExplosion(obj, lbl_803E4554, 1, 1, 0, 0, 0, 1, 0);
        state->flags |= 0x200;
        state->respawnTimer = gMoonRockRespawnTime;
        ((GameObject*)obj)->anim.alpha = 0;
        ((GameObject*)obj)->anim.localPosX = state->homeX;
        ((GameObject*)obj)->anim.localPosY = state->homeY;
        ((GameObject*)obj)->anim.localPosZ = state->homeZ;
        saveGame_saveObjectPos(obj);
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void fn_801A80C4(int obj, f32 x, f32 y, f32 z)
{
    ((GameObject*)obj)->anim.localPosX = x;
    ((GameObject*)obj)->anim.localPosY = y;
    ((GameObject*)obj)->anim.localPosZ = z;
    saveGame_saveObjectPos(obj);
}

#pragma scheduling off
void mmp_moonrock_free(int obj)
{
    extern void ObjGroup_RemoveObject(u32 obj, int group);
    ObjGroup_RemoveObject((u32)obj, 4);
    (*gCarryableInterface)->free(obj);
}

extern const f32 lbl_803E457C;
void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if ((*gCarryableInterface)->isVisible(obj, visible) != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (obj, p2, p3, p4, p5, lbl_803E457C);
    }
}

extern void vecRotateZXY(void* in, void* out);
extern f32 lbl_803E456C;
extern f32 lbl_803E4570;
extern f32 lbl_803E4574;
extern f32 lbl_803E4578;

#pragma dont_inline on
#pragma peephole off
void fn_801A7CC4(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    struct
    {
        s16 a;
        s16 b;
        s16 c;
        s16 _pad;
        f32 d;
        f32 e;
        f32 f;
        f32 g;
    } stk;
    int* player = Obj_GetPlayerObject();
    int* playerState = ((GameObject*)player)->extra;
    f32 c1 = lbl_803E4554;
    ((GameObject*)obj)->anim.velocityX = c1;
    ((GameObject*)obj)->anim.velocityY = lbl_803E4570 * *(f32*)((char*)playerState + 0x298) + lbl_803E456C;
    ((GameObject*)obj)->anim.velocityZ = lbl_803E4578 * *(f32*)((char*)playerState + 0x298) + lbl_803E4574;
    stk.e = c1;
    stk.f = c1;
    stk.g = c1;
    stk.d = lbl_803E457C;
    stk.c = 0;
    stk.b = 0;
    stk.a = ((GameObject*)player)->anim.rotX;
    vecRotateZXY(&stk, (void*)(obj + 0x24));
    state->flags |= 0x40;
}
#pragma dont_inline reset

void fn_801A80F0(int obj, u8 flag)
{
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    if (flag != 0)
    {
        state->flags |= 0x4;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        state->flags &= ~0x4;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    }
}


extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern f32 lbl_803E4548;

int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32* out1, int* out2)
{
    f32** results;
    f32* e;
    int i;
    int count;

    count = hitDetectFn_80065e50(obj, x, y, z, &results, 0, 1);
    *out1 = y;
    *out2 = 0;
    for (i = 0; i < count; i++)
    {
        if (*(s8*)((u8*)results[i] + 0x14) != 0xE && y < results[i][0] && (y2 > results[i][0] || i == count - 1))
        {
            *out2 = *(int*)((u8*)results[i] + 0x10);
            *out1 = results[i][0];
            return (results[i][2] < lbl_803E4548) + 1;
        }
    }
    return 0;
}

void mmp_moonrock_init(int obj, int param2)
{
    extern u32 ObjGroup_AddObject();
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    u8 kind;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
    *(s16*)&state->flags = 0;
    state->kind = GameBit_Get(((MmpMoonrockPlacement*)param2)->kindGameBit);
    kind = state->kind;
    if (kind != 0)
    {
        if ((u8)(kind - 3) <= 1 || kind == 6)
        {
            state->flags = state->flags | 0x400;
        }
        (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 0);
    }
    else
    {
        (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 1);
    }
    {
        f32 z = ((GameObject*)obj)->anim.localPosY;
        state->baseY = z;
        state->baseY2 = z;
    }
    (*gCarryableInterface)->initAnim((void*)obj, *(int*)&((GameObject*)obj)->extra, 0x32);
    (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x2c))((int)state, 1);
    ObjGroup_AddObject(obj, 4);
    state->homeX = ((GameObject*)obj)->anim.localPosX;
    state->homeY = ((GameObject*)obj)->anim.localPosY;
    state->homeZ = ((GameObject*)obj)->anim.localPosZ;
    ObjHits_DisableObject(obj);
    fn_801A7D74(obj, 1, 2);
}

extern void* ObjList_GetObjects(int* outA, int* outB);

extern f32 gMoonRockPickupRange;

void fn_801A7D74(int obj, u8 a, u8 b)
{
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
    extern f32 Vec_distance(f32* a, f32* b);

    int i;
    int count;
    int* list;
    MmpMoonrockState * state;
    MmpMoonrockPlacement* odef;
    MmpMoonrockPlacement* mydef;
    s8 g1;
    s8 g2;

    state = ((GameObject*)obj)->extra;
    list = ObjList_GetObjects(&i, &count);
    for (; i < count; i++)
    {
        u32 o = list[i];
        if (o != obj && ((GameObject*)o)->anim.seqId == 0x518 &&
            Vec_distance((void*)(obj + 0x18), (void*)(o + 0x18)) < gMoonRockPickupRange)
        {
            u32 c;
            odef = (MmpMoonrockPlacement*)((GameObject*)list[i])->anim.placementData;
            mydef = (MmpMoonrockPlacement*)((GameObject*)obj)->anim.placementData;
            g1 = GameBit_Get(0x88C);
            g2 = GameBit_Get(0x894);
            if (a == 0)
            {
                (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 1);
                if (odef->unk1E != -1)
                {
                    GameBit_Set(odef->unk1E, 0);
                }
                c = state->kind;
                if (c == 3) goto dec;
                if (c == 4) goto dec;
                if (c == 6)
                {
                dec:
                    g1 -= 1;
                }
                else
                {
                    g2 -= 1;
                }
                if (mydef->kindGameBit != -1)
                {
                    GameBit_Set(mydef->kindGameBit, 0);
                    state->kind = 0;
                }
                {
                    f32 y = ((GameObject*)obj)->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                state->flags &= ~0x400;
                ((GameObject*)obj)->anim.localPosX = state->homeX;
                ((GameObject*)obj)->anim.localPosY = state->homeY;
                ((GameObject*)obj)->anim.localPosZ = state->homeZ;
                saveGame_saveObjectPos(obj);
            }
            else
            {
                (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 0);
                if (odef->unk1E != -1)
                {
                    GameBit_Set(odef->unk1E, 1);
                }
                if (b == 0)
                {
                    ((GameObject*)obj)->anim.localPosX = ((GameObject*)list[i])->anim.localPosX;
                    ((GameObject*)obj)->anim.localPosY = ((GameObject*)list[i])->anim.localPosY;
                    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)list[i])->anim.localPosZ;
                    saveGame_saveObjectPos(obj);
                }
                {
                    f32 y = ((GameObject*)obj)->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                if (mydef->kindGameBit != -1)
                {
                    GameBit_Set(mydef->kindGameBit, odef->kindGameBit);
                    state->kind = odef->kindGameBit;
                }
                c = state->kind;
                if (c == 3) goto held;
                if (c == 4) goto held;
                if (c == 6)
                {
                held:
                    if (b != 2)
                    {
                        g1 = g1 + 1;
                    }
                    if (b == 0)
                    {
                        Sfx_PlayFromObject(0, g1 < 3 ? SFXTRIG_menuups16k : SFXTRIG_mpick1_b);
                        GameBit_Set(0x9AE, 1);
                    }
                    state->flags |= 0x400;
                    setAButtonIcon(0);
                }
                else if (b != 2)
                {
                    g2 += 1;
                }
            }
            if (g1 >= 3)
            {
                GameBit_Set(0x89B, 1);
            }
            else
            {
                GameBit_Set(0x89B, 0);
            }
            if (g1 > 3)
            {
                g1 = 3;
            }
            else if (g1 < 0)
            {
                g1 = 0;
            }
            if (g2 > 3)
            {
                g2 = 3;
            }
            else if (g2 < 0)
            {
                g2 = 0;
            }
            GameBit_Set(0x88C, g1);
            GameBit_Set(0x894, g2);
        }
    }
}

extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 volume, f32 scale);

extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern void objParticleFn_80099d84(int obj, f32 a, int c, f32 b, int d);
extern u32 playerGetStateFlag310(int obj);
extern char gMoonRockSpawnParams[];
extern f32 gMoonRockAlphaMax;
extern f32 lbl_803E4588;
extern f32 lbl_803E458C;
extern f32 lbl_803E4590;
extern f32 lbl_803E4594;
extern f32 gMoonRockPi;
extern f32 gMoonRockAngleScale;
extern f32 gMoonRockWobbleAmplitude;

void mmp_moonrock_update(int obj)
{
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
    extern void* Obj_GetPlayerObject(void);
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    u8 grabbed;
    int d;
    int count;
    if (objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                            ((GameObject*)obj)->anim.localPosZ) == -1)
    {
        return;
    }
    if ((state->flags & 4) != 0)
    {
        return;
    }
    if ((state->flags & 0x200) != 0)
    {
        f32 v = state->respawnTimer;
        f32 k = lbl_803E4554;
        if (v > k)
        {
            state->respawnTimer = v - timeDelta;
            if (state->respawnTimer <= k)
            {
                *(s16*)&state->flags = 0;
                ((GameObject*)obj)->anim.alpha = 0xFF;
                ObjHits_DisableObject(obj);
                fn_801A7D74(obj, 1, 1);
            }
            else
            {
                ((GameObject*)obj)->anim.alpha =
                    (u8)(int)(gMoonRockAlphaMax * (lbl_803E457C - state->respawnTimer / gMoonRockRespawnTime));
                objParticleFn_80099d84(obj, lbl_803E4588, 2, lbl_803E457C - state->respawnTimer / gMoonRockRespawnTime, 0);
                objParticleFn_80099d84(obj, lbl_803E4588, 2, lbl_803E457C - state->respawnTimer / gMoonRockRespawnTime, 0);
            }
        }
        return;
    }
    objfx_spawnDirectionalBurst(obj, 1, lbl_803E457C, 5, 1, 0xA, lbl_803E454C, 0, 0);
    objfx_spawnDirectionalBurst(obj, 5, lbl_803E457C, 5, 1, 0x14, lbl_803E454C, 0, 0);
    if ((state->flags & 0x40) != 0)
    {
        fn_801A7B10(obj);
        fn_801A79E0(obj);
        return;
    }
    grabbed = 0;
    if ((state->flags & 8) != 0 &&
        (u8)(*gMapEventInterface)->getObjGroupStatus(0x12, 6) == 0)
    {
        state->flags |= 1;
    }
    else if ((state->flags & 0x400) == 0)
    {
        if (((MmpMoonrockPlacement*)def)->gateBit != -1 && GameBit_Get(((MmpMoonrockPlacement*)def)->gateBit) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        else if ((*gCarryableInterface)->getAnimState(obj, *(int*)&((GameObject*)obj)->extra) != 0)
        {
            grabbed = 1;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    state->flags &= ~0x8;
    if (grabbed != 0)
    {
        int stateCopy;
        int i;
        int* list;
        u8 found;
        if ((playerGetStateFlag310((int)Obj_GetPlayerObject()) & 0x4000) != 0)
        {
            setAButtonIcon(5);
            state->flags |= 0x18;
            state->flags &= ~0x20;
        }
        else
        {
            setAButtonIcon(4);
            state->flags |= 0x28;
            state->flags &= ~0x10;
        }
        stateCopy = *(int*)&((GameObject*)obj)->extra;
        (*gCarryableInterface)->setVisible(stateCopy, 0);
        list = (int*)ObjGroup_GetObjects(0x10, &count);
        {
            f32 k = gMoonRockPickupRange;
            for (i = 0; i < count; i++)
            {
                u32 o = (u32) * list;
                if (o != obj && ((GameObject*)o)->anim.seqId == 0x519 &&
                    Vec_xzDistance((f32*)(obj + 0x18), (f32*)(o + 0x18)) < k)
                {
                    (*gCarryableInterface)->setVisible(stateCopy, 1);
                    found = 0;
                    goto checked;
                }
                list++;
            }
        }
        found = 1;
    checked:
        if (found != 0)
        {
            state->flags |= 1;
        }
        if ((state->flags & 2) != 0)
        {
            fn_801A7D74(obj, 0, 0);
            state->flags &= ~0x2;
        }
        return;
    }
    {
        u16 flags = state->flags;
        if ((flags & 0x400) == 0 && (flags & 1) != 0)
        {
            if ((flags & 0x20) != 0)
            {
                fn_801A7CC4(obj);
            }
            else
            {
                fn_801A7D74(obj, 1, 0);
            }
            state->flags &= ~0x1;
        }
    }
    state->flags |= 2;
    if (state->kind == 0)
    {
        return;
    }
    if ((state->flags & 0x400) != 0)
    {
        state->raised = GameBit_Get(0x894);
    }
    else
    {
        state->raised = 0;
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_diallp_c);
    Sfx_SetObjectChannelVolume(obj, 0x40, state->raised * 0x20 + 0x20, lbl_803E4588);
    {
        f32 speed = ((GameObject*)obj)->anim.velocityY;
        if (speed < lbl_803E458C * ((lbl_803E4568 * state->raised + state->baseY) - ((GameObject*)obj)->anim.
            localPosY))
        {
            ((GameObject*)obj)->anim.velocityY = speed + lbl_803E4590;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityY = speed - lbl_803E4594;
        }
    }
    state->bobPhase += 0x1000;
    state->rollPhase += 0xDAC;
    state->pitchPhase += 0x800;
    ((void (*)(int, f32, f32, f32))objMove)(obj, lbl_803E4554, ((GameObject*)obj)->anim.velocityY * timeDelta,
                                            *(f32*)&lbl_803E4554);
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + mathSinf(
        (gMoonRockPi * state->bobPhase) / gMoonRockAngleScale);
    if (((GameObject*)obj)->anim.localPosY < state->baseY)
    {
        ((GameObject*)obj)->anim.localPosY = state->baseY;
    }
    ((GameObject*)obj)->anim.rotZ = (s16)(
        ((GameObject*)obj)->anim.rotZ + (int)(gMoonRockWobbleAmplitude * mathSinf(
            (gMoonRockPi * state->rollPhase) / gMoonRockAngleScale)));
    ((GameObject*)obj)->anim.rotY = (s16)(
        ((GameObject*)obj)->anim.rotY + (int)(gMoonRockWobbleAmplitude * mathSinf(
            (gMoonRockPi * state->pitchPhase) / gMoonRockAngleScale)));
    *(f32*)(gMoonRockSpawnParams + 8) = lbl_803E457C;
    *(f32*)(gMoonRockSpawnParams + 0xC) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(gMoonRockSpawnParams + 0x10) = state->baseY;
    *(f32*)(gMoonRockSpawnParams + 0x14) = ((GameObject*)obj)->anim.localPosZ;
    d = (int)(((GameObject*)obj)->anim.localPosY - state->baseY);
    (*gPartfxInterface)->spawnObject((void*)obj, 0x723, gMoonRockSpawnParams, 0x200001, -1, &d);
}
