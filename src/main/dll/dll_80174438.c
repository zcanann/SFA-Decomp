/* DLL — collectible objects [80173224-801732A4) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/magicgemstate_struct.h"
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICGEM family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */

/* 8b "li r3, N; blr" returners. */

/* render-with-fn(lbl) (no visibility check). */

#include "main/obj_placement.h"
#include "main/dll/pushable.h"
#include "main/objtexture.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"
extern int Sfx_PlayFromObject(int obj, int sfxId);

extern u32 fn_80174BFC();


STATIC_ASSERT(offsetof(MagicGemState, flags27A) == 0x27A);

extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern int fn_80295A04(void* player, int p2);
extern void fn_80175428(int obj, int p2);
extern f32 lbl_803E352C;
extern f64 lbl_803E3530;
extern f64 lbl_803E3538;
extern f32 lbl_803E3540;
extern f32 lbl_803E3544;
extern f32 lbl_803E3548;
extern f32 lbl_803E354C;
extern f32 lbl_803E3550;
extern f32 lbl_803E3554;
extern f32 lbl_803E3558;
extern f32 lbl_803E355C;
extern f32 lbl_803E3560;
extern f32 lbl_803E3564;
extern f32 lbl_803E3568;
extern f32 lbl_803E356C;
extern f32 lbl_803E3570;
extern f32 lbl_803E3528;

void fn_80174588(int obj, PushableState* p2)
{
    int data = *(int*)&((GameObject*)obj)->anim.placementData;

    switch (*(int*)(data + 0x14))
    {
    case 0x49B2C:
        p2->requiredHitId = 10;
        break;
    case 0x49B5D:
        p2->requiredHitId = 11;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        break;
    case 0x49B5E:
        p2->requiredHitId = 12;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        break;
    }

    if (GameBit_Get(*(s16*)(data + 0x18)) != 0)
    {
        ObjTextureRuntimeSlot* tex;
        p2->flags = (u16)(p2->flags | 0x80);
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != NULL)
        {
            tex->textureId = 256;
        }
    }
}

int fn_80174438(int obj, PushableState* state)
{
    int def;
    void* player;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (((state->flags & 0x80) != 0) || (fn_80295A04(player, 10) != 0))
    {
        Sfx_StopObjectChannel(obj, 8);
        return 0;
    }
    Sfx_PlayFromObject(obj, SFXTRIG_treedrum16);
    state->flags |= 2;
    if ((state->flags & 4) == 0)
    {
        fn_80174BFC(obj, state);
    }
    if (((GameObject*)obj)->anim.localPosX <= lbl_803E352C + ((ObjPlacement*)def)->posX)
    {
        GameBit_Set(state->gameBit, 1);
        state->flags |= 0x80;
        ((GameObject*)obj)->anim.localPosX = (f32)(((ObjPlacement*)def)->posX - lbl_803E3530);
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = (f32)(lbl_803E3538 + ((ObjPlacement*)def)->posZ);
        Sfx_PlayFromObject(obj, SFXTRIG_curtainopen16);
    }
    if (GameBit_Get(0xa1a) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)def)->posZ;
    }
    return 0;
}

int fn_80174668(int obj, PushableState* state)
{
    u8 flag;
    ObjTextureRuntimeSlot* tex;
    f32 dy;
    f32 dx;
    f32 cur;
    f32 bound;
    f32 p1;
    f32 p2;
    f32 dist[2];

    flag = 0;
    dist[0] = lbl_803E3540;
    fn_80175428(obj, 0);
    if (GameBit_Get(state->gameBit) != 0)
    {
        cur = ((GameObject*)obj)->anim.rootMotionScale;
        bound = lbl_803E3544;
        if (cur > bound)
        {
            ((GameObject*)obj)->anim.rootMotionScale = -(lbl_803E3548 * timeDelta - ((GameObject*)obj)->anim.
                rootMotionScale);
            if (((GameObject*)obj)->anim.rootMotionScale <= bound)
            {
                ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3528;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E354C;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            }
        }
        return 1;
    }
    if (state->nearestObj == NULL)
    {
        state->nearestObj = (void*)ObjGroup_FindNearestObject(0x11, obj, dist);
    }
    if (state->nearestObj == NULL)
    {
        return 0;
    }
    if (state->eyeOpenAmount < lbl_803E3550)
    {
        state->eyeOpenAmount = *(f32 *)&lbl_803E3550;
    }
    dy = ((GameObject*)state->nearestObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    if (dy < lbl_803E3528)
    {
        dy = dy * lbl_803E3554;
    }
    cur = state->unk_F0;
    if (cur < lbl_803E3558 + dy)
    {
        return 0;
    }
    dx = ((GameObject*)state->nearestObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    if (dx < *(f32 *)&lbl_803E3528)
    {
        dx = dx * lbl_803E3554;
    }
    if (dx > lbl_803E355C)
    {
        return 0;
    }
    if ((cur >= lbl_803E3558 + dy) && (cur <= lbl_803E3560 + dy))
    {
        flag = 1;
        GameBit_Set(0x1c9, 1);
    }
    tex = objFindTexture((void*)obj, 0, 0);
    state->blinkPhase = state->blinkStep * timeDelta + state->blinkPhase;
    if (state->blinkPhase >= state->blinkInterval)
    {
        state->blinkStep = state->blinkStep * lbl_803E3554;
    }
    else if (state->blinkPhase < lbl_803E3528)
    {
        state->blinkInterval = lbl_803E3564 * (f32)(int)
        randomGetRange(0x19, 0x4b);
        state->blinkStep = state->blinkInterval / (f32)(int)
        randomGetRange(0x28, 0x46);
        state->blinkPhase = lbl_803E3528;
    }
    if (tex != NULL)
    {
        state->eyeOpenAmount = state->eyeOpenAmount + state->eyeOpenSpeed;
        if (state->eyeOpenAmount >= lbl_803E3568)
        {
            GameBit_Set(state->gameBit, 1);
            if (flag)
            {
                GameBit_Set(0x1c9, 0);
            }
            tex = (ObjTextureRuntimeSlot*)Resource_Acquire(0x5b, 1);
            ((VtableFn*)(*(int*)tex))[1](obj, 0x14, 0, 2, -1, 0);
            ((VtableFn*)(*(int*)tex))[1](obj, 0x14, 0, 2, -1, 0);
            Resource_Release(tex);
            Sfx_PlayFromObject(obj, SFXTRIG_espar5_c);
        }
        else
        {
            state->eyePosX = state->eyePosX + state->eyeDriftSpeedX;
            if (state->eyePosX > lbl_803E356C)
            {
                state->eyePosX = lbl_803E356C;
            }
            else if (state->eyePosX < lbl_803E3528)
            {
                state->eyePosX = lbl_803E356C;
            }
            state->eyePosY = state->eyePosY + state->eyeDriftSpeedY;
            if (state->eyePosY > lbl_803E356C)
            {
                state->eyePosY = lbl_803E356C;
            }
            else if (state->eyePosY < lbl_803E3528)
            {
                state->eyePosY = lbl_803E356C;
            }
            p1 = state->eyePosX * (lbl_803E3570 + state->blinkPhase);
            p2 = state->eyePosY * (lbl_803E3570 + state->blinkPhase);
            tex->colorR = (u8)(int)state->eyeOpenAmount;
            tex->colorG = (u8)(int)p1;
            tex->colorB = (u8)(int)p2;
        }
    }
    return 0;
}
