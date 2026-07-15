/* DLL — collectible objects [80173224-801732A4) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/magicgemstate_struct.h"

#include "main/obj_placement.h"
#include "main/dll/pushable.h"
#include "main/objtexture.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_stop_channel_api.h"

extern u32 fn_80174BFC();

#define MAGICGEM_TARGET_OBJGROUP 0x11

STATIC_ASSERT(offsetof(MagicGemState, flags27A) == 0x27A);

extern void pushable_handleMsgs(int obj, int p2);
#define PUSHABLE_ZERO 0.0f
#define CURTAIN_TRIGGER_X_OFFSET -175.0f
#define CURTAIN_POSITION_X_OFFSET 188.0
#define CURTAIN_POSITION_Z_OFFSET 186.0
#define MAGIC_GEM_INITIAL_DISTANCE 10000.0f
#define MAGIC_GEM_ROOT_MOTION_CUTOFF 0.001f
#define MAGIC_GEM_ROOT_MOTION_DECAY 0.02f
#define MAGIC_GEM_HIDE_Y_OFFSET 300.0f
#define MAGIC_GEM_EYE_OPEN_MIN 150.0f
#define MAGIC_GEM_NEGATE -1.0f
#define MAGIC_GEM_NEAR_Z_MIN 10.0f
#define MAGIC_GEM_NEAR_X_MAX 30.0f
#define MAGIC_GEM_NEAR_Z_MAX 40.0f
#define MAGIC_GEM_BLINK_INTERVAL_SCALE 0.01f
#define MAGIC_GEM_EYE_OPEN_MAX 225.0f
#define MAGIC_GEM_EYE_POSITION_MAX 255.0f
#define MAGIC_GEM_BLINK_SCALE_BASE 0.25f

int fn_80174438(int obj, PushableState* state)
{
    int def;
    GameObject* player;

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
    if (((GameObject*)obj)->anim.localPosX <= CURTAIN_TRIGGER_X_OFFSET + ((ObjPlacement*)def)->posX)
    {
        mainSetBits(state->gameBit, 1);
        state->flags |= 0x80;
        ((GameObject*)obj)->anim.localPosX = (f32)(((ObjPlacement*)def)->posX - CURTAIN_POSITION_X_OFFSET);
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = (f32)(CURTAIN_POSITION_Z_OFFSET + ((ObjPlacement*)def)->posZ);
        Sfx_PlayFromObject(obj, SFXTRIG_curtainopen16);
    }
    if (mainGetBit(0xa1a) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)def)->posZ;
    }
    return 0;
}

void fn_80174588(GameObject *obj, PushableState* state)
{
    int data = *(int*)&(obj)->anim.placementData;

    switch (*(int*)(data + 0x14))
    {
    case 0x49B2C:
        state->requiredHitId = 10;
        break;
    case 0x49B5D:
        state->requiredHitId = 11;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        break;
    case 0x49B5E:
        state->requiredHitId = 12;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        break;
    }

    if (mainGetBit(*(s16*)(data + 0x18)) != 0)
    {
        ObjTextureRuntimeSlot* tex;
        state->flags = (u16)(state->flags | 0x80);
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            tex->textureId = 256;
        }
    }
}

int fn_80174668(GameObject *obj, PushableState* state)
{
    u8 flag;
    ObjTextureRuntimeSlot* tex;
    f32 cur;
    f32 dx;
    f32 dy;
    f32 bound;
    f32 eyeScaledX;
    f32 eyeScaledY;
    f32 dist[2];

    flag = 0;
    dist[0] = MAGIC_GEM_INITIAL_DISTANCE;
    pushable_handleMsgs((int)obj, 0);
    if (mainGetBit(state->gameBit) != 0)
    {
        cur = (obj)->anim.rootMotionScale;
        bound = MAGIC_GEM_ROOT_MOTION_CUTOFF;
        if (cur > bound)
        {
            obj->anim.rootMotionScale -= MAGIC_GEM_ROOT_MOTION_DECAY * timeDelta;
            if ((obj)->anim.rootMotionScale <= bound)
            {
                (obj)->anim.rootMotionScale = PUSHABLE_ZERO;
                obj->anim.localPosY -= MAGIC_GEM_HIDE_Y_OFFSET;
                *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            }
        }
        return 1;
    }
    if (state->nearestObj == NULL)
    {
        state->nearestObj = (void*)ObjGroup_FindNearestObject(MAGICGEM_TARGET_OBJGROUP, (int)obj, dist);
    }
    if (state->nearestObj == NULL)
    {
        return 0;
    }
    if (state->eyeOpenAmount < MAGIC_GEM_EYE_OPEN_MIN)
    {
        state->eyeOpenAmount = MAGIC_GEM_EYE_OPEN_MIN;
    }
    dy = ((GameObject*)state->nearestObj)->anim.localPosZ - (obj)->anim.localPosZ;
    if (dy < PUSHABLE_ZERO)
    {
        dy *= MAGIC_GEM_NEGATE;
    }
    cur = state->unk_F0;
    if (cur < MAGIC_GEM_NEAR_Z_MIN + dy)
    {
        return 0;
    }
    dx = ((GameObject*)state->nearestObj)->anim.localPosX - (obj)->anim.localPosX;
    if (dx < PUSHABLE_ZERO)
    {
        dx *= MAGIC_GEM_NEGATE;
    }
    if (dx > MAGIC_GEM_NEAR_X_MAX)
    {
        return 0;
    }
    if ((cur >= MAGIC_GEM_NEAR_Z_MIN + dy) && (cur <= MAGIC_GEM_NEAR_Z_MAX + dy))
    {
        flag = 1;
        mainSetBits(0x1c9, 1);
    }
    tex = objFindTexture(obj, 0, 0);
    state->blinkPhase += state->blinkStep * timeDelta;
    if (state->blinkPhase >= state->blinkInterval)
    {
        state->blinkStep *= MAGIC_GEM_NEGATE;
    }
    else if (state->blinkPhase < PUSHABLE_ZERO)
    {
        state->blinkInterval = MAGIC_GEM_BLINK_INTERVAL_SCALE * (f32)(int)
        randomGetRange(0x19, 0x4b);
        state->blinkStep = state->blinkInterval / (f32)(int)
        randomGetRange(0x28, 0x46);
        state->blinkPhase = PUSHABLE_ZERO;
    }
    if (tex != NULL)
    {
        state->eyeOpenAmount += state->eyeOpenSpeed;
        if (state->eyeOpenAmount >= MAGIC_GEM_EYE_OPEN_MAX)
        {
            mainSetBits(state->gameBit, 1);
            if (flag)
            {
                mainSetBits(0x1c9, 0);
            }
            tex = (ObjTextureRuntimeSlot*)Resource_Acquire(0x5b, 1);
            ((VtableFn*)(*(int*)tex))[1](obj, 0x14, 0, 2, -1, 0);
            ((VtableFn*)(*(int*)tex))[1](obj, 0x14, 0, 2, -1, 0);
            Resource_Release(tex);
            Sfx_PlayFromObject((int)obj, SFXTRIG_espar5_c);
        }
        else
        {
            state->eyePosX += state->eyeDriftSpeedX;
            if (state->eyePosX > MAGIC_GEM_EYE_POSITION_MAX)
            {
                state->eyePosX = MAGIC_GEM_EYE_POSITION_MAX;
            }
            else if (state->eyePosX < PUSHABLE_ZERO)
            {
                state->eyePosX = MAGIC_GEM_EYE_POSITION_MAX;
            }
            state->eyePosY += state->eyeDriftSpeedY;
            if (state->eyePosY > MAGIC_GEM_EYE_POSITION_MAX)
            {
                state->eyePosY = MAGIC_GEM_EYE_POSITION_MAX;
            }
            else if (state->eyePosY < PUSHABLE_ZERO)
            {
                state->eyePosY = MAGIC_GEM_EYE_POSITION_MAX;
            }
            eyeScaledX = state->eyePosX * (MAGIC_GEM_BLINK_SCALE_BASE + state->blinkPhase);
            eyeScaledY = state->eyePosY * (MAGIC_GEM_BLINK_SCALE_BASE + state->blinkPhase);
            tex->colorR = (u8)(int)state->eyeOpenAmount;
            tex->colorG = (u8)(int)eyeScaledX;
            tex->colorB = (u8)(int)eyeScaledY;
        }
    }
    return 0;
}
