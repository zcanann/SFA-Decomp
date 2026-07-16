/* DLL 0x00FF - magic-gem / collectible objects [80173224-801732A4) */
#include "main/dll/dll_00FF_magicgem.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "main/dll/magicgemstate_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"
#include "main/gamebits.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/os/OSReport.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/player_api.h"

#define MAGICGEM_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MAGICGEM_MSG_IN_RANGE               0x7000a /* sent to player when in pickup range */
#define MAGICGEM_MSG_PICKUP                 0x7000b /* collect: award magic + burst */
#define MAGICGEM_GAMEBIT_CLAIMED            0x90d   /* per-frame single-pickup latch */

#define MAGICGEM_RENDER_SCALE              1.0f
#define MAGICGEM_BURST_TIMER               180.0f
#define MAGICGEM_ACTIVATE_DIST_SQ          250000.0f
#define MAGICGEM_VELOCITY_DAMPING          0.99f
#define MAGICGEM_GRAVITY                   0.1f
#define MAGICGEM_ZERO                      0.0f
#define MAGICGEM_LONG_BURST_TIMER          1800.0f
#define MAGICGEM_BOUNCE_SFX_SPEED          0.5f
#define MAGICGEM_FLOOR_NORMAL_THRESHOLD    0.707f
#define MAGICGEM_BOUNCE_RESTITUTION_Y      0.6f
#define MAGICGEM_BOUNCE_RESTITUTION_XZ     0.7f
#define MAGICGEM_PICKUP_Y_RANGE            20.0f
#define MAGICGEM_PICKUP_RADIUS_BASE        8.0f
#define MAGICGEM_RANDOM_SPEED_SCALE        100.0f
#define MAGICGEM_PI                        3.1415927f
#define MAGICGEM_ANGLE_RAND_SCALE          32768.0f
#define MAGICGEM_RANDOM_Y_SPEED_SCALE      50.0f
#define MAGICGEM_FOLLOW_TIME               120.0f
#define MAGICGEM_COLLECT_RADIUS            7.0f
#define MAGICGEM_INITIAL_BURST_TIMER        60.0f

static const u16 sMagicGemTexPickA[2] = {0xD10, 0};
static const u16 sMagicGemTexPickB[2] = {0xE11, 0};
static u8 sMagicGemPathData[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

ObjectDescriptor gMagicGemObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicDust_init,
    (ObjectDescriptorCallback)MagicDust_update,
    0,
    (ObjectDescriptorCallback)MagicDust_render,
    (ObjectDescriptorCallback)MagicDust_free,
    0,
    MagicDust_getExtraSize,
};
STATIC_ASSERT(offsetof(MagicGemState, flags27A) == 0x27A);

int MagicDust_getExtraSize(void)
{
    return 0x288;
}

void MagicDust_free(GameObject* obj)
{
    if (*(u32*)&obj->ownerObj != 0)
    {
        ObjLink_DetachChild((GameObject*)obj->ownerObj, (int)obj);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    return;
}

void MagicDust_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes((GameObject*)p1, MAGICGEM_RENDER_SCALE);
}

typedef struct MagicgemObjectDef
{
    u8 pad0[0xb - 0x0];
    s8 magicAmount;
    u8 padC[0x26 - 0xc];
    u8 bankIndex;
    u8 pad27[0x2e - 0x27];
    s16 spawnMode;
} MagicgemObjectDef;

static inline void magicgem_collect(GameObject* obj, MagicGemState* state, int player)
{
    MagicgemObjectDef* ref = (MagicgemObjectDef*)obj->anim.modelInstance->extraSetupData;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    itemPickupDoParticleFxLegacy((int)obj, MAGICGEM_RENDER_SCALE, state->mode, 0x28);
    ObjHits_DisableObject(obj);
    Sfx_PlayFromObject((int)obj, (u16)state->sfxId);
    Sfx_StopFromObject((int)obj, SFXTRIG_rfall5_c);
    playerAddRemoveMagic((GameObject*)player, (int)ref->magicAmount);
    state->flags27A = state->flags27A & ~5;
    state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECTED;
    state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECT_LATCH;
    state->burstTimer = MAGICGEM_BURST_TIMER;
    OSReport("Magic collected");
    obj->anim.alpha = 1;
}

void MagicDust_update(GameObject* obj)
{
    float fval;
    u8 flagsByte;
    int player;
    int ref;
    u32 val;
    MagicGemState* state;
    u8 burstArg;
    char fxArg;
    int msg[1];
    f32 dist;

    player = (int)Obj_GetPlayerObject();
    state = obj->extra;
    while (ref = ObjMsg_Pop(obj, (u32*)msg, 0x0, 0x0), ref != 0)
    {
        switch (msg[0])
        {
        case MAGICGEM_MSG_PICKUP:
            magicgem_collect(obj, state, player);
            break;
        }
    }
    if ((state->flags27A & MAGICGEM_FLAG_AMBIENT_FX) == 0)
    {
        if (((state->flags27A & MAGICGEM_FLAG_COLLECT_LATCH) == 0) &&
            (getXZDistance(&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < MAGICGEM_ACTIVATE_DIST_SQ))
        {
            state->flags27A = state->flags27A | MAGICGEM_FLAG_AMBIENT_FX;
            fxArg = '\0';
            (*gPartfxInterface)->spawnObject((void*)obj, state->ambientEffectId, NULL, 0x10002, -1, &fxArg);
            fxArg = '\x01';
            (*gPartfxInterface)->spawnObject((void*)obj, state->ambientEffectId, NULL, 0x10002, -1, &fxArg);
            fxArg = '\x02';
            (*gPartfxInterface)->spawnObject((void*)obj, state->ambientEffectId, NULL, 0x10002, -1, &fxArg);
        }
    }
    else
    {
        if (getXZDistance(&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) >= MAGICGEM_ACTIVATE_DIST_SQ)
        {
            state->flags27A = state->flags27A & ~MAGICGEM_FLAG_AMBIENT_FX;
            (*gExpgfxInterface)->freeSource2((u32)obj);
        }
    }
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        if ((state->flags27A & MAGICGEM_FLAG_SETTLED) != 0)
        {
            obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x100;
            if ((state->ambientTimer -= framesThisStep) < 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_rfall5_c);
                val = randomGetRange(0xf0, 300);
                state->ambientTimer = val;
            }
        }
        if (*(u32*)&obj->ownerObj != 0)
        {
            player = (int)obj->anim.modelState;
            if ((u32)player != 0)
            {
                obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
            (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
            goto LAB_80173f80;
        }
        ref = (int)obj->anim.modelState;
        if ((u32)ref != 0)
        {
            obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        state->unk25B = 1;
        if ((state->flags27A & 3) == 0)
        {
            obj->anim.velocityX *= MAGICGEM_VELOCITY_DAMPING;
            obj->anim.velocityZ *= MAGICGEM_VELOCITY_DAMPING;
            obj->anim.velocityY = -(MAGICGEM_GRAVITY * timeDelta - obj->anim.velocityY);
        }
        state->burstTimer = state->burstTimer - timeDelta;
        flagsByte = state->flags27A;
        if ((flagsByte & MAGICGEM_FLAG_BURST1) != 0)
        {
            if (state->burstTimer <= MAGICGEM_ZERO)
            {
                state->flags27A = flagsByte & ~MAGICGEM_FLAG_BURST1;
                state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST2;
                state->burstTimer = MAGICGEM_LONG_BURST_TIMER;
                obj->anim.alpha = 0xff;
            }
            if (obj->anim.parent == NULL)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, state->burstEffectId, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, state->burstEffectId, NULL, 1, -1, NULL);
            }
        }
        else
        {
            if ((flagsByte & MAGICGEM_FLAG_BURST2) != 0)
            {
                if (state->burstTimer <= MAGICGEM_ZERO)
                {
                    state->flags27A = flagsByte & ~MAGICGEM_FLAG_BURST2;
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECTED;
                    state->burstTimer = MAGICGEM_BURST_TIMER;
                    (*gExpgfxInterface)->freeSource2((u32)obj);
                    if (obj->anim.parent == NULL)
                    {
                        for (burstArg = '\x1e'; burstArg != '\0'; burstArg--)
                        {
                            (*gPartfxInterface)->spawnObject((void*)obj, state->burstEffectId, NULL, 1, -1, &burstArg);
                        }
                    }
                    obj->anim.alpha = 1;
                    Sfx_PlayFromObject((int)obj, SFXTRIG_en_liftstpc);
                }
                objMove((GameObject*)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                        obj->anim.velocityZ * timeDelta);
            }
            else
            {
                if (state->burstTimer <= MAGICGEM_ZERO)
                {
                    Obj_FreeObject(obj);
                }
                goto LAB_80173f80;
            }
        }
        if ((state->flags27A & 3) == 0)
        {
            (*gPathControlInterface)->update((void*)obj, (void*)state, timeDelta);
            (*gPathControlInterface)->apply((void*)obj, (void*)state);
            (*gPathControlInterface)->advance((void*)obj, (void*)state, timeDelta);
            if (state->contacted != '\0')
            {
                float vx = -obj->anim.velocityX;
                float vy = -obj->anim.velocityY;
                float vz = -obj->anim.velocityZ;
                float mag = sqrtf(vx * vx + vy * vy + vz * vz);
                if (mag > MAGICGEM_BOUNCE_SFX_SPEED)
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_en_lflsh3_c_16b);
                }
                if (state->contactNormalY >= MAGICGEM_FLOOR_NORMAL_THRESHOLD)
                {
                    obj->anim.velocityY = -obj->anim.velocityY;
                    obj->anim.velocityY *= MAGICGEM_BOUNCE_RESTITUTION_Y;
                }
                else
                {
                    obj->anim.velocityX = -obj->anim.velocityX;
                    obj->anim.velocityZ = -obj->anim.velocityZ;
                    obj->anim.velocityX *= MAGICGEM_BOUNCE_RESTITUTION_XZ;
                    obj->anim.velocityZ *= MAGICGEM_BOUNCE_RESTITUTION_XZ;
                }
                ref = state->bounceCount + 1;
                state->bounceCount++;
                if (5 < (u8)ref)
                {
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_SETTLED;
                    fval = MAGICGEM_ZERO;
                    obj->anim.velocityX = MAGICGEM_ZERO;
                    obj->anim.velocityY = fval;
                    obj->anim.velocityZ = fval;
                }
            }
        }
    }
    if ((state->flags27A & MAGICGEM_FLAG_CLAIMED) == 0)
    {
        switch (state->flags27A & MAGICGEM_FLAG_COLLECT_LATCH)
        {
        case 0:
            fval = obj->anim.localPosY - ((GameObject*)player)->anim.localPosY;
            if (fval < MAGICGEM_ZERO)
            {
                fval = -fval;
            }
            if (fval < MAGICGEM_PICKUP_Y_RANGE)
            {
                dist = getXZDistance(&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
                fval = MAGICGEM_PICKUP_RADIUS_BASE + state->collectRadius;
                if ((dist < fval * fval) && (Obj_IsParentSlackClear((GameObject*)player) != 0))
                {
                    val = mainGetBit(MAGICGEM_GAMEBIT_CLAIMED);
                    if (val == 0)
                    {
                        *(s16*)&state->pickupMsgArg = 0xffff;
                        ObjMsg_SendToObject((void*)player, MAGICGEM_MSG_IN_RANGE, obj, (int)state + 0x280);
                        ObjHits_DisableObject(obj);
                        mainSetBits(MAGICGEM_GAMEBIT_CLAIMED, 1);
                        state->flags27A = state->flags27A | MAGICGEM_FLAG_CLAIMED;
                    }
                    else
                    {
                        magicgem_collect(obj, state, player);
                    }
                }
            }
        }
    }
LAB_80173f80:
    return;
}

void MagicDust_init(GameObject* obj, MagicgemObjectDef* placement)
{
    short mode;
    u32 randVal;
    int ref;
    MagicGemState* state;
    f32 ang;
    f32 spd;
    u16 texPickA[2];
    u16 texPickB[2];
    u8 pathArgs[4];

    state = obj->extra;
    pathArgs[0] = 3;
    texPickA[0] = sMagicGemTexPickA[0];
    texPickB[0] = sMagicGemTexPickB[0];
    randVal = randomGetRange(0, 0xffff);
    spd = (f32)(int)randomGetRange(0x27, 0x2c) / MAGICGEM_RANDOM_SPEED_SCALE;
    ang = (MAGICGEM_PI * (f32)(int)randVal) / MAGICGEM_ANGLE_RAND_SCALE;
    obj->anim.velocityX = spd * mathSinf(ang);
    obj->anim.velocityZ = spd * mathCosf(ang);
    obj->anim.velocityY = (f32)(int)randomGetRange(0x28, 0x32) / MAGICGEM_RANDOM_Y_SPEED_SCALE;
    mode = placement->spawnMode;
    if (mode == 1)
    {
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = 1;
    }
    else if (mode == 2)
    {
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = 1;
        if (*(u32*)&obj->anim.hitReactState != 0)
        {
            ObjHits_DisableObject(obj);
        }
        ref = (int)Obj_GetPlayerObject();
        obj->anim.velocityX = (((GameObject*)ref)->anim.localPosX - obj->anim.localPosX) / MAGICGEM_FOLLOW_TIME;
        obj->anim.velocityY = (((GameObject*)ref)->anim.localPosY - obj->anim.localPosY) / MAGICGEM_FOLLOW_TIME;
        obj->anim.velocityZ = (((GameObject*)ref)->anim.localPosZ - obj->anim.localPosZ) / MAGICGEM_FOLLOW_TIME;
    }
    else if (mode == 3)
    {
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = 1;
        obj->anim.velocityY = -((f32)(int)randomGetRange(0x8c, 0x96) / MAGICGEM_RANDOM_Y_SPEED_SCALE);
    }
    obj->anim.bankIndex = placement->bankIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount)
    {
        obj->anim.bankIndex = 0;
    }
    if (obj->anim.modelState != NULL)
    {
        obj->anim.modelState->shadowTintA = 100;
        obj->anim.modelState->shadowTintB = 0x96;
    }
    ref = (int)Obj_GetActiveModel(obj);
    mode = obj->anim.seqId;
    switch (mode)
    {
    case 0x2c4:
        randVal = randomGetRange(0, 1);
        *(u8*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickA + randVal);
        state->ambientEffectId = 0x54f;
        state->burstEffectId = 0x54b;
        state->sfxId = 0x58;
        state->unk276 = 0x5b0;
        state->mode = 4;
        break;
    case 0x2cd:
        randVal = randomGetRange(0, 1);
        *(u8*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickB + randVal);
        state->ambientEffectId = 0x54e;
        state->burstEffectId = 0x54a;
        state->sfxId = 0x59;
        state->unk276 = 0x5b1;
        state->mode = 1;
        break;
    case 0x2ce:
        *(u8*)(*(int*)(ref + 0x34) + 8) = 3;
        state->ambientEffectId = 0x54d;
        state->burstEffectId = 0x549;
        state->sfxId = 0x5a;
        state->unk276 = 0x5b2;
        state->mode = 2;
        break;
    case 0x2cf:
    default:
        *(u8*)(*(int*)(ref + 0x34) + 8) = 2;
        state->ambientEffectId = 0x550;
        state->burstEffectId = 0x54c;
        state->sfxId = 0x5b;
        state->unk276 = 0x5b3;
        state->mode = 6;
        break;
    }
    state->collectRadius = MAGICGEM_COLLECT_RADIUS;
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        (*gPathControlInterface)->init((void*)state, 0, 0x40007, 0);
        (*gPathControlInterface)->setup((void*)state, 1, sMagicGemPathData, (void*)((int)state + 0x268), pathArgs);
        (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
    }
    obj->objectFlags = obj->objectFlags | MAGICGEM_OBJFLAG_HITDETECT_DISABLED;
    if ((state->flags27A & MAGICGEM_FLAG_BURST1) != 0)
    {
        state->burstTimer = MAGICGEM_INITIAL_BURST_TIMER;
    }
    else
    {
        state->burstTimer = MAGICGEM_LONG_BURST_TIMER;
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST2;
    }
    ObjMsg_AllocQueue(obj, 1);
    return;
}
