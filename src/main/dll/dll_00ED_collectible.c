/*
 * DLL 0x00ED — collectible / genprops object group. TU: 0x80171D14–0x801723DC.
 *
 * Hosts the pick-up "collectible" object (the magicgem/scarab family) plus
 * the ObjectDescriptor tables for a batch of sibling genprops objects whose
 * bodies live in other TUs (mikabomb, mikabombshadow, StaticCamera,
 * gcbaddieshield, baddieinterestp, animatedobj, dim2roofrub, depthoffieldpoint,
 * staff, fireball, flamethrowerspe, shield, curve, restartmarker, dll_F7,
 * checkpoint4).
 *
 * collectible behaviour (init/update/render/SeqFn): each instance is gated by
 * placement game bits (visibilityGameBit / hideGameBit). On player proximity
 * (Vec_xzDistance vs a per-object radius) it is picked up by anim.seqId: health
 * items add health, dust items bump counters, others message the player object
 * (ObjMsg 0x7000a / 0x7000b) and play a pickup sfx + particle fx. Picked-up
 * objects fade their shadow (OBJ_MODEL_STATE_SHADOW_FADE_OUT), set their hide
 * game bit, and unsave their saved position. Per-seqId spin/bob motion and a
 * bounce/path-follow physics step (gPathControlInterface) run while idle.
 */
#include "main/game_object.h"
#include "main/vecmath_distance_api.h"
#include "main/dll/checkpoint4.h"
#include "main/dll/dll_00E5_shield_api.h"
#include "main/dll/dll_00DD_gcbaddieshield_api.h"
#include "main/dll/dll_00DC_mikabombshadow_api.h"
#include "main/dll/dll_00DB_mikabomb_api.h"
#include "main/dll/dll_00DE_baddieinterestp_api.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/dll_00C6_animatedobj_api.h"
#include "main/dll/DIM/dll_00C7_dim2roofrub_api.h"
#include "main/dll/dll_00E6_restartmarker.h"
#include "main/dll/dll_00F7_dllf7_api.h"
#include "main/dll/dll_0125_curve_api.h"
#include "main/dll/dll_025A_staticcamera.h"
#include "main/object.h"
#include "main/dll/savegame.h"
#include "main/dll/player_api.h"
#include "main/object_api.h"
#include "main/objprint_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/dll/path_control_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/obj_placement.h"
#include "main/dll/collectible_state.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_00ED_collectible.h"
#include "main/dll/dll_00E4_flamethrowerspe_api.h"
#include "main/dll/dll_00C8_depthoffieldpoint_api.h"
#include "main/dll/dll_00E3_fireball_api.h"
#include "main/audio/sfx_trigger_ids.h"
#define COLLECTIBLE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define COLLECTIBLE_OBJGROUP 4
extern u8 framesThisStep;
extern f32 timeDelta;
extern void saveGame_unsaveObjectPos(int* obj);
extern f32 gCollectibleDespawnTimerDuration;
extern f32 lbl_803E3454;
extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 gCollectibleBounceDamping;
extern f32 gCollectibleAirFriction;
extern f32 gCollectibleGravity;
extern f32 lbl_803E3458;
extern f32 gCollectibleLaunchSpeed;
extern f32 gCollectibleLaunchAngle;
extern f32 lbl_803E348C;
extern int Obj_IsParentSlackClear(u8 * player);
extern f32 gCollectiblePickupRange;
extern f32 gCollectibleSpinDamping;
extern f32 gCollectibleSpinRate;
extern f32 gCollectibleRotRate;

extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 gCollectibleDefaultScale;
extern f32 gCollectibleLifetimeTimer;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;
































/* ObjMsg slots: collectible notifies the player it is in range, player
   replies to trigger the pickup. */
#define COLLECTIBLE_MSG_IN_RANGE 0x7000a
#define COLLECTIBLE_MSG_PICKUP 0x7000b

/* scatter/launch burst spawned 10x on anim-event cmd 3 (after the cmd-1 launch impulse) */
#define COLLECTIBLE_PARTFX_SCATTER 0x7ef
/* idle sparkle spawned randomly for the 0x27f seqId variant in collectible_updateIdleMotion */
#define COLLECTIBLE_PARTFX_IDLE 0x423

u32 lbl_80320700[] = {
    0xFFFFFFFF,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

u32 lbl_80320768[] = {
    0x00000000,
    0x3FD5A1CB,
    0xC0253F7D,
    0x3C23D70A,
    0x06100000,
    0x402F3B64,
    0x3F4B020C,
    0xBFFA1CAC,
    0x3C23D70A,
    0x09200000,
    0x402EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0x4032E148,
    0xBF795810,
    0xBFF8F5C3,
    0x3C23D70A,
    0x09200000,
    0x4033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0xC02F3B64,
    0x3F4B020C,
    0xBFFC28F6,
    0x3C23D70A,
    0x09200000,
    0xC02EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0xC032E148,
    0xBF795810,
    0xBFFC49BA,
    0x3C23D70A,
    0x09200000,
    0xC033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0x00000000,
    0x3ECF5C29,
    0x403CED91,
    0x3C23D70A,
    0x08400000,
};

u32 lbl_80320978[] = {
    0xFF202020,
    0xFF202020,
    0xFF000000,
};

u32 lbl_803209C0[] = {
    0x0000004F,
    0xFFC40000,
    0x0000001F,
    0x0000004F,
    0x00C4FF00,
    0x00000005,
    0x0000004F,
    0x00C4FF00,
    0x0000001E,
};

f32 lbl_80320A28[] = {
    0.5f,
    0.55f,
    0.65f,
    0.7f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.3f,
    0.3f,
    0.3f,
    0.3f,
};

u32 jumptable_80320AA0[] = {
    (u32)((char*)staffFn_80170380 + 0x10C),
    (u32)((char*)staffFn_80170380 + 0x184),
    (u32)((char*)staffFn_80170380 + 0x35C),
    (u32)((char*)staffFn_80170380 + 0x3D0),
    (u32)((char*)staffFn_80170380 + 0x584),
    (u32)((char*)staffFn_80170380 + 0x550),
    (u32)((char*)staffFn_80170380 + 0x65C),
    (u32)((char*)staffFn_80170380 + 0x84),
};

u8 collectible_getVisibilityBitClear(int* obj) { return ((CollectibleState*)((GameObject*)obj)->extra)->visibilityBitClear; }

int collectible_getIsHidden(int* obj) { return ((GameObject*)obj)->unkF4; }

void collectible_setVisibilityBitClear(int* obj, u32 v)
{
    ((CollectibleState*)((GameObject*)obj)->extra)->visibilityBitClear = v;
}

void collectible_startBounceMotion(int* obj, f32 f1, f32 f2, f32 f3)
{
    s32 v = 0x8;
    ((CollectibleState*)((GameObject*)obj)->extra)->bounceTimer = v;
    ((GameObject*)obj)->anim.velocityX = f1;
    ((GameObject*)obj)->anim.velocityY = f2;
    ((GameObject*)obj)->anim.velocityZ = f3;
}

void collectible_setPosition(int* obj, f32 f1, f32 f2, f32 f3)
{
    char* inner = (char*)((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.localPosX = f1;
    ((CollectibleState*)inner)->basePosX = f1;
    ((GameObject*)obj)->anim.localPosY = f2;
    ((CollectibleState*)inner)->basePosY = f2;
    ((GameObject*)obj)->anim.localPosZ = f3;
    ((CollectibleState*)inner)->basePosZ = f3;
    if (mainGetBit(((CollectibleState*)inner)->hideGameBit) == 0)
    {
        saveGame_saveObjectPos((GameObject*)obj);
    }
}

void collectible_setDisabled(int* obj, int flag)
{
    char* inner = (char*)((GameObject*)obj)->extra;
    ((CollectibleState*)inner)->disabled = flag;
    if (flag != 0)
    {
        ObjHits_DisableObject((u32)obj);
    }
    else
    {
        if (mainGetBit(((CollectibleState*)inner)->hideGameBit) == 0)
        {
            ObjHits_EnableObject((u32)obj);
        }
    }
}

int collectible_getHitRegionId(int* obj)
{
    int* inner = (int*)*(int*)&((GameObject*)obj)->extra;
    if (((CollectibleState*)inner)->hitRegionId == -2)
    {
        f32 f1 = ((GameObject*)obj)->anim.worldPosX;
        f32 f2 = ((GameObject*)obj)->anim.worldPosY;
        f32 f3 = ((GameObject*)obj)->anim.worldPosZ;
        *(u32*)&((CollectibleState*)inner)->hitRegionId = (u16)ObjHitRegion_FindContainingId(f1, f2, f3);
    }
    return ((CollectibleState*)inner)->hitRegionId;
}

GenPropsWGPipe GXWGFifo : (0xCC008000);

#pragma opt_common_subs off

void collectible_applyPickup(int* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfx);
    u8* state = ((GameObject*)obj)->extra;
    u8* params = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* setup2 = ((GameObject*)obj)->anim.modelInstance->extraSetupData;
    Obj_GetPlayerObject();
    getTrickyObject();
    Obj_GetPlayerObject();
    getTrickyObject();
    ObjHits_DisableObject((u32)obj);
    if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
    {
        ((CollectibleState*)state)->despawnTimer = gCollectibleDespawnTimerDuration;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (((CollectibleState*)state)->hideGameBit != -1)
    {
        mainSetBits(((CollectibleState*)state)->hideGameBit, 1);
        saveGame_unsaveObjectPos(obj);
    }
    if (((CollectibleSetup*)params)->collectGameBit != -1)
    {
        mainSetBits(((CollectibleSetup*)params)->collectGameBit, 1);
    }
    if (((CollectibleSetup*)params)->counterGameBit > 0)
    {
        gameBitIncrement(((CollectibleSetup*)params)->counterGameBit);
    }
    switch (*(s16*)(setup2 + 2))
    {
    case 1:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 90:
            Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 2, 40);
            break;
        case 793:
            Sfx_PlayFromObject(obj, SFXTRIG_bapt11_c);
            mainSetBits(GAMEBIT_ITEM_NWFood_Got, 1);
            ((CollectibleState*)state)->hideFrames = 1200;
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 255, 40);
            break;
        case 1702:
            {
                s8 c = mainGetBit(GAMEBIT_ITEM_MoonSeed_Count);
                if (c < 7)
                {
                    c = c + 1;
                }
                mainSetBits(GAMEBIT_ITEM_MoonSeed_Count, c);
                itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 6, 40);
                Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                break;
            }
        case 34:
            Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 255, 40);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_cam90_c);
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    case 4:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case COLLECTIBLE_ITEM_ENERGY_EGG:
            Sfx_PlayFromObject((int*)Obj_GetPlayerObject(), SFXTRIG_lockoff22);
            playerAddHealth(Obj_GetPlayerObject(), 4);
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 3, 40);
            break;
        case COLLECTIBLE_ITEM_APPLE:
            playerAddHealth(Obj_GetPlayerObject(), 2);
            Sfx_PlayFromObject((int*)Obj_GetPlayerObject(), SFXTRIG_lockoff22);
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 1, 40);
            break;
        default:
            Sfx_PlayFromObject((int*)Obj_GetPlayerObject(), SFXTRIG_cam90_c);
            itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, SFXTRIG_cam90_c);
        itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 255, 40);
        break;
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    ((GameObject*)obj)->unkF4 = 1;
}

void collectible_updateLooseMotion(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 1702)
    {
        objMove((GameObject*)obj, lbl_803E345C, ((GameObject*)obj)->anim.velocityY * (f32)(u32)framesThisStep, lbl_803E345C);
    }
    else
    {
        int n = framesThisStep;
        objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityY * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityZ * (f32)(u32)n);
    }
    (*gPathControlInterface)->update(obj, state + 0x50, timeDelta);
    (*gPathControlInterface)->apply(obj, state + 0x50);
    (*gPathControlInterface)->advance(obj, state + 0x50, timeDelta);
    if (*(s8*)&((CollectibleState*)state)->bounceHitFlag != 0)
    {
        f32 nx = -((GameObject*)obj)->anim.velocityX;
        f32 ny = -((GameObject*)obj)->anim.velocityY;
        f32 nz = -((GameObject*)obj)->anim.velocityZ;
        f32 len = sqrtf(nx * nx + ny * ny + nz * nz);
        if (lbl_803E345C != len)
        {
            f32 inv = lbl_803E3454 / len;
            nx = nx * inv;
            ny = ny * inv;
            nz = nz * inv;
        }
        {
            f32 px = *(f32*)(state + 0xb8);
            f32 py = *(f32*)(state + 0xbc);
            f32 pz = *(f32*)(state + 0xc0);
            f32 d = lbl_803E3460 * (nx * px + ny * py + nz * pz);
            ((GameObject*)obj)->anim.velocityX = px * d;
            ((GameObject*)obj)->anim.velocityY = py * d;
            ((GameObject*)obj)->anim.velocityZ = pz * d;
        }
        ((GameObject*)obj)->anim.velocityX -= nx;
        ((GameObject*)obj)->anim.velocityY -= ny;
        ((GameObject*)obj)->anim.velocityZ -= nz;
        ((GameObject*)obj)->anim.velocityY *= len;
        ((GameObject*)obj)->anim.velocityY *= gCollectibleBounceDamping;
        ((GameObject*)obj)->anim.velocityX *= len;
        ((GameObject*)obj)->anim.velocityZ *= len;
        ((CollectibleState*)state)->bounceTimer -= 1;
        if (((CollectibleState*)state)->bounceTimer == 0)
        {
            f32 z;
            ((CollectibleState*)state)->bounceTimer = 0;
            z = lbl_803E345C;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityZ = z;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * gCollectibleAirFriction;
        ((GameObject*)obj)->anim.velocityY = -(gCollectibleGravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
}

#pragma opt_common_subs reset

void collectible_free(GameObject *obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject((int)obj, COLLECTIBLE_OBJGROUP);
    return;
}

int collectible_getExtraSize(void)
{
    return 0x2b8;
}

int collectible_getObjectTypeId(void)
{
    return 0x13;
}

void collectible_hitDetect(void)
{
}

int collectible_SeqFn(GameObject *obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* state = (obj)->extra;
    f32 buf[6];
    int j;
    int i;
    f32 s_val;
    f32 c_val;
    f32 vy;

    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->visibilityBitClear = (u8)(mainGetBit((s32)((CollectibleState*)state)->visibilityGameBit) == 0);
    }
    if (((CollectibleState*)state)->visibilityBitClear == 0)
    {
        switch ((obj)->anim.seqId)
        {
        case 0x6a6:
            objfx_spawnDirectionalBurstLegacy((int)obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
            break;
        }
    }

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            s_val = gCollectibleLaunchSpeed * mathCosf(gCollectibleLaunchAngle);
            c_val = gCollectibleLaunchSpeed * mathSinf(gCollectibleLaunchAngle);
            ((CollectibleState*)(obj)->extra)->bounceTimer = 8;
            (obj)->anim.velocityX = c_val;
            (obj)->anim.velocityY = (vy = lbl_803E3460);
            (obj)->anim.velocityZ = s_val;
            ((CollectibleState*)(obj)->extra)->bounceTimer = 8;
            (obj)->anim.velocityX = lbl_803E348C;
            (obj)->anim.velocityY = vy;
            (obj)->anim.velocityZ = lbl_803E345C;
        }
        else if (cmd == 2)
        {
            ((CollectibleState*)state)->delayedMsgTimer = 1;
        }
        else if (cmd == 3)
        {
            f32 z;
            j = 0;
            z = lbl_803E345C;
            for (; j < 10; j++)
            {
                buf[3] = z;
                buf[4] = z;
                buf[5] = z;
                (*gPartfxInterface)->spawnObject((void*)obj, COLLECTIBLE_PARTFX_SCATTER, buf, 1,
                                                 -1, NULL);
            }
        }
    }
    return 0;
}

void collectible_checkProximityPickup(GameObject *obj, u8* state)
{
    extern void collectible_applyPickup(int obj);
    GameObject* player;
    s16* attach;
    u8* focus;
    f32 dist;
    f32 dy;

    attach = (obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    if ((state[0x37] & 1) != 0)
    {
        return;
    }
    focus = (u8*)playerGetFocusObject((GameObject*)player);
    if (focus == NULL)
    {
        focus = (u8*)player;
    }
    dist = Vec_xzDistance(&(obj)->anim.worldPosX, &((GameObject*)focus)->anim.worldPosX);
    dy = ((GameObject*)focus)->anim.worldPosY - (obj)->anim.worldPosY;
    if (dy < lbl_803E345C)
    {
        dy = -dy;
    }
    if (dy < gCollectiblePickupRange && dist < ((CollectibleState*)state)->scale &&
        Obj_IsParentSlackClear((u8*)player) != 0)
    {
        ((CollectibleState*)state)->pickupMsgValue = -1;
        switch ((obj)->anim.seqId)
        {
        case COLLECTIBLE_ITEM_ENERGY_EGG:
            if (mainGetBit(GAMEBIT_SawBigHealth) == 0)
            {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj, (u32)(state + 0x48));
                mainSetBits(GAMEBIT_SawBigHealth, 1);
            }
            else
            {
                collectible_applyPickup((int)obj);
            }
            state[0x37] |= 1;
            break;
        case 0x319:
            collectible_applyPickup((int)obj);
            state[0x37] |= 1;
            break;
        case 0x49:
        case 0x2da:
        case COLLECTIBLE_ITEM_APPLE:
            if (mainGetBit(GAMEBIT_SawApple) == 0)
            {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj, (u32)(state + 0x48));
                mainSetBits(GAMEBIT_SawApple, 1);
            }
            else
            {
                collectible_applyPickup((int)obj);
            }
            state[0x37] |= 1;
            break;
        case 0x6a6:
            if (mainGetBit(GAMEBIT_CollectedFlag09A8) == 0)
            {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj, (u32)(state + 0x48));
                mainSetBits(GAMEBIT_CollectedFlag09A8, 1);
            }
            else
            {
                collectible_applyPickup((int)obj);
            }
            state[0x37] |= 1;
            break;
        default:
            if (ObjTrigger_IsSet((int)obj) != 0)
            {
                mainSetBits(GAMEBIT_EnableCMenu, 1);
                ((CollectibleState*)state)->pickupMsgValue = attach[0xf];
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj, (u32)(state + 0x48));
                state[0x37] |= 1;
                if ((obj)->anim.modelState != NULL)
                {
                    (obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
            }
            break;
        }
    }
    *(f32*)state = dist;
}

void collectible_update(int obj)
{
    extern void collectible_updateLooseMotion(int obj);
    extern void Obj_FreeObject(int obj);
    extern void collectible_applyPickup(int obj);
    u8* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    int msgParam;
    int msg;
    int hideFrames;
    f32 timer;
    f32 zero;

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    timer = ((CollectibleState*)state)->despawnTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((CollectibleState*)state)->despawnTimer = timer - timeDelta;
        if (((CollectibleState*)state)->despawnTimer <= zero)
        {
            ((CollectibleState*)state)->despawnTimer = zero;
            ObjHits_DisableObject((u32)obj);
            if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
            {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->visibilityBitClear = (u8)(mainGetBit((s32)((CollectibleState*)state)->visibilityGameBit) == 0);
    }
    if (((CollectibleState*)state)->visibilityBitClear != 0 || state[0xf] != 0)
    {
        return;
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x6a6:
        objfx_spawnDirectionalBurstLegacy(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
        break;
    }
    timer = ((CollectibleState*)state)->lifetimeTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((CollectibleState*)state)->lifetimeTimer = timer - timeDelta;
        if (((CollectibleState*)state)->lifetimeTimer <= zero)
        {
            if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
            {
                ((CollectibleState*)state)->despawnTimer = gCollectibleDespawnTimerDuration;
                if (((GameObject*)obj)->anim.modelState != NULL)
                {
                    ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
                itemPickupDoParticleFxLegacy(obj, lbl_803E3454, 255, 40);
            }
            ((CollectibleState*)state)->lifetimeTimer = lbl_803E345C;
            return;
        }
    }
    while (ObjMsg_Pop((void*)obj, (u32*)&msg, (u32*)&msgParam, NULL) != 0)
    {
        switch (msg)
        {
        case COLLECTIBLE_MSG_PICKUP:
            collectible_applyPickup(obj);
            break;
        }
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x319:
        hideFrames = ((CollectibleState*)state)->hideFrames;
        if (hideFrames != 0)
        {
            ((CollectibleState*)state)->hideFrames -= framesThisStep;
            if (((CollectibleState*)state)->hideFrames <= 0)
            {
                ((CollectibleState*)state)->hideFrames = 0;
                state[0x37] &= ~1;
                ((GameObject*)obj)->anim.alpha = 255;
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
        break;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags |= OBJHITS_PRIORITY_STATE_HIT_EXCLUDED;
        }
        ObjHits_DisableObject((u32)obj);
        if (((CollectibleState*)state)->hideGameBit != -1 && mainGetBit((s32)((CollectibleState*)state)->hideGameBit) == 0)
        {
            ((GameObject*)obj)->unkF4 = 0;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        collectible_updateIdleMotion((GameObject*)(obj));
        if (((CollectibleState*)state)->bounceTimer != 0)
        {
            collectible_updateLooseMotion(obj);
        }
        if (state[0x3e] != 0)
        {
            state[0x3e]--;
            if (state[0x3e] == 0)
            {
                ((CollectibleState*)state)->pickupMsgValue = -1;
                ObjMsg_SendToObject(Obj_GetPlayerObject(), COLLECTIBLE_MSG_IN_RANGE, (void*)obj,
                                    (u32)(state + 0x48));
            }
        }
        else
        {
            collectible_checkProximityPickup((GameObject*)(obj), state);
        }
    }
}

void collectible_render(GameObject *obj, int a, int b, int c, int d, s8 visible)
{
    int state = *(int*)&(obj)->extra;
    if (visible != 0 && ((CollectibleState*)state)->despawnTimer == lbl_803E345C && (obj)->unkF4 == 0
        && ((obj)->anim.seqId == 0x156 || ((CollectibleState*)state)->visibilityBitClear == 0))
    {
        if ((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0 && ((CollectibleState*)state)->useColor != 0)
        {
            fn_8003B608(((CollectibleState*)state)->colorR, ((CollectibleState*)state)->colorG, ((CollectibleState*)state)->colorB);
        }
        objRenderModelAndHitVolumes((int)obj, a, b, c, d, lbl_803E3454);
        if ((obj)->anim.seqId == 0xa8)
        {
            objfx_spawnDirectionalBurstLegacy((int)obj, 7, lbl_803E3454, 5, 1, 10, lbl_803E348C, 0, 0x20000000);
        }
    }
}

void collectible_updateIdleMotion(GameObject *obj)
{
    u8* state = (obj)->extra;

    switch ((obj)->anim.seqId)
    {
    case COLLECTIBLE_ITEM_ENERGY_EGG:
        if ((((CollectibleState*)state)->spinTimer -= framesThisStep) <= 0)
        {
            ((CollectibleState*)state)->spinSpeed = (f32)(int)
            randomGetRange(600, 800);
            ((CollectibleState*)state)->spinTimer = randomGetRange(180, 240);
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_169);
        }
        (obj)->anim.rotY = ((CollectibleState*)state)->spinSpeed;
        ((CollectibleState*)state)->spinSpeed *= gCollectibleSpinDamping;
        if ((obj)->anim.rotY < 10 && (obj)->anim.rotY > -10)
        {
            (obj)->anim.rotY = 0;
        }
        break;
    case 0x12d:
    case 0x135:
    case 0x137:
    case 0x156:
    case 0x246:
        (obj)->anim.rotX = gCollectibleSpinRate * timeDelta + (f32)(obj)->anim.rotX;
        break;
    case 0x22:
        (obj)->anim.rotX = gCollectibleSpinRate * timeDelta + (f32)(obj)->anim.rotX;
        itemPickupDoParticleFxLegacy((int)obj, lbl_803E3454, 10, 1);
        break;
    case 0x27f:
        if (*(f32*)state < gCollectibleSpinRate)
        {
            if ((int)randomGetRange(0, 10) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, COLLECTIBLE_PARTFX_IDLE, NULL, 2,
                                                 -1, NULL);
            }
            (obj)->anim.rotX += (s16)(gCollectibleRotRate * timeDelta);
        }
        break;
    case 0x5e8:
        (obj)->anim.rotX = gCollectibleSpinRate * timeDelta + (f32)(obj)->anim.rotX;
        itemPickupDoParticleFxLegacy((int)obj, lbl_803E3454, 9, 1);
        break;
    }
}

void collectible_init(GameObject *obj, int setup)
{
    ObjAnimComponent* objAnim;
    u8* state;
    int setupObj;
    int setupModelIndex;
    u8* data;
    u32 pathWord;
    u8 pathByte;

    objAnim = (ObjAnimComponent*)obj;
    state = (obj)->extra;
    pathWord = lbl_803E3440;
    pathByte = lbl_803E3444;
    ObjGroup_AddObject((int)obj, COLLECTIBLE_OBJGROUP);
    ObjMsg_AllocQueue(obj, 2);
    (obj)->anim.rotX = (s16)((u8)((CollectibleSetup*)setup)->rotXByte << 8);
    (obj)->anim.rotY = (s16)((u8)((CollectibleSetup*)setup)->rotYByte << 8);
    (obj)->anim.rotZ = (s16)((u8)((CollectibleSetup*)setup)->rotZByte << 8);
    setupObj = (int)objAnim->modelInstance;
    (obj)->anim.rootMotionScale = *(f32*)(setupObj + 4);
    (obj)->animEventCallback = collectible_SeqFn;
    setupModelIndex = ((CollectibleSetup*)setup)->modelIndex;
    objAnim->bankIndex = setupModelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    (obj)->objectFlags = (obj)->objectFlags | COLLECTIBLE_OBJFLAG_HITDETECT_DISABLED;
    ((CollectibleState*)state)->unkC = ((CollectibleSetup*)setup)->unkC;
    ((CollectibleState*)state)->unkD = ((CollectibleSetup*)setup)->unkD;
    ((CollectibleState*)state)->disabled = 0;
    ((CollectibleState*)state)->hitRegionId = -2;
    ((CollectibleState*)state)->bounceTimer = 0;
    ((CollectibleState*)state)->visibilityGameBit = ((CollectibleSetup*)setup)->visibilityGameBit;
    ((CollectibleState*)state)->mapId = ((ObjPlacement*)setup)->mapId;
    ((CollectibleState*)state)->basePosX = (obj)->anim.localPosX;
    ((CollectibleState*)state)->basePosY = (obj)->anim.localPosY;
    ((CollectibleState*)state)->basePosZ = (obj)->anim.localPosZ;
    ((CollectibleState*)state)->useColor = ((CollectibleSetup*)setup)->useColor;
    ((CollectibleState*)state)->delayedMsgTimer = 0;
    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->visibilityBitClear = (u8)(
            (u32)__cntlzw(mainGetBit(((CollectibleState*)state)->visibilityGameBit)) >> 5);
    }
    ((CollectibleState*)state)->hideGameBit = ((CollectibleSetup*)setup)->hideGameBit;
    if (((CollectibleState*)state)->hideGameBit != -1)
    {
        *(u32*)&(obj)->unkF4 = mainGetBit(((CollectibleState*)state)->hideGameBit);
    }
    else
    {
        *(u32*)&(obj)->unkF4 = 0;
    }
    if ((obj)->unkF4 == 0)
    {
        data = (obj)->anim.modelInstance->extraSetupData;
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32) * (s8*)(data + 8);
        }
        else
        {
            ((CollectibleState*)state)->scale = gCollectibleDefaultScale;
        }
        data = (u8*)(obj)->anim.modelInstance->hitVolumes;
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32)(s32)(((ObjDefHitVolume*)data)->bounds[0] << 2);
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0) &&
            (((CollectibleState*)state)->useColor != 0))
        {
            ((CollectibleState*)state)->colorR = ((CollectibleSetup*)setup)->colorR;
            ((CollectibleState*)state)->colorG = ((CollectibleSetup*)setup)->colorG;
            ((CollectibleState*)state)->colorB = ((CollectibleSetup*)setup)->colorB;
        }
        switch ((obj)->anim.seqId)
        {
        case COLLECTIBLE_ITEM_ENERGY_EGG:
            ((CollectibleState*)state)->unk40 = lbl_803E345C;
            ((CollectibleState*)state)->lifetimeTimer = gCollectibleLifetimeTimer;
            break;
        case COLLECTIBLE_ITEM_APPLE:
            ((CollectibleState*)state)->unk40 = lbl_803E349C;
            ((CollectibleState*)state)->lifetimeTimer = gCollectibleLifetimeTimer;
            break;
        default:
            ((CollectibleState*)state)->unk40 = lbl_803E34A0;
            break;
        }
        (*gPathControlInterface)->init(state + 0x50, 0, 0x40006, 1);
        (*gPathControlInterface)->setup(state + 0x50, 1, lbl_80320C58, &pathWord, &pathByte);
        (*gPathControlInterface)->attachObject((void*)obj, state + 0x50);
    }
}

void collectible_release(void)
{
}

void collectible_initialise(void)
{
}
