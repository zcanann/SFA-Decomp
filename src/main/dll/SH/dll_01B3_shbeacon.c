/*
 * shbeacon (DLL 0x1B3) - the SnowHorn beacon / brazier the player lights.
 *
 * mode (ShBeaconState.mode): 0 = unlit, 1 = lit, 2 = igniting. While
 * unlit it waits for the light event (0x194); igniting spawns the flame
 * child object (type 0x55), runs the ignite sequence and ticks the
 * flame/fade effects through fn_80098B18; once lit it loops the fire sfx
 * and sets its progress game bit. The placement carries the lit/ignite
 * game-bit ids.
 */
#include "main/dll/beaconflags_types.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

/* flame child object spawned on ignition, cached in ShBeaconState.childObj */
#define SHBEACON_CHILD_OBJ_FLAME 0x55

#define SHBEACON_OBJFLAG_HIDDEN   0x4000
#define SHBEACON_OBJFLAG_RENDERED 0x800
#define SHBEACON_OBJFLAG_FREED    0x40

typedef struct ShBeaconPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 litGameBit;    /* 0x1E: set once the beacon is fully lit */
    s16 igniteGameBit; /* 0x20: set when ignition is triggered */
    u8 pad22[0x28 - 0x22];
} ShBeaconPlacement;

typedef enum ShBeaconMode
{
    SH_BEACON_MODE_UNLIT = 0,    /* waits for the light event, then ignites */
    SH_BEACON_MODE_LIT = 1,      /* fully lit: loops fire sfx and emits bursts */
    SH_BEACON_MODE_IGNITING = 2, /* ignition sequence and flame/fade effects */
} ShBeaconMode;

STATIC_ASSERT(sizeof(ShBeaconState) == 0x18);


f32 lbl_803DDBF8;

int sh_beacon_SeqFn(GameObject* obj)
{
    int extra = *(int*)&(obj)->extra;
    ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer + timeDelta;
    if (((ShBeaconState*)extra)->seqTimer >= 20.0f)
    {
        ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer - 20.0f;
        if (((obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
        {
            fn_80098B18Legacy((int)obj, (obj)->anim.rootMotionScale, 0, 2, 0, 0);
        }
    }
    return 0;
}

int fn_801DA9CC(GameObject* obj)
{
    ((ShBeaconState*)*(int*)&obj->extra)->fadeTimer = 6.0f;
    return 1;
}

int sh_beacon_getExtraSize(void)
{
    return 0x18;
}

void sh_beacon_free(GameObject* obj, int keepChild)
{
    int extra = *(int*)&obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (keepChild == 0)
    {
        GameObject* p = ((ShBeaconState*)extra)->childObj;
        if (p != NULL && (p->objectFlags & SHBEACON_OBJFLAG_FREED) == 0)
        {
            Obj_FreeObject(p);
        }
    }
}

void sh_beacon_update(GameObject* obj)
{
    u8* state;
    int def;
    int tricky;
    ObjPlacement* setup;
    int mode;
    int state2;

    state = (obj)->extra;
    def = *(int*)&(obj)->anim.placementData;
    switch (((ShBeaconState*)state)->mode)
    {
    case SH_BEACON_MODE_UNLIT:
        if ((((obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) &&
            ((*gGameUIInterface)->isEventReady(0x194) != 0))
        {
            gameBitDecrement(GAMEBIT_ITEM_FireWeed_Count);
            mainSetBits(((ShBeaconPlacement*)def)->igniteGameBit, 1);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x20, SHBEACON_CHILD_OBJ_FLAME);
                setup->posX = (obj)->anim.localPosX;
                setup->posY = (obj)->anim.localPosY;
                setup->posZ = (obj)->anim.localPosZ;
                setup->color[0] = 2;
                setup->color[1] = *(u8*)(*(int*)&(obj)->anim.placementData + 5);
                setup->color[3] = *(u8*)(*(int*)&(obj)->anim.placementData + 7);
                ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, (ObjPlacement*)setup);
            }
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((ShBeaconState*)state)->mode = SH_BEACON_MODE_IGNITING;
        }
    case SH_BEACON_MODE_IGNITING:
        state2 = *(int*)&(obj)->extra;
        ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer + timeDelta;
        if (((ShBeaconState*)state2)->seqTimer >= 20.0f)
        {
            ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer - 20.0f;
            if (((obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
            {
                fn_80098B18Legacy((int)obj, (obj)->anim.rootMotionScale, 0, 2, 0, 0);
            }
        }
        break;
    case SH_BEACON_MODE_LIT:
        if ((((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping) == 0)
        {
            Sfx_AddLoopedObjectSound((int)obj, SFXTRIG_forcecryslp11);
            ((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping = 1;
        }
        if (((obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
        {
            ((ShBeaconState*)state)->modeTimer = ((ShBeaconState*)state)->modeTimer + timeDelta;
            if (((ShBeaconState*)state)->modeTimer > 10.0f)
            {
                mode = 2;
                ((ShBeaconState*)state)->modeTimer = ((ShBeaconState*)state)->modeTimer - 10.0f;
            }
            else
            {
                mode = 0;
            }
            ((ShBeaconState*)state)->burstTimer = ((ShBeaconState*)state)->burstTimer + timeDelta;
            if (((ShBeaconState*)state)->burstTimer > 2.0f)
            {
                ((ShBeaconState*)state)->burstTimer = ((ShBeaconState*)state)->burstTimer - 2.0f;
                fn_80098B18Legacy((int)obj, (obj)->anim.rootMotionScale, 2, mode, 0, 0);
            }
        }
        break;
    }
    if (((ShBeaconState*)state)->mode != SH_BEACON_MODE_LIT)
    {
        (obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (((ShBeaconState*)state)->mode == SH_BEACON_MODE_IGNITING)
        {
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 8);
        }
        else if ((((ShBeaconState*)state)->mode == SH_BEACON_MODE_UNLIT) &&
                 (mainGetBit(GAMEBIT_ITEM_FireWeed_Count) == 0))
        {
            (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            (obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        tricky = (int)getTrickyObject();
        if (((void*)tricky != NULL) && (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0))
        {
            (*(VtableFn*)(*(int*)(*(int*)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 4);
        }
    }
    else
    {
        if ((mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got) != 0) || (((ShBeaconPlacement*)def)->litGameBit != 0x95))
        {
            (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        else
        {
            (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if (((ShBeaconState*)state)->fadeTimer > 0.0f)
    {
        ((ShBeaconState*)state)->fadeTimer = ((ShBeaconState*)state)->fadeTimer - timeDelta;
        if (((obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
        {
            fn_80098B18Legacy((int)obj, 0.6f * (obj)->anim.rootMotionScale, 3, 0, 0, 0);
        }
        if ((((ShBeaconState*)state)->fadeTimer <= 0.0f) && (((ShBeaconState*)state)->mode == SH_BEACON_MODE_IGNITING))
        {
            ((ShBeaconState*)state)->mode = SH_BEACON_MODE_LIT;
            mainSetBits(((ShBeaconPlacement*)def)->litGameBit, 1);
            if ((mainGetBit(GAMEBIT_SH_FireWeed_190) != 0) && (mainGetBit(GAMEBIT_SH_FireWeed_191) != 0) &&
                (mainGetBit(GAMEBIT_SH_FireWeed_192) != 0))
            {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
            }
        }
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, &lbl_803DDBF8);
}

void sh_beacon_init(GameObject* obj, int defData)
{
    int state;
    ObjPlacement* setup;

    state = *(int*)&(obj)->extra;
    (obj)->anim.rotX = (s16)((s32) * (s8*)(defData + 0x18) << 8);
    (obj)->objectFlags = (u16)((obj)->objectFlags | SHBEACON_OBJFLAG_HIDDEN);

    ((ShBeaconState*)state)->mode = mainGetBit(((ShBeaconPlacement*)defData)->litGameBit);
    if (((ShBeaconState*)state)->mode == SH_BEACON_MODE_UNLIT)
    {
        if (mainGetBit(((ShBeaconPlacement*)defData)->igniteGameBit) != 0)
        {
            ((ShBeaconState*)state)->mode = SH_BEACON_MODE_IGNITING;
        }
    }

    if (((ShBeaconState*)state)->mode != SH_BEACON_MODE_UNLIT && Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x20, SHBEACON_CHILD_OBJ_FLAME);
        setup->posX = (obj)->anim.localPosX;
        setup->posY = (obj)->anim.localPosY;
        setup->posZ = (obj)->anim.localPosZ;
        setup->color[0] = 2;
        setup->color[1] = *(u8*)(*(int*)&(obj)->anim.placementData + 5);
        setup->color[3] = *(u8*)(*(int*)&(obj)->anim.placementData + 7);
        ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, (ObjPlacement*)setup);
    }

    (obj)->animEventCallback = sh_beacon_SeqFn;
}
