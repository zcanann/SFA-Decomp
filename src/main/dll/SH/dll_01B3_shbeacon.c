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
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/gameloop.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define SHBEACON_OBJFLAG_HIDDEN 0x4000
#define SHBEACON_OBJFLAG_RENDERED 0x800
#define SHBEACON_OBJFLAG_FREED 0x40

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


extern f32 timeDelta;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern void Obj_FreeObject(int obj);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int loadObjectAtObject(int obj, int* setup);


extern f32 lbl_803DDBF8;

int sh_beacon_SeqFn(int obj)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer + timeDelta;
    if (((ShBeaconState*)extra)->seqTimer >= 20.0f)
    {
        ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer - 20.0f;
        if ((((GameObject*)obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
        {
            fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
        }
    }
    return 0;
}

int fn_801DA9CC(int obj)
{
    ((ShBeaconState*)*(int*)&((GameObject*)obj)->extra)->fadeTimer = 6.0f;
    return 1;
}

int sh_beacon_getExtraSize(void) { return 0x18; }

void sh_beacon_free(int obj, int keepChild)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (keepChild == 0)
    {
        void* p = *(void**)&((ShBeaconState*)extra)->childObj;
        if (p != NULL && (((GameObject*)p)->objectFlags & SHBEACON_OBJFLAG_FREED) == 0)
        {
            Obj_FreeObject((int)p);
        }
    }
}

void sh_beacon_update(int obj)
{
    u8* state;
    int def;
    int tmp;
    int* setup;
    int mode;
    int state2;

    state = ((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (((ShBeaconState*)state)->mode)
    {
    case SH_BEACON_MODE_UNLIT:
        if (((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) &&
            ((*gGameUIInterface)->isEventReady(0x194) != 0))
        {
            gameBitDecrement(0x194);
            GameBit_Set(((ShBeaconPlacement*)def)->igniteGameBit, 1);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x20, 0x55);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                ((ObjPlacement*)setup)->color[0] = 2;
                ((ObjPlacement*)setup)->color[1] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
                ((ObjPlacement*)setup)->color[3] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
                ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
            }
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((ShBeaconState*)state)->mode = SH_BEACON_MODE_IGNITING;
        }
    case SH_BEACON_MODE_IGNITING:
        state2 = *(int*)&((GameObject*)obj)->extra;
        ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer + timeDelta;
        if (((ShBeaconState*)state2)->seqTimer >= 20.0f)
        {
            ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer - 20.0f;
            if ((((GameObject*)obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
            {
                fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
            }
        }
        break;
    case SH_BEACON_MODE_LIT:
        if ((((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping) == 0)
        {
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            ((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping = 1;
        }
        if ((((GameObject*)obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
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
                fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 2, mode, 0, 0);
            }
        }
        break;
    }
    if (((ShBeaconState*)state)->mode != SH_BEACON_MODE_LIT)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (((ShBeaconState*)state)->mode == SH_BEACON_MODE_IGNITING)
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 8);
        }
        else if ((((ShBeaconState*)state)->mode == SH_BEACON_MODE_UNLIT) && (GameBit_Get(0x194) == 0))
        {
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        tmp = (int)getTrickyObject();
        if (((void*)tmp != NULL) && ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0))
        {
            (*(VtableFn*)(*(int*)(*(int*)(tmp + 0x68)) + 0x28))(tmp, obj, 1, 4);
        }
    }
    else
    {
        if ((GameBit_Get(0x193) != 0) || (((ShBeaconPlacement*)def)->litGameBit != 0x95))
        {
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        else
        {
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if (((ShBeaconState*)state)->fadeTimer > 0.0f)
    {
        ((ShBeaconState*)state)->fadeTimer = ((ShBeaconState*)state)->fadeTimer - timeDelta;
        if ((((GameObject*)obj)->objectFlags & SHBEACON_OBJFLAG_RENDERED) != 0)
        {
            fn_80098B18(obj, 0.6f * ((GameObject*)obj)->anim.rootMotionScale, 3, 0, 0, 0);
        }
        if ((((ShBeaconState*)state)->fadeTimer <= 0.0f) && (((ShBeaconState*)state)->mode == SH_BEACON_MODE_IGNITING))
        {
            ((ShBeaconState*)state)->mode = SH_BEACON_MODE_LIT;
            GameBit_Set(((ShBeaconPlacement*)def)->litGameBit, 1);
            if ((GameBit_Get(0x190) != 0) && (GameBit_Get(0x191) != 0) && (GameBit_Get(0x192) != 0))
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

void sh_beacon_init(int obj, int defData)
{
    int state;
    int* setup;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)(defData + 0x18) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | SHBEACON_OBJFLAG_HIDDEN);

    ((ShBeaconState*)state)->mode = GameBit_Get(((ShBeaconPlacement*)defData)->litGameBit);
    if (((ShBeaconState*)state)->mode == SH_BEACON_MODE_UNLIT)
    {
        if (GameBit_Get(((ShBeaconPlacement*)defData)->igniteGameBit) != 0)
        {
            ((ShBeaconState*)state)->mode = SH_BEACON_MODE_IGNITING;
        }
    }

    if (((ShBeaconState*)state)->mode != SH_BEACON_MODE_UNLIT && Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x20, 0x55);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 2;
        ((ObjPlacement*)setup)->color[1] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
        ((ObjPlacement*)setup)->color[3] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
        ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
    }

    ((GameObject*)obj)->animEventCallback = sh_beacon_SeqFn;
}
