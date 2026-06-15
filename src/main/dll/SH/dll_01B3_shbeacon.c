/* DLL 0x1B3 - SHBeacon [801D9B1C-801D9BDC) */
#include "main/game_object.h"
#include "main/dll/beaconflags_types.h"

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

#include "main/dll/DR/DRearthwalk.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objseq.h"

#include "main/dll/DR/shstaff_state.h"

typedef struct ShBeaconPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} ShBeaconPlacement;

STATIC_ASSERT(sizeof(ShBeaconState) == 0x18);

extern uint GameBit_Get(int eventId);

extern f32 timeDelta;

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E5528;
extern f32 lbl_803E552C;
extern u8 Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int a, int b);
extern int loadObjectAtObject(int obj, int* setup);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int GameBit_Set(int eventId, int value);
extern void gameBitDecrement(int eventId);
extern void* getTrickyObject(void);
extern f32 lbl_803E5530;
extern f32 lbl_803E5534;
extern f32 lbl_803E5538;
extern f32 lbl_803E553C;
extern f32 lbl_803DDBF8;

int sh_beacon_getExtraSize(void) { return 0x18; }

int sh_beacon_SeqFn(int obj)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer + timeDelta;
    if (((ShBeaconState*)extra)->seqTimer >= lbl_803E5528)
    {
        ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer - lbl_803E5528;
        if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
        {
            fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
        }
    }
    return 0;
}

int fn_801DA9CC(int obj)
{
    ((ShBeaconState*)*(int*)&((GameObject*)obj)->extra)->fadeTimer = lbl_803E552C;
    return 1;
}

void sh_beacon_free(int obj, int keepChild)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (keepChild == 0)
    {
        void* p = *(void**)&((ShBeaconState*)extra)->childObj;
        if (p != NULL && (((GameObject*)p)->objectFlags & 0x40) == 0)
        {
            Obj_FreeObject((int)p);
        }
    }
}

void sh_emptytumblew_update(int obj);

/* TODO stubs to align function set with v1.0 asm. Bodies are large
 * state-machine and animation logic; filling them is a follow-up task. */

void sh_beacon_init(int obj, int defData)
{
    int state;
    int* setup;

    state = *(int*)&((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32) * (s8*)(defData + 0x18) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);

    ((ShBeaconState*)state)->mode = (u8)GameBit_Get(*(s16*)(defData + 0x1e));
    if (((ShBeaconState*)state)->mode == 0)
    {
        if (GameBit_Get(*(s16*)(defData + 0x20)) != 0)
        {
            ((ShBeaconState*)state)->mode = 2;
        }
    }

    if (((ShBeaconState*)state)->mode != 0 && Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x20, 0x55);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->unk04[0] = 2;
        ((ObjPlacement*)setup)->unk04[1] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
        ((ObjPlacement*)setup)->unk04[3] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
        ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
    }

    ((GameObject*)obj)->animEventCallback = (void*)sh_beacon_SeqFn;
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
    case 0:
        if (((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0) &&
            ((*gGameUIInterface)->isEventReady(0x194) != 0))
        {
            gameBitDecrement(0x194);
            GameBit_Set(((ShBeaconPlacement*)def)->unk20, 1);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x20, 0x55);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                ((ObjPlacement*)setup)->unk04[0] = 2;
                ((ObjPlacement*)setup)->unk04[1] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
                ((ObjPlacement*)setup)->unk04[3] = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
                ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
            }
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((ShBeaconState*)state)->mode = 2;
        }
    case 2:
        state2 = *(int*)&((GameObject*)obj)->extra;
        ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer + timeDelta;
        if (((ShBeaconState*)state2)->seqTimer >= lbl_803E5528)
        {
            ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer - lbl_803E5528;
            if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
            {
                fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
            }
        }
        break;
    case 1:
        if ((((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping) == 0)
        {
            Sfx_AddLoopedObjectSound(obj, 0x9e);
            ((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping = 1;
        }
        if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
        {
            ((ShBeaconState*)state)->modeTimer = ((ShBeaconState*)state)->modeTimer + timeDelta;
            if (((ShBeaconState*)state)->modeTimer > lbl_803E5530)
            {
                mode = 2;
                ((ShBeaconState*)state)->modeTimer = ((ShBeaconState*)state)->modeTimer - lbl_803E5530;
            }
            else
            {
                mode = 0;
            }
            ((ShBeaconState*)state)->burstTimer = ((ShBeaconState*)state)->burstTimer + timeDelta;
            if (((ShBeaconState*)state)->burstTimer > lbl_803E5534)
            {
                ((ShBeaconState*)state)->burstTimer = ((ShBeaconState*)state)->burstTimer - lbl_803E5534;
                fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 2, mode, 0, 0);
            }
        }
        break;
    }
    if (((ShBeaconState*)state)->mode != 1)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        if (((ShBeaconState*)state)->mode == 2)
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 8);
        }
        else if ((((ShBeaconState*)state)->mode == 0) && (GameBit_Get(0x194) == 0))
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        tmp = (int)getTrickyObject();
        if (((void*)tmp != NULL) && ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0))
        {
            (*(code*)(*(int*)(*(int*)(tmp + 0x68)) + 0x28))(tmp, obj, 1, 4);
        }
    }
    else
    {
        if ((GameBit_Get(0x193) != 0) || (((ShBeaconPlacement*)def)->unk1E != 0x95))
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    if (((ShBeaconState*)state)->fadeTimer > lbl_803E5538)
    {
        ((ShBeaconState*)state)->fadeTimer = ((ShBeaconState*)state)->fadeTimer - timeDelta;
        if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
        {
            fn_80098B18(obj, lbl_803E553C * ((GameObject*)obj)->anim.rootMotionScale, 3, 0, 0, 0);
        }
        if ((((ShBeaconState*)state)->fadeTimer <= lbl_803E5538) && (((ShBeaconState*)state)->mode == 2))
        {
            ((ShBeaconState*)state)->mode = 1;
            GameBit_Set(((ShBeaconPlacement*)def)->unk1E, 1);
            if ((GameBit_Get(0x190) != 0) && (GameBit_Get(0x191) != 0) && (GameBit_Get(0x192) != 0))
            {
                Sfx_PlayFromObject(0, 0x7e);
            }
            else
            {
                Sfx_PlayFromObject(0, 0x409);
            }
        }
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, &lbl_803DDBF8);
}
