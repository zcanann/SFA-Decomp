/* === moved from main/dll/IM/IMsnowbike.c [801D9B1C-801D9BDC) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"





/*
 * --INFO--
 *
 * Function: sh_levelcontrol_update
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 2452b
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */




/* 8b "li r3, N; blr" returners. */
int sh_staff_getExtraSize(void);






/* render-with-objRenderFn_8003b8f4 pattern. */

void sh_staff_free(int* obj, int p2);

#include "main/dll/DR/DRearthwalk.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objseq.h"

#include "main/dll/DR/shstaff_state.h"

typedef struct ShStaffPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 pad6[0x7 - 0x6];
    u8 unk7;
    u8 pad8[0x18 - 0x8];
    u8 unk18;
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} ShStaffPlacement;


typedef struct ShBeaconPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} ShBeaconPlacement;


/* sh_beacon_getExtraSize == 0x18. */
typedef struct ShBeaconState
{
    int childObj; /* 0x00: spawned 0x55 flame object */
    f32 seqTimer; /* 0x04 */
    f32 fadeTimer; /* 0x08 */
    f32 burstTimer; /* 0x0c */
    f32 modeTimer; /* 0x10 */
    u8 mode; /* 0x14: 0 unlit, 1 lit, 2 igniting */
    u8 flags15; /* 0x15: bit 7 = looping sfx active (BeaconFlags) */
    u8 pad16[2];
} ShBeaconState;

STATIC_ASSERT(sizeof(ShBeaconState) == 0x18);


extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointLocalMtx();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();


/*
 * --INFO--
 *
 * Function: sh_staff_render
 * EN v1.0 Address: 0x801D9BDC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801DA010
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void* Obj_GetPlayerObject(void);
extern void Obj_BuildWorldTransformMatrix(int obj, f32* mtx, int p3);
extern void PSMTXInverse(int src, f32* dst);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * dst);
extern void objSetMtxFn_800412d4(f32 * mtx);
extern void objRenderModel(int obj);
extern f32 timeDelta;
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;
extern f32 lbl_803E54D8;
extern f32 lbl_803E54DC;
extern f32 lbl_803E54E0;
extern f32 lbl_803E54E4;
extern f32 lbl_803E54E8;
extern f32 lbl_803E54EC;
extern f32 lbl_803E54F0;
extern f32 lbl_803E54F4;
extern f32 lbl_803E54F8;

void sh_staff_render(int obj, int p2, int p3, int p4, int p5, s8 visible);


/* 8b "li r3, N; blr" returners. */
int sh_beacon_getExtraSize(void) { return 0x18; }

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern void Obj_FreeObject(int obj);
extern void ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d,
                                                      int e, void* f);
extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;
extern f32 lbl_803E5528;
extern f32 lbl_803E552C;

/* 96b: render via objRenderFn + fn_80098B18 with 3-float local. */
void sh_staffhaze_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5);

/* 48b: free if 0x4000 flag set. */
void sh_staffhaze_update(int obj);

/* 120b: tick a float timer; on wrap optionally trigger an effect. */
int sh_beacon_SeqFn(int obj)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer + timeDelta;
    if (((ShBeaconState*)extra)->seqTimer >= lbl_803E5528)
    {
        ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer - lbl_803E5528;
        if ((*(unsigned short*)(obj + 0xb0) & 0x800) != 0)
        {
            fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
        }
    }
    return 0;
}

/* 20b: reset extra->field_0x8 = lbl_803E552C, return 1. */
int fn_801DA9CC(int obj)
{
    ((ShBeaconState*)*(int*)&((GameObject*)obj)->extra)->fadeTimer = lbl_803E552C;
    return 1;
}

/* 112b: vtable cleanup then maybe Obj_FreeObject. */
void sh_beacon_free(int obj, int param_2)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (param_2 == 0)
    {
        void* p = *(void**)&((ShBeaconState*)extra)->childObj;
        if (p != NULL && (*(unsigned short*)((char*)p + 0xb0) & 0x40) == 0)
        {
            Obj_FreeObject((int)p);
        }
    }
}

/* 56b: single-call hit-effect poll. */
void sh_emptytumblew_update(int obj);

/* TODO stubs to align function set with v1.0 asm. Bodies are large
 * state-machine and animation logic; filling them is a follow-up task. */
extern u8 Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int a, int b);
extern int loadObjectAtObject(int obj, int* setup);
extern void hudFn_8011f38c(int a);
extern void fn_801DA4A8(int obj, ShStaffState* state, int a);
extern f32 lbl_803E5508;

int sh_staff_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

extern f32 getXZDistance(f32 * a, f32 * b);
extern void* fn_802966CC(int player);
extern int fn_80295CF4(int player, int a);
extern int fn_8029672C(int player, int a);
extern int ObjTrigger_IsSet(int obj);
extern void mapUnload(int idx, int flags);
extern void loadMapAndParent(int mapId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803E550C;
extern f32 lbl_803E5510;
extern f32 lbl_803E5514;

void fn_801DA4A8(int obj, ShStaffState* state, int clearChildren);

void sh_staff_update(int obj);

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
        *(u8*)((char*)setup + 4) = 2;
        *(u8*)((char*)setup + 5) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
        *(u8*)((char*)setup + 7) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
        ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
    }

    ((GameObject*)obj)->animEventCallback = (void*)sh_beacon_SeqFn;
}

extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int GameBit_Set(int eventId, int value);
extern void gameBitDecrement(int eventId);
extern void* getTrickyObject(void);
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern f32 lbl_803E5530;
extern f32 lbl_803E5534;
extern f32 lbl_803E5538;
extern f32 lbl_803E553C;
extern int lbl_803DDBF8;

typedef struct
{
    u8 looping : 1;
    u8 rest : 7;
} BeaconFlags;

/*
 * --INFO--
 *
 * Function: sh_beacon_update
 * EN v1.0 Address: 0x801DAA58
 * EN v1.0 Size: 1080b
 */
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
                *(u8*)((char*)setup + 4) = 2;
                *(u8*)((char*)setup + 5) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
                *(u8*)((char*)setup + 7) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
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
            fn_8002B6D8(obj, 0, 0, 0, 0, 8);
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
