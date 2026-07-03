/* DLL 0x0285 - SP shop objects [801E4288-801E42F8) */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/player_objects.h"

extern void objRenderFn_8003b8f4(f32);
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/music_trigger_ids.h"

typedef struct ShopBuyItemState
{
    s8 unk0; /* 0x0 */
    s8 itemIndex; /* 0x1 shop item type: purchase-effect switch + items-table index */
    u8 pad2[0x4 - 0x2];
    u8 unk4;
    u8 pad5[0x56 - 0x5];
    u8 unk56;
    u8 pad57[0x6E - 0x57];
    s16 unk6E;
    u8 pad70[0x90 - 0x70];
    u8 unk90;
    u8 pad91[0x9B0 - 0x91];
    s32 unk9B0;
    u8 pad9B4[0x9D6 - 0x9B4];
    u8 unk9D6;
    u8 pad9D7[0x9D8 - 0x9D7];
} ShopBuyItemState;

/*
 * Per-object extra state for the ShipBattle cloud-ball projectile
 * (SB_CloudBall_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);

/*
 * Per-object extra state for the ShipBattle fireball projectile
 * (SB_FireBall_getExtraSize == SB_FIREBALL_EXTRA_SIZE == 0x18).
 */

STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

/*
 * Per-object extra state for the ShipBattle kyte cage
 * (SB_KyteCage_getExtraSize == 0x8).
 */

STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);

/*
 * Per-object extra state for the ShipBattle chain segment
 * (ShipBattle_getExtraSize == 0x140). The head is handed to
 * gObjectTriggerInterface (+0x1C/+0x24) - interface-owned record;
 * only the locally-evidenced fields are named.
 */

STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);

extern void playerAddMoney(int obj, int amount);
extern void playerAddHealth(int obj, int amount);
extern int gameBitIncrement(int bit);
extern u8 lbl_80327FD0[];

typedef struct ShopItemRow
{
    u8 price; /* 0x0 */
    u8 pad1[0x4 - 0x1];
    u8 field4; /* 0x4 */
    u8 minPrice; /* 0x5 */
    s16 availBit; /* 0x6 "available" GameBit slot (-1 = always available) */
    s16 boughtBit; /* 0x8 "bought" GameBit slot (-1 = none) */
    s16 textId; /* 0xa */
} ShopItemRow;

/* number of ShopItemRow entries in lbl_80327FD0
   (data symbol size 0x2D0 / sizeof(ShopItemRow)(0xc) == 0x3c). */
#define SHOP_ITEM_ROW_COUNT 0x3c
extern void fn_80295CF4(int obj, int a);
extern void skyFn_80088c94(int flags, int mode);
extern void envFxActFn_800887f8(u8 value);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern f32 lbl_803E59C8;
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void Music_Trigger(int id, int arg);

void FUN_801e55c0(u64 unused1, double unused2, double unused3, u64 unused4,
                  u64 unused5, u64 unused6, u64 unused7, u64 unused8,
                  u16* unused9, int unused10)
{
}

void SB_FireBall_release(void);

void shop_hitDetect(void)
{
}

void shop_release(void)
{
}

void shop_initialise(void)
{
}

int SB_CloudBall_getExtraSize(void);
int shop_getExtraSize(void) { return 0x5; }
int shop_getObjectTypeId(void) { return 0x0; }
int fn_801E66DC(void);

s32 shop_getStateField1(int* obj) { return ((ShopBuyItemState*)((GameObject*)obj)->extra)->itemIndex; }
s32 shop_setScale(int* obj) { return ((ShopBuyItemState*)((GameObject*)obj)->extra)->unk0; }

void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E59C8);
}

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */
void Flag_init(int* obj, int* def);

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

void shop_buyItem(int obj, int price)
{

    int player;
    int state;
    int mapEventState;
    u8* items;
    s16 boughtBit;

    player = (int)Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    mapEventState = (int)(*gMapEventInterface)->getCurCharacterState();
    playerAddMoney(player, -price);

    switch (((ShopBuyItemState*)state)->itemIndex)
    {
    case 0:
        playerAddHealth(player, 2);
        break;
    case 0x17:
        *(u8*)(mapEventState + 0xa) = 10;
        break;
    case 1:
        playerAddHealth(player, 8);
        break;
    case 2:
        playerAddHealth(player, 4);
        break;
    case 3:
        playerAddHealth(player, 0x1c);
        break;
    case 4:
        gameBitIncrement(0x66c);
        break;
    case 5:
        gameBitIncrement(0x86a);
        break;
    case 6:
        gameBitIncrement(0xc1);
        break;
    case 7:
        gameBitIncrement(0x13d);
        gameBitIncrement(0x5d6);
        break;
    case 8:
        gameBitIncrement(0x3f5);
        break;
    }

    items = lbl_80327FD0 + 8;
    boughtBit = *(s16*)(items + ((ShopBuyItemState*)state)->itemIndex * 0xc);
    if (boughtBit != -1)
    {
        GameBit_Set(boughtBit, 1);
    }
}

void shop_free(int* obj)
{
    skyFn_80088c94(7, 0);
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(MUSICTRIG_communicator, 0);
    GameBit_Set(3838, 0);
}

void shop_func0B(int* obj, int v, int p3)
{
    s8* state = ((GameObject*)obj)->extra;
    state[0] = v;
    if (v != 0)
    {
        (*gObjectTriggerInterface)->runSequence(p3, obj, -1);
    }
}

/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash v in obj->_b8[4]. */
void shop_func15(int* obj, int v)
{
    s8* b = ((GameObject*)obj)->extra;
    b[2] = 0;
    b[3] = 0;
    b[4] = v;
}

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */
void shop_func16(int* obj, int p2, int p3)
{
    s8* b = ((GameObject*)obj)->extra;
    b[2] = (s8)(b[2] + p3);
    b[3] = (s8)(b[3] + p2);
}

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */
void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4)
{
    s8* b = ((GameObject*)obj)->extra;
    *out_b2 = b[2];
    *out_b3 = b[3];
    *out_b4 = b[4];
}

int shop_getItemPrice(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return ((ShopItemRow*)lbl_80327FD0)[idx].price;
    }
    return 0;
}

s16 shop_getItemTextId(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        ShopItemRow* rows = (ShopItemRow*)lbl_80327FD0;
        return rows[idx].textId;
    }
    return 0;
}

u8 shop_getItemField4(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return lbl_80327FD0[idx * 0xc + 0x4];
    }
    return 0;
}

u8 shop_getItemMinPrice(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return lbl_80327FD0[idx * 0xc + 0x5];
    }
    return 0;
}

void shop_init(int obj, int objDef)
{
    int i;
    u8* item;

    ((ShopBuyItemState*)((GameObject*)obj)->extra)->itemIndex = -1;
    ObjGroup_AddObject(obj, 9);
    for (i = 0; i < SHOP_ITEM_ROW_COUNT; i++)
    {
        item = &lbl_80327FD0[i * 0xc];
        item[5] = item[randomGetRange(0, 2) + 1];
    }
    Music_Trigger(MUSICTRIG_communicator, 1);
    ((GameObject*)obj)->unkF8 = 0;
    GameBit_Set(0xefe, 1);
}

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */
int shop_isItemAvailable(int p, int idx)
{

    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = ((ShopItemRow*)lbl_80327FD0)[idx].availBit;
    if (slot == -1 || GameBit_Get(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
int shop_isItemBought(int p, int idx)
{

    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = ((ShopItemRow*)lbl_80327FD0)[idx].boughtBit;
    if (slot != -1 && GameBit_Get(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

void shop_setStateField1(int* obj, int v)
{
    s8* state = ((GameObject*)obj)->extra;
    state[1] = v;
}

void shop_update(int obj)
{

    int player;

    player = (int)Obj_GetPlayerObject();
    if ((void*)Player_GetStaffObject(player) != NULL && GameBit_Get(0x18b) == 0u)
    {
        fn_80295CF4(player, 0);
    }

    if (((GameObject*)obj)->unkF4 == 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0, 1);
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 5, 1);
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 1);
        GameBit_Set(0x617, 1);
        skyFn_80088c94(7, 1);
        ((GameObject*)obj)->unkF4 = 1;
    }

    if ((u32)GameBit_Get(0xd21) != 0u && ((GameObject*)obj)->unkF8 == 0)
    {
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, 0x1c8, 0);
        getEnvfxAct(obj, obj, 0x1cb, 0);
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }

    if ((u32)GameBit_Get(0xd21) == 0u && ((GameObject*)obj)->unkF8 != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
    }
}
