/*
 * spshop (DLL 0x285) - the shop "stall" manager object for the SnowHorn /
 * ThornTail store. It owns the item table (lbl_80327FD0: SHOP_ITEM_COUNT
 * rows describing each purchasable item) and the interface the shopkeeper,
 * scarab coins and item beams query through object group 9.
 *
 * init() randomizes each item's current price from its price tier, opens
 * the shop (music + GAMEBIT_SHOP_LOADED + sky), and drives the spirit-vision
 * style env fx from gamebit 0xd21. buyItem() applies an item's effect
 * (health / money / inventory gamebits) and marks it bought. The remaining
 * small accessors are the object's interface vtable slots used by the
 * shopkeeper UI (price/text/availability/bought queries, selection state).
 */
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/player_objects.h"

#define SHOP_ITEM_COUNT 0x3c
#define SHOP_OBJGROUP 9
#define SHOP_MUSIC_ID 0x90
#define GAMEBIT_SHOP_LOADED 0xefe /* set while the shop is loaded (init / free) */

extern void* Obj_GetPlayerObject(void);
extern void objRenderFn_8003b8f4(f32);
extern void playerAddMoney(int player, int amount);
extern void playerAddHealth(int player, int amount);
extern int gameBitIncrement(int bit);
extern int GameBit_Get(int);
extern void GameBit_Set(int slot, int val);
extern u32 randomGetRange(int min, int max);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int obj, int group);
extern void Music_Trigger(int a, int b);
extern void skyFn_80088c94(int skyId, int enable);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern void fn_80295CF4(int player, int mode);
extern f32 lbl_803E59C8;
extern u8 lbl_80327FD0[]; /* ShopItemRow[SHOP_ITEM_COUNT] */

/* obj->extra layout (shop_getExtraSize == 0x5) */
typedef struct ShopState
{
    s8 field0;       /* 0x00: read by shop_setScale */
    s8 selectedItem; /* 0x01: item index applied by shop_buyItem (-1 = none) */
    s8 unk2;         /* 0x02: shop_func15/16/17 accumulator */
    s8 unk3;         /* 0x03 */
    s8 unk4;         /* 0x04 */
} ShopState;

STATIC_ASSERT(sizeof(ShopState) == 0x5);

/* one row of the lbl_80327FD0 item table */
typedef struct ShopItemRow
{
    u8 price;        /* 0x00 */
    u8 priceTier[3]; /* 0x01: candidate prices; one is chosen into currentPrice */
    u8 field4;       /* 0x04 */
    u8 currentPrice; /* 0x05: this run's price, picked at init */
    s16 availBit;    /* 0x06: GameBit gating availability (-1 = always available) */
    s16 boughtBit;   /* 0x08: GameBit set once purchased (-1 = none) */
    s16 textId;      /* 0x0a: description text id */
} ShopItemRow;

STATIC_ASSERT(sizeof(ShopItemRow) == 0xc);

void shop_hitDetect(void)
{
}

void shop_release(void)
{
}

void shop_initialise(void)
{
}

int shop_getExtraSize(void) { return 0x5; }
int shop_getObjectTypeId(void) { return 0x0; }

s32 shop_getStateField1(int* obj) { return *(s8*)((char*)((int**)obj)[0xb8 / 4] + 0x1); }
s32 shop_setScale(int* obj) { return *(s8*)((char*)((int**)obj)[0xb8 / 4] + 0x0); }

void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E59C8);
}

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

    switch (((ShopState*)state)->selectedItem)
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

    items = lbl_80327FD0;
    items = items + ((ShopState*)state)->selectedItem * 0xc;
    boughtBit = *(s16*)(items + 8);
    if (boughtBit != -1)
    {
        GameBit_Set(boughtBit, 1);
    }
}

void shop_free(int* obj)
{
    skyFn_80088c94(7, 0);
    ObjGroup_RemoveObject(obj, SHOP_OBJGROUP);
    Music_Trigger(SHOP_MUSIC_ID, 0);
    GameBit_Set(GAMEBIT_SHOP_LOADED, 0);
}

void shop_func0B(int* obj, int v, int p3)
{
    s8* state = ((GameObject*)obj)->extra;
    state[0] = (s8)v;
    if (v != 0)
    {
        (*gObjectTriggerInterface)->runSequence(p3, obj, -1);
    }
}

void shop_func15(int* obj, int v)
{
    s8* b = ((GameObject*)obj)->extra;
    b[2] = 0;
    b[3] = 0;
    b[4] = (s8)v;
}

void shop_func16(int* obj, int p2, int p3)
{
    s8* b = ((GameObject*)obj)->extra;
    b[2] = (s8)(b[2] + p3);
    b[3] = (s8)(b[3] + p2);
}

void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4)
{
    s8* b = ((GameObject*)obj)->extra;
    *out_b2 = b[2];
    *out_b3 = b[3];
    *out_b4 = b[4];
}

int shop_getItemPrice(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_COUNT)
    {
        return lbl_80327FD0[idx * 0xc];
    }
    return 0;
}

s16 shop_getItemTextId(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_COUNT)
    {
        ShopItemRow* rows = (ShopItemRow*)lbl_80327FD0;
        return rows[idx].textId;
    }
    return 0;
}

u8 shop_getItemField4(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_COUNT)
    {
        return lbl_80327FD0[idx * 0xc + 0x4];
    }
    return 0;
}

u8 shop_getItemMinPrice(int p, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_COUNT)
    {
        return lbl_80327FD0[idx * 0xc + 0x5];
    }
    return 0;
}

void shop_init(int obj, int objDef)
{
    int i;
    u8* item;

    *(s8*)(*(int*)&((GameObject*)obj)->extra + 1) = -1;
    ObjGroup_AddObject(obj, SHOP_OBJGROUP);
    i = 0;
    item = lbl_80327FD0;
    while (i < SHOP_ITEM_COUNT)
    {
        item[5] = item[randomGetRange(0, 2) + 1];
        item += 0xc;
        i++;
    }
    Music_Trigger(SHOP_MUSIC_ID, 1);
    ((GameObject*)obj)->unkF8 = 0;
    GameBit_Set(GAMEBIT_SHOP_LOADED, 1);
}

/* 1 unless the item's availability GameBit (availBit) is present and unset
   (open by default; gated when availBit != -1). */
int shop_isItemAvailable(int p, int idx)
{
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = *(s16*)(lbl_80327FD0 + idx * 0xc + 0x6);
    if (slot == -1 || (u32)GameBit_Get(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

int shop_isItemBought(int p, int idx)
{
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = *(s16*)(lbl_80327FD0 + idx * 0xc + 0x8);
    if (slot != -1 && (u32)GameBit_Get(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

void shop_setStateField1(int* obj, int v)
{
    s8* state = ((GameObject*)obj)->extra;
    state[1] = (s8)v;
}

void shop_update(int obj)
{
    int player;

    player = (int)Obj_GetPlayerObject();
    if ((void*)Player_GetStaffObject(player) != NULL && (u32)GameBit_Get(0x18b) == 0u)
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
