/* DLL 0x0285 - SP shop objects [801E4288-801E42F8) */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/player_objects.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/SP/dll_0285_spshop.h"

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

#define SPSHOP_OBJGROUP 9

/* number of ShopItemRow entries in lbl_80327FD0
   (data symbol size 0x2D0 / sizeof(ShopItemRow)(0xc) == 0x3c). */
#define SHOP_ITEM_ROW_COUNT 0x3c

/* Row indices ("No" column) into lbl_80327FD0 / ShopItemRow. Only the
   non-omitted rows are named; unlisted indices in [0, SHOP_ITEM_ROW_COUNT)
   are all-zero/unused rows. */
enum ShopItemIndex
{
    SHOP_ITEM_DUMBLEDANG_POD = 0x00,    /* 1/2 heart */
    SHOP_ITEM_DUMBLEDANG_POD_4X = 0x01, /* 2 hearts */
    SHOP_ITEM_PUKPUK_EGG = 0x02,        /* 1 heart */
    SHOP_ITEM_PUKPUK_EGGS_7X = 0x03,    /* 7 hearts */
    SHOP_ITEM_BOMB_SPORE = 0x04,
    SHOP_ITEM_MOON_SEED = 0x05,
    SHOP_ITEM_GRUBTUB_FUNGUS = 0x06,
    SHOP_ITEM_FIREFLY = 0x07,
    SHOP_ITEM_FUEL_CELL = 0x08,
    SHOP_ITEM_TRICKYS_BALL = 0x14,
    SHOP_ITEM_FIREFLY_LANTERN = 0x15,
    SHOP_ITEM_SNOWHORN_ARTIFACT = 0x16,
    SHOP_ITEM_BAFOMDAD_HOLDER = 0x17,
    SHOP_ITEM_BAD_GUY_ALERT_UNUSED = 0x18, /* never available (GAMEBIT_Always0) */
    SHOP_ITEM_ROCK_CANDY = 0x19,
    SHOP_ITEM_PDA_UNUSED = 0x1A,
    SHOP_ITEM_VIEWFINDER = 0x1B,
    SHOP_ITEM_MAP_DARKICE_MINES = 0x28,
    SHOP_ITEM_MAP_CAPE_CLAW = 0x29,
    SHOP_ITEM_MAP_THORNTAIL_HOLLOW = 0x2A,
    SHOP_ITEM_MAP_MOON_PASS = 0x2B,
    SHOP_ITEM_MAP_WALLED_CITY = 0x2C,
    SHOP_ITEM_MAP_CLOUDRUNNER_FORT = 0x2D,
    SHOP_ITEM_MAP_LIGHTFOOT_VILLAGE = 0x2E,
    SHOP_ITEM_MAP_DRAGON_ROCK = 0x2F,
    SHOP_ITEM_MAP_KRAZOA_PALACE = 0x30,
    SHOP_ITEM_MAP_OCEAN_FORCE_POINT = 0x31,
    SHOP_ITEM_MAP_SNOWHORN_WASTES = 0x32,
    SHOP_ITEM_MAP_VOLCANO_FORCE_PT = 0x33,

    SHOP_ITEM_LAST = 0x3B
};

/* Env-fx ids co-activated once on gamebit 0xd21 (getEnvfxAct 3rd arg) */
#define SPSHOP_ENVFX_A 0x1c8
#define SPSHOP_ENVFX_B 0x1cb

extern u8 lbl_80327FD0[];
extern f32 lbl_803E59C8;

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void playerAddMoney(int obj, int amount);
extern void playerAddHealth(int obj, int amount);
extern int gameBitIncrement(int bit);
extern void staffToggle(struct GameObject *obj, int a);
extern void skyFn_80088c94(int flags, int mode);
extern void envFxActFn_800887f8(u8 value);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void Music_Trigger(int id, int arg);

/* Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */
void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4)
{
    s8* b = ((GameObject*)obj)->extra;
    *out_b2 = b[2];
    *out_b3 = b[3];
    *out_b4 = b[4];
}

/* Increment-and-store: obj->_b8[2] += delta2,
 * obj->_b8[3] += delta3. */
void shop_func16(int* obj, int delta3, int delta2)
{
    s8* b = ((GameObject*)obj)->extra;
    b[2] = (s8)(b[2] + delta2);
    b[3] = (s8)(b[3] + delta3);
}

/* Shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash v in obj->_b8[4]. */
void shop_func15(int* obj, int v)
{
    s8* b = ((GameObject*)obj)->extra;
    b[2] = 0;
    b[3] = 0;
    b[4] = v;
}

void shop_buyItem(struct GameObject *obj, int price)
{

    int player;
    int state;
    int mapEventState;
    u8* items;
    s16 boughtBit;

    player = (int)Obj_GetPlayerObject();
    state = *(int*)&(obj)->extra;
    mapEventState = (int)(*gMapEventInterface)->getCurCharacterState();
    playerAddMoney(player, -price);

    switch (((ShopBuyItemState*)state)->itemIndex)
    {
    case SHOP_ITEM_DUMBLEDANG_POD:
        playerAddHealth(player, 2);
        break;
    case SHOP_ITEM_BAFOMDAD_HOLDER:
        *(u8*)(mapEventState + 0xa) = 10;
        break;
    case SHOP_ITEM_DUMBLEDANG_POD_4X:
        playerAddHealth(player, 8);
        break;
    case SHOP_ITEM_PUKPUK_EGG:
        playerAddHealth(player, 4);
        break;
    case SHOP_ITEM_PUKPUK_EGGS_7X:
        playerAddHealth(player, 0x1c);
        break;
    case SHOP_ITEM_BOMB_SPORE:
        gameBitIncrement(GAMEBIT_ITEM_BombSpore_Count);
        break;
    case SHOP_ITEM_MOON_SEED:
        gameBitIncrement(GAMEBIT_ITEM_MoonSeed_Count);
        break;
    case SHOP_ITEM_GRUBTUB_FUNGUS:
        gameBitIncrement(GAMEBIT_ITEM_TrickyFood_Count);
        break;
    case SHOP_ITEM_FIREFLY:
        gameBitIncrement(GAMEBIT_ITEM_Firefly_Count);
        gameBitIncrement(GAMEBIT_ITEM_FireflyNotShown_Count);
        break;
    case SHOP_ITEM_FUEL_CELL:
        gameBitIncrement(GAMEBIT_ITEM_FuelCell_Count);
        break;
    }

    items = lbl_80327FD0 + 8;
    boughtBit = *(s16*)(items + ((ShopBuyItemState*)state)->itemIndex * 0xc);
    if (boughtBit != -1)
    {
        mainSetBits(boughtBit, 1);
    }
}

s32 shop_getItemIndex(int* obj)
{
    return ((ShopBuyItemState*)((GameObject*)obj)->extra)->itemIndex;
}

void shop_setItemIndex(int* obj, int v)
{
    s8* state = ((GameObject*)obj)->extra;
    state[1] = v;
}

s16 shop_getItemTextId(int obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        ShopItemRow* rows = (ShopItemRow*)lbl_80327FD0;
        return rows[idx].textId;
    }
    return 0;
}

int shop_getItemPrice(int obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return ((ShopItemRow*)lbl_80327FD0)[idx].price;
    }
    return 0;
}

u8 shop_getItemField4(int obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return lbl_80327FD0[idx * 0xc + 0x4];
    }
    return 0;
}

u8 shop_getItemMinPrice(int obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return lbl_80327FD0[idx * 0xc + 0x5];
    }
    return 0;
}

/* Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
int shop_isItemBought(int obj, int idx)
{

    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = ((ShopItemRow*)lbl_80327FD0)[idx].boughtBit;
    if (slot != -1 && mainGetBit(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

/* Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */
int shop_isItemAvailable(int obj, int idx)
{

    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = ((ShopItemRow*)lbl_80327FD0)[idx].availBit;
    if (slot == -1 || mainGetBit(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

void shop_func0B(int* obj, int v, int seqId)
{
    s8* state = ((GameObject*)obj)->extra;
    state[0] = v;
    if (v != 0)
    {
        (*gObjectTriggerInterface)->runSequence(seqId, obj, -1);
    }
}

s32 shop_getStateField0(int* obj)
{
    return ((ShopBuyItemState*)((GameObject*)obj)->extra)->unk0;
}

int shop_getExtraSize(void)
{
    return 0x5;
}

int shop_getObjectTypeId(void)
{
    return 0x0;
}

void shop_free(int* obj)
{
    skyFn_80088c94(7, 0);
    ObjGroup_RemoveObject(obj, SPSHOP_OBJGROUP);
    Music_Trigger(MUSICTRIG_communicator, 0);
    mainSetBits(GAMEBIT_PlayerInShop, 0);
}

void shop_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E59C8);
}

void shop_hitDetect(void)
{
}

void shop_update(int obj)
{

    int player;

    player = (int)Obj_GetPlayerObject();
    if ((void*)Player_GetStaffObject(player) != NULL && mainGetBit(GAMEBIT_STAFF_ACQUIRED) == 0u)
    {
        staffToggle((struct GameObject*)(player), 0);
    }

    if (((GameObject*)obj)->unkF4 == 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0, 1);
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 5, 1);
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 1);
        mainSetBits(GAMEBIT_SHOP_Unk0617, 1);
        skyFn_80088c94(7, 1);
        ((GameObject*)obj)->unkF4 = 1;
    }

    if ((u32)mainGetBit(GAMEBIT_SHOP_Unk0D21) != 0u && ((GameObject*)obj)->unkF8 == 0)
    {
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, SPSHOP_ENVFX_A, 0);
        getEnvfxAct(obj, obj, SPSHOP_ENVFX_B, 0);
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }

    if ((u32)mainGetBit(GAMEBIT_SHOP_Unk0D21) == 0u && ((GameObject*)obj)->unkF8 != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
    }
}

#pragma inline_max_size(1000)
static inline void shop_initBody(int obj, int objDef)
{
    u8* item;
    int i;

    ((ShopBuyItemState*)((GameObject*)obj)->extra)->itemIndex = -1;
    ObjGroup_AddObject(obj, SPSHOP_OBJGROUP);
    for (i = 0, item = lbl_80327FD0; i < SHOP_ITEM_ROW_COUNT; i++)
    {
        item[5] = item[randomGetRange(0, 2) + 1];
        item += 0xc;
    }
    Music_Trigger(MUSICTRIG_communicator, 1);
    ((GameObject*)obj)->unkF8 = 0;
    mainSetBits(GAMEBIT_PlayerInShop, 1);
}
#pragma inline_max_size reset

void shop_init(int obj, int objDef)
{
    shop_initBody(obj, objDef);
}

void shop_release(void)
{
}

void shop_initialise(void)
{
}
