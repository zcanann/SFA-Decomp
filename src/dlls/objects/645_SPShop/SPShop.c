/* SPShop (DLL 645) */
#include "main/object_render.h"
#include "main/sky_api.h"
#include "main/render_envfx_api.h"
#include "main/dll/player_objects.h"
#include "sys/objects.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/gamebit_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/SP/dll_0285_spshop.h"
#include "dlls/object_descriptor.h"
#include "main/audio/music_api.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state.h"
#include "main/dll/player_staff_api.h"
#include "main/gamebits_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/mapEventTypes.h"

#define SPSHOP_OBJGROUP 9

/* number of ShopItemRow entries in gShopItemRows
   (data symbol size 0x2D0 / sizeof(ShopItemRow)(0xc) == 0x3c). */
#define SHOP_ITEM_ROW_COUNT 0x3c

/* Row indices ("No" column) into gShopItemRows / ShopItemRow. Only the
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

ShopItemRow gShopItemRows[SHOP_ITEM_ROW_COUNT] = {
    {3, {2, 2, 3}, 0, 0, 149, -1, 0x3F},
    {10, {7, 8, 10}, 0, 0, 149, -1, 0x40},
    {6, {4, 5, 6}, 0, 0, 149, -1, 0x41},
    {15, {10, 12, 15}, 0, 0, 149, -1, 0x42},
    {5, {3, 4, 5}, 0, 0, 149, -1, 0x43},
    {30, {25, 27, 30}, 0, 0, 149, -1, 0x44},
    {12, {11, 11, 12}, 0, 0, 149, -1, 0x45},
    {10, {7, 8, 10}, 0, 0, 149, -1, 0x46},
    {10, {7, 8, 10}, 0, 0, 149, -1, 0x47},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {15, {10, 12, 15}, 0, 0, 149, 37, 0x53},
    {20, {15, 18, 20}, 0, 0, 149, 318, 0x48},
    {130, {110, 120, 130}, 0, 0, 149, 418, 0x49},
    {20, {15, 17, 20}, 0, 0, 149, 3762, 0x4B},
    {50, {45, 47, 50}, 0, 0, 150, 3760, 0x4C},
    {10, {8, 9, 10}, 0, 0, 149, 3196, 0x52},
    {22, {18, 20, 22}, 0, 0, 149, 3213, 0x4C},
    {20, {17, 18, 20}, 0, 0, 149, 3172, 0xF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {5, {3, 4, 5}, 0, 0, 149, 1438, 0x4D},
    {5, {3, 4, 5}, 0, 0, 149, 2095, 0x4E},
    {5, {3, 4, 5}, 0, 0, 149, 1443, 0x50},
    {5, {3, 4, 5}, 0, 0, 149, 2101, 0x4F},
    {5, {3, 4, 5}, 0, 0, 149, 2094, 0x51},
    {5, {3, 4, 5}, 0, 0, 149, 1441, 0x54},
    {5, {3, 4, 5}, 0, 0, 149, 1442, 0x55},
    {5, {3, 4, 5}, 0, 0, 149, 2013, 0x13B},
    {5, {3, 4, 5}, 0, 0, 149, 2021, 0x13C},
    {10, {7, 8, 10}, 0, 0, 149, 2025, 0x13D},
    {5, {3, 4, 5}, 0, 0, 149, 1440, 0x13E},
    {10, {7, 8, 10}, 0, 0, 149, 1437, 0x13F},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
    {0, {0, 0, 0}, 0, 0, -1, -1, 0xFFFF},
};

ObjectDescriptor24 gShopObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)shop_initialise,
    (ObjectDescriptorCallback)shop_release,
    0,
    (ObjectDescriptorCallback)shop_init,
    (ObjectDescriptorCallback)shop_update,
    (ObjectDescriptorCallback)shop_hitDetect,
    (ObjectDescriptorCallback)shop_render,
    (ObjectDescriptorCallback)shop_free,
    (ObjectDescriptorCallback)shop_getObjectTypeId,
    shop_getExtraSize,
    (ObjectDescriptorCallback)shop_getStateField0,
    (ObjectDescriptorCallback)shop_playSequence,
    (ObjectDescriptorCallback)shop_isItemAvailable,
    (ObjectDescriptorCallback)shop_isItemBought,
    (ObjectDescriptorCallback)shop_getItemMinPrice,
    (ObjectDescriptorCallback)shop_getItemSpecialPrice,
    (ObjectDescriptorCallback)shop_getItemPrice,
    (ObjectDescriptorCallback)shop_getItemTextId,
    (ObjectDescriptorCallback)shop_setItemIndex,
    (ObjectDescriptorCallback)shop_getItemIndex,
    (ObjectDescriptorCallback)shop_buyItem,
    (ObjectDescriptorCallback)shop_func15,
    (ObjectDescriptorCallback)shop_func16,
    (ObjectDescriptorCallback)shop_func17,
};

/* Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */
void shop_func17(GameObject* obj, int* out_b3, int* out_b2, int* out_b4)
{
    s8* b = obj->extra;
    *out_b2 = b[2];
    *out_b3 = b[3];
    *out_b4 = b[4];
}

/* Increment-and-store: obj->_b8[2] += delta2,
 * obj->_b8[3] += delta3. */
void shop_func16(GameObject* obj, int delta3, int delta2)
{
    s8* b = obj->extra;
    b[2] = (s8)(b[2] + delta2);
    b[3] = (s8)(b[3] + delta3);
}

/* Shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash v in obj->_b8[4]. */
void shop_func15(GameObject* obj, int v)
{
    s8* b = obj->extra;
    b[2] = 0;
    b[3] = 0;
    b[4] = v;
}

void shop_buyItem(GameObject* obj, int price)
{

    GameObject* player;
    ShopBuyItemState* state;
    PlayerStatus* mapEventState;
    s16 boughtBit;

    player = (GameObject*)Obj_GetPlayerObject();
    state = obj->extra;
    mapEventState = (*gMapEventInterface)->getCurCharacterState();
    playerAddMoney(player, -price);

    switch (state->itemIndex)
    {
    case SHOP_ITEM_DUMBLEDANG_POD:
        playerAddHealth(player, 2);
        break;
    case SHOP_ITEM_BAFOMDAD_HOLDER:
        mapEventState->healCountMax = 10;
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

    boughtBit = gShopItemRows[state->itemIndex].boughtBit;
    if (boughtBit != -1)
    {
        mainSetBits(boughtBit, 1);
    }
}

s32 shop_getItemIndex(GameObject* obj)
{
    return ((ShopBuyItemState*)obj->extra)->itemIndex;
}

void shop_setItemIndex(GameObject* obj, int v)
{
    ShopBuyItemState* state = obj->extra;
    state->itemIndex = v;
}

s16 shop_getItemTextId(GameObject* obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return gShopItemRows[idx].textId;
    }
    return 0;
}

int shop_getItemPrice(GameObject* obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return gShopItemRows[idx].price;
    }
    return 0;
}

u8 shop_getItemSpecialPrice(GameObject* obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return gShopItemRows[idx].specialPrice;
    }
    return 0;
}

u8 shop_getItemMinPrice(GameObject* obj, int idx)
{
    if (idx >= 0 && idx < SHOP_ITEM_ROW_COUNT)
    {
        return gShopItemRows[idx].minPrice;
    }
    return 0;
}

/* Returns 1 when shop item's "bought"
 * GameBit (ShopItemRow.boughtBit) is set; else 0. */
int shop_isItemBought(GameObject* obj, int idx)
{

    ShopItemRow* row;
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    row = &gShopItemRows[idx];
    slot = row->boughtBit;
    if (slot != -1 && mainGetBit(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

/* Returns 1 unless the item's
 * "available" GameBit gate (ShopItemRow.availBit) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */
int shop_isItemAvailable(GameObject* obj, int idx)
{

    ShopItemRow* row;
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    row = &gShopItemRows[idx];
    slot = row->availBit;
    if (slot == -1 || mainGetBit(slot) != 0u)
    {
        result = 1;
    }
    return result;
}

void shop_playSequence(GameObject* obj, int playSequence, int sequenceIndex)
{
    ShopBuyItemState* state = obj->extra;
    state->unk0 = playSequence;
    if (playSequence != 0)
    {
        (*gObjectTriggerInterface)->runSequence(sequenceIndex, obj, -1);
    }
}

s32 shop_getStateField0(GameObject* obj)
{
    return ((ShopBuyItemState*)obj->extra)->unk0;
}

int shop_getExtraSize(void)
{
    return 0x5;
}

int shop_getObjectTypeId(void)
{
    return 0x0;
}

void shop_free(GameObject* obj)
{
    skySetSlotFlag80(7, 0);
    objFreeObjectType(obj, SPSHOP_OBJGROUP);
    Music_Trigger(MUSICTRIG_communicator, 0);
    mainSetBits(GAMEBIT_PlayerInShop, 0);
}

void shop_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void shop_hitDetect(void)
{
}

void shop_update(GameObject* obj)
{

    GameObject* player;

    player = Obj_GetPlayerObject();
    if (Player_GetStaffObject(player) != NULL && mainGetBit(GAMEBIT_STAFF_ACQUIRED) == 0u)
    {
        staffToggle(player, 0);
    }

    if (obj->userData1 == 0) {
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0, 1);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 5, 1);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 1);
        mainSetBits(GAMEBIT_SHOP_Unk0617, 1);
        skySetSlotFlag80(7, 1);
        obj->userData1 = 1;
    }

    if (mainGetBit(GAMEBIT_SHOP_Unk0D21) != 0u && obj->userData2 == 0) {
        skySetEnvFxFlags(0);
        getEnvfxAct(obj, obj, SPSHOP_ENVFX_A, 0);
        getEnvfxAct(obj, obj, SPSHOP_ENVFX_B, 0);
        obj->userData2 = 1;
        return;
    }

    if (mainGetBit(GAMEBIT_SHOP_Unk0D21) == 0u && obj->userData2 != 0) {
        obj->userData2 = 0;
    }
}

static inline void shop_initBody(GameObject* obj, int objDef)
{
    ShopItemRow* item;
    int i;

    ((ShopBuyItemState*)obj->extra)->itemIndex = -1;
    objAddObjectType(obj, SPSHOP_OBJGROUP);
    for (i = 0, item = gShopItemRows; i < SHOP_ITEM_ROW_COUNT; i++)
    {
        item->minPrice = item->discount[randomGetRange(0, 2)];
        item++;
    }
    Music_Trigger(MUSICTRIG_communicator, 1);
    obj->userData2 = 0;
    mainSetBits(GAMEBIT_PlayerInShop, 1);
}

void shop_init(GameObject* obj, int objDef)
{
    shop_initBody(obj, objDef);
}

void shop_release(void)
{
}

void shop_initialise(void)
{
}
