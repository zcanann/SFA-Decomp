#ifndef MAIN_DLL_SP_DLL_0285_SPSHOP_H_
#define MAIN_DLL_SP_DLL_0285_SPSHOP_H_

#include "types.h"

typedef struct ShopBuyItemState
{
    s8 unk0;      /* 0x0 */
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

typedef struct ShopItemRow
{
    u8 price;      /* 0x0 "P$" */
    u8 discount1;  /* 0x1 "D1" */
    u8 discount2;  /* 0x2 "D2" */
    u8 discount3;  /* 0x3 "D3" (observed always == price) */
    u8 field4;     /* 0x4 */
    u8 minPrice;   /* 0x5 */
    s16 availBit;  /* 0x6 "available" GameBit slot (-1 = always available) */
    s16 boughtBit; /* 0x8 "bought" GameBit slot (-1 = none) */
    s16 textId;    /* 0xa */
} ShopItemRow;

void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4);
void shop_func16(int* obj, int p2, int p3);
void shop_func15(int* obj, int v);
void shop_buyItem(struct GameObject* obj, int price);
s32 shop_getItemIndex(int* obj);
void shop_setItemIndex(int* obj, int v);
s16 shop_getItemTextId(int obj, int idx);
int shop_getItemPrice(int obj, int idx);
u8 shop_getItemField4(int obj, int idx);
u8 shop_getItemMinPrice(int obj, int idx);
int shop_isItemBought(int obj, int idx);
int shop_isItemAvailable(int obj, int idx);
void shop_func0B(int* obj, int v, int p3);
s32 shop_getStateField0(int* obj);
int shop_getExtraSize(void);
int shop_getObjectTypeId(void);
void shop_free(int* obj);
void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void shop_hitDetect(void);
void shop_update(int obj);
void shop_init(int obj, int objDef);
void shop_release(void);
void shop_initialise(void);

#endif /* MAIN_DLL_SP_DLL_0285_SPSHOP_H_ */
