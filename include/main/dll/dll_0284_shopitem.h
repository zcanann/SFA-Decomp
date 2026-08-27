#ifndef MAIN_DLL_DLL_0284_SHOPITEM_H_
#define MAIN_DLL_DLL_0284_SHOPITEM_H_

#include "game/objects/object.h"
#include "main/dll/firefly_flight_state.h"
#include "main/lightningeffect.h"
#include "main/objseq.h"
#include "types.h"

typedef struct ShopItemFlags {
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} ShopItemFlags;

typedef struct ShopItemState {
    FireFlyFlightState flight;
    u8 pad7C[0x88 - 0x7C];
    s16 msgParam;
    u8 pad8A[6];
    int vendorObj; /* codegen-proven object handle */
    s16 helpTextId;
    u8 pad96;
    ShopItemFlags flags97;
    LightningEffect* lightningHandles[10];
    f32 lightningTimers[10];
    ShopItemFlags flagsE8;
    u8 padE9[0xEC - 0xE9];
} ShopItemState;

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);
STATIC_ASSERT(offsetof(ShopItemState, flight) == 0x00);
STATIC_ASSERT(offsetof(ShopItemState, flight.ownerData) == 0x00);
STATIC_ASSERT(offsetof(ShopItemState, flight.splineX) == 0x04);
STATIC_ASSERT(offsetof(ShopItemState, flight.splineT) == 0x40);
STATIC_ASSERT(offsetof(ShopItemState, flight.pathAge) == 0x68);
STATIC_ASSERT(offsetof(ShopItemState, msgParam) == 0x88);
STATIC_ASSERT(offsetof(ShopItemState, vendorObj) == 0x90);
STATIC_ASSERT(offsetof(ShopItemState, helpTextId) == 0x94);
STATIC_ASSERT(offsetof(ShopItemState, flags97) == 0x97);
STATIC_ASSERT(offsetof(ShopItemState, lightningHandles) == 0x98);
STATIC_ASSERT(offsetof(ShopItemState, lightningTimers) == 0xC0);
STATIC_ASSERT(offsetof(ShopItemState, flagsE8) == 0xE8);

void shopitem_onSeqFree(GameObject* obj);

#endif
