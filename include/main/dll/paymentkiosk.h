#ifndef MAIN_DLL_PAYMENTKIOSK_H_
#define MAIN_DLL_PAYMENTKIOSK_H_

#include "global.h"
#include "main/obj_placement.h"

/*
 * Per-object extra state for the PaymentKiosk family
 * (paymentkiosk_getExtraSize == 3). Shared by VF/platform1.c and
 * DB/DBrockfall.c (paymentkiosk_init).
 */
typedef struct PaymentKioskState {
  u8 payState;    /* 0 = resolve from gamebit, 1 = trigger disabled, 2 = paid */
  u8 textVariant; /* 1 for objType 0x476 -- indexes the kiosk text table */
  u8 promptState; /* 0 = none, 1 = show approach text, 2 = cannot afford */
} PaymentKioskState;

typedef struct PaymentKioskMapData {
  ObjPlacement base;
  s8 facingByte;
  u8 pad19;
  s16 price;
  u8 pad1C[0x1E - 0x1C];
  s16 gameBit;
} PaymentKioskMapData;

STATIC_ASSERT(sizeof(PaymentKioskState) == 0x3);
STATIC_ASSERT(offsetof(PaymentKioskMapData, facingByte) == 0x18);
STATIC_ASSERT(offsetof(PaymentKioskMapData, price) == 0x1A);
STATIC_ASSERT(offsetof(PaymentKioskMapData, gameBit) == 0x1E);

#define PAYMENT_KIOSK_WELL_TEXT_SEQ_ID 0x0476

/* PaymentKioskState.payState */
#define PAYMENT_KIOSK_STATE_RESOLVE 0 /* decide from gamebit: already paid -> PAID, else ACTIVE */
#define PAYMENT_KIOSK_STATE_ACTIVE 1  /* interactable; run pay sequence on activation */
#define PAYMENT_KIOSK_STATE_PAID 2    /* gamebit set; interaction disabled */

#endif /* MAIN_DLL_PAYMENTKIOSK_H_ */
