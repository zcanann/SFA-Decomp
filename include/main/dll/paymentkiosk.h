#ifndef MAIN_DLL_PAYMENTKIOSK_H_
#define MAIN_DLL_PAYMENTKIOSK_H_

#include "global.h"

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

STATIC_ASSERT(sizeof(PaymentKioskState) == 0x3);

#endif /* MAIN_DLL_PAYMENTKIOSK_H_ */
