#include <dolphin.h>
#include <dolphin/os.h>
#include <dolphin/dvd.h>

#include "dolphin/dvd/__dvd.h"
#include "dolphin/os/__os.h"

extern u32 lbl_8032DD38[18];

#define DIDNT_MATCH 29

#pragma dont_inline on
static u8 ErrorCode2Num(u32 errorCode) {
	u32 i;

	for (i = 0; i < 18; i++) {
		if (errorCode == lbl_8032DD38[i]) {
            ASSERTLINE(73, i < DIDNT_MATCH);
			return i;
		}
	}

	if (errorCode >= 0x100000 && errorCode <= 0x100008) {
		return 17;
	}

	return DIDNT_MATCH;
}
#pragma dont_inline reset

void __DVDStoreErrorCode(u32 error) {
    u32 statusCode;
    u32 errorCode;
    u8 errorNum;
    OSSramEx* sram;
    u8 num;

    if (error == 0x01234567) {
        num = (u8)-1;
    } else if (error == 0x01234568) {
        num = (u8)-2;
    } else {
        statusCode = (error >> 24) & 0xFF;
        errorCode = error & 0x00FFFFFF;
        errorNum = ErrorCode2Num(errorCode);
        if (statusCode >= 6) {
            statusCode = 6;
        }

        num = statusCode * 30 + errorNum;
    }

    sram = __OSLockSramEx();
    sram->dvdErrorCode = num;
    __OSUnlockSramEx(TRUE);
}
