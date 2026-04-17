#include <dolphin.h>
#include <dolphin/os.h>
#include <dolphin/dvd.h>

#include "dolphin/dvd/__dvd.h"
#include "dolphin/os/__os.h"

static u32 ErrorTable[18] = {
    0x00000000,
    0x00023A00,
    0x00062800,
    0x00030200,
    0x00031100,
    0x00052000,
    0x00052001,
    0x00052100,
    0x00052400,
    0x00052401,
    0x00052402,
    0x000B5A01,
    0x00056300,
    0x00020401,
    0x00020400,
    0x00040800,
    0x00100007,
    0x00000000,
};

#define DIDNT_MATCH 29

static u8 ErrorCode2Num(u32 errorCode) {
	u32 i;

	for (i = 0; i < 18; i++) {
		if (errorCode == ErrorTable[i]) {
            ASSERTLINE(73, i < DIDNT_MATCH);
			return i;
		}
	}

	if (errorCode >= 0x100000 && errorCode <= 0x100008) {
		return 17;
	}

	return DIDNT_MATCH;
}

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
