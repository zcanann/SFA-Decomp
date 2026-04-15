#include <dolphin/card.h>

#include "dolphin/card/__card.h"

s32 CARDGetSerialNo(s32 chan, u64* serialNo) {
    CARDControl* card;
    s32 result;
    CARDID* id;
    u64 code;
    int i;

    ASSERTLINE(105, 0 <= chan && chan < 2);

    if (!(0 <= chan && chan < 2)) {
        return CARD_RESULT_FATAL_ERROR;
    }

    result = __CARDGetControlBlock(chan, &card);
    if (result < 0) {
        return result;
    }

    id = (CARDID*)card->workArea;
    for (code = 0, i = 0; i < sizeof(id->serial) / sizeof(u64); ++i) {
        code ^= *(u64*)&id->serial[sizeof(u64) * i];
    }
    *serialNo = code;

    return __CARDPutControlBlock(card, CARD_RESULT_READY);
}
