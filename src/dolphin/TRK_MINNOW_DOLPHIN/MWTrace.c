#include "dolphin/types.h"

typedef struct MWTraceRecord {
    u32 type;
    u32 level;
    u32 pad[3];
} MWTraceRecord;

extern u32 lbl_803DC9C8;
extern char* lbl_803DC9CC;
extern MWTraceRecord lbl_8033A540[];
extern char lbl_802C7400[][0x20];

void MWTRACE(int level, char* format) {
    MWTraceRecord* record;
    char* current;
    u32 index;

    (void) format;

    index = lbl_803DC9C8;
    lbl_803DC9C8 = index + 1;
    record = &lbl_8033A540[index];

    if (level == 0xFF) {
        current = NULL;
    } else {
        current = lbl_802C7400[level];
    }

    lbl_803DC9CC = current;
    record->type = 8;
    record->level = level;
}
