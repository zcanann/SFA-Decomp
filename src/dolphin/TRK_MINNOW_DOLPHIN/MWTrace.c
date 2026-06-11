#include "dolphin.h"

extern char gTextBoxes[];
extern volatile u32 lbl_8033A540[][5];
extern volatile u32 lbl_803DC9C8;
extern void* gCurTextBox;

void MWTRACE(level, format)
int level;
char* format;
{
    int trace_index;
    volatile u32* trace_entry;
    void* trace_message;

    (void)format;

    trace_index = lbl_803DC9C8;
    lbl_803DC9C8 = trace_index + 1;
    trace_entry = lbl_8033A540[trace_index];

    if (level == 0xFF) {
        trace_message = NULL;
    } else {
        trace_message = &gTextBoxes[level * 0x20];
    }
    gCurTextBox = trace_message;

    trace_entry[0] = 8;
    trace_entry[1] = level;
}
