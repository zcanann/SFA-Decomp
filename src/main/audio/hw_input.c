#include "main/audio/hw_input.h"

#pragma exceptions on

extern u8 lbl_803CC1E0[];
extern void salAddStudioInput(void* entry, void* input);

void hwAddInput(u8 index, void* input)
{
    salAddStudioInput(lbl_803CC1E0 + index * 0xbc, input);
}
