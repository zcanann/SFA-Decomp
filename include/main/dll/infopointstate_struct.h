#ifndef MAIN_DLL_INFOPOINTSTATE_STRUCT_H_
#define MAIN_DLL_INFOPOINTSTATE_STRUCT_H_

#include "types.h"

typedef struct InfopointState
{
    int text;        /* 0x00: pointer to the loaded game-text body */
    int textValue;   /* 0x04: first word reached through text[2] */
    int unk08;       /* 0x08: pointer to lbl_80321990 */
    int timer;       /* 0x0C: scroll/fade timer (starts at 100) */
    u8 unk10;        /* 0x10: copied from def->unk1B */
    u8 pad11[0x16 - 0x11];
    s16 flag;        /* 0x16: toggled 0xff/0 by InfoPoint_SeqFn events 1/2 */
    int unk18;       /* 0x18: starts at 2 */
    u8 pad1C[0x20 - 0x1C];
} InfopointState;

#endif
