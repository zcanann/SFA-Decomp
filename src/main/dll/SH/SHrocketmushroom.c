#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"

#pragma peephole off
#pragma scheduling off

void bombplantingspot_init(void *obj, void *param2) {
    *(u16 *)((u8 *)obj + 0xb0) |= 0x4000;
    *(s16 *)obj = (s16)((s8) * ((s8 *)param2 + 0x18) << 8);
}
