#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"

#pragma peephole off
#pragma scheduling off

extern uint GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int gameBitDecrement(int bit);
extern int ObjTrigger_IsSetById(void *obj, int triggerId);
extern void objRenderFn_80041018(void *obj);

extern void *lbl_803DCA54;

void bombplantingspot_update(void *obj) {
    void *pState = *(void **)((u8 *)obj + 0x4c);
    s32 trigBit;

    *(s16 *)obj = (s16)((s8) * ((s8 *)pState + 0x18) << 8);

    trigBit = *(s16 *)((u8 *)pState + 0x20);
    if (trigBit != -1 && GameBit_Get(trigBit) == 0) {
        *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
        return;
    }

    if (GameBit_Get(0x66c) == 0) {
        *(u8 *)((u8 *)obj + 0xaf) |= 0x10;
    } else {
        *(u8 *)((u8 *)obj + 0xaf) &= ~0x10;
    }

    if (ObjTrigger_IsSetById(obj, 0x66c) != 0) {
        gameBitDecrement(0x66c);
        GameBit_Set(*(s16 *)((u8 *)pState + 0x1e), 1);
        (*(void (***)(int, void *, int))lbl_803DCA54)[0x12](1, obj, -1);
    } else if ((*(u8 *)((u8 *)obj + 0xaf) & 0x4) != 0 && GameBit_Get(0x196) == 0) {
        (*(void (***)(int, void *, int))lbl_803DCA54)[0x12](0, obj, -1);
        GameBit_Set(0x196, 1);
    }

    if (GameBit_Get(*(s16 *)((u8 *)pState + 0x1e)) == 0) {
        *(u8 *)((u8 *)obj + 0xaf) &= ~0x8;
        objRenderFn_80041018(obj);
    } else {
        *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
    }
}

void bombplantingspot_init(void *obj, void *param2) {
    *(u16 *)((u8 *)obj + 0xb0) |= 0x4000;
    *(s16 *)obj = (s16)((s8) * ((s8 *)param2 + 0x18) << 8);
}
