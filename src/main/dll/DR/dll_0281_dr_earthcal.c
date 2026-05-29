#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int drearthcal_setScale(void) { return 1; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drearthcal_getExtraSize(void) { return 1; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drearthcal_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drearthcal_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drearthcal_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drearthcal_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drearthcal_init(int obj, int setup)
{
    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(u16 *)(obj + 0xb0) |= 0x6000;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drearthcal_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drearthcal_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void drearthcal_update(int obj)
{
    int player;
    int i;
    struct {
        f32 _pad[3];
        f32 vec[3];
    } part;
    f32 searchDist;

    player = Obj_GetPlayerObject();
    searchDist = lbl_803E6C08;
    if (fn_802972A8() != NULL) {
        *(u8 *)(obj + 0xaf) &= ~0x18;
        if ((*(u8 *)(obj + 0xaf) & 0x4) != 0) {
            setAButtonIcon(0x15);
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
        }
    } else {
        *(u8 *)(obj + 0xaf) |= 0x8;
        for (i = 0; i < *(s8 *)(*(int *)(obj + 0x58) + 0x10f); i++) {
            if (*(int *)(0x100 + i * 4 + *(int *)(obj + 0x58)) == player) {
                *(u8 *)(obj + 0xaf) &= ~0x8;
            }
        }
        if ((u32)ObjGroup_FindNearestObject(0xa, obj, &searchDist) == 0) {
            *(u8 *)(obj + 0xaf) |= 0x10;
        } else {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        }
        if ((*(u8 *)(obj + 0xaf) & 0x4) != 0) {
            setAButtonIcon(0x14);
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, -1);
        }
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
        part.vec[0] = lbl_803E6C0C;
        part.vec[1] = lbl_803E6C10;
        part.vec[2] = lbl_803E6C0C;
        objParticleFn_80097734(obj, 5, lbl_803E6C14, 2, 2, 0xf, lbl_803E6C18, lbl_803E6C18,
                               lbl_803E6C1C, &part, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset
