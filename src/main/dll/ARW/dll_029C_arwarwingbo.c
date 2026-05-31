#include "main/dll/dll_80220608_shared.h"

#define SFXbaddie_eba_death 0x2a5

#pragma peephole on
#pragma scheduling on
int arwarwingbo_getExtraSize(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwarwingbo_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwarwingbo_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
    ObjGroup_RemoveObject(obj, 0x52);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwingbo_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E704C);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwingbo_init(int obj, int setup)
{
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    ObjGroup_AddObject(obj, 0x52);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwingbo_setActiveVisible(int obj, u8 active, u8 visible)
{
    int state = *(int *)(obj + 0xb8);
    if (active != 0) {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        *(u8 *)(state + 0) = 1;
        *(s16 *)(obj + 6) &= ~0x4000;
    } else {
        *(u8 *)(state + 0) = 0;
        *(s16 *)(obj + 6) |= 0x4000;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwingbo_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwingbo_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwingbo_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (*(u16 *)(arwing + 0xb0) & 0x1000) {
        fn_8022D4F8(arwing);
        Obj_FreeObject(obj);
        return;
    }
    if (*(f32 *)(state + 8) > lbl_803E7044) {
        *(f32 *)(state + 8) -= timeDelta;
        if (*(f32 *)(state + 8) <= lbl_803E7044)
            Obj_FreeObject(obj);
        return;
    }
    if (*(f32 *)(state + 0) > lbl_803E7044) {
        *(f32 *)(state + 0) -= timeDelta;
        if (*(f32 *)(state + 0) <= lbl_803E7044) {
            state = *(int *)(obj + 0xb8);
            fn_8022D4F8(getArwing());
            Sfx_PlayFromObject(obj, SFXbaddie_eba_death);
            *(f32 *)(state + 8) = lbl_803E7040;
            *(f32 *)(state + 0) = lbl_803E7044;
            *(u8 *)(obj + 0x36) = 0;
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            *(f32 *)(obj + 0x24) = lbl_803E7044;
            *(f32 *)(obj + 0x28) = lbl_803E7044;
            *(f32 *)(obj + 0x2c) = lbl_803E7044;
        }
        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x79e, 0, 1, -1, obj + 0x24);
        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x79e, 0, 1, -1, obj + 0x24);
        ObjHits_SetHitVolumeSlot(obj, 0xf, 0, 0);
        if (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL ||
            (s8)*(u8 *)(*(int *)(obj + 0x54) + 0xad) != 0 ||
            (getButtonsJustPressed(0) & 0x200)) {
            state = *(int *)(obj + 0xb8);
            fn_8022D4F8(getArwing());
            Sfx_PlayFromObject(obj, SFXbaddie_eba_death);
            *(f32 *)(state + 8) = lbl_803E7040;
            *(f32 *)(state + 0) = lbl_803E7044;
            *(u8 *)(obj + 0x36) = 0;
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            *(f32 *)(obj + 0x24) = lbl_803E7044;
            *(f32 *)(obj + 0x28) = lbl_803E7044;
            *(f32 *)(obj + 0x2c) = lbl_803E7044;
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
                *(f32 *)(obj + 0x2c) * timeDelta);
    }
}
#pragma scheduling reset
#pragma peephole reset
