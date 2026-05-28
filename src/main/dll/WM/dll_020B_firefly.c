#include "main/dll/WM/wm_shared.h"

#pragma peephole off
#pragma scheduling off
void FireFlyFn_801f4f88(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int player = (int)Obj_GetPlayerObject();
    if (*(u8 *)(obj + 0x36) < 0xff) {
        int v = (int)(lbl_803E5EDC * timeDelta + (f32)*(u8 *)(obj + 0x36));
        if (v > 0xff) v = 0xff;
        *(u8 *)(obj + 0x36) = (u8)v;
    }
    if (*(f32 *)(state + 0x40) > lbl_803E5EB4) {
        *(f32 *)(state + 0x40) = *(f32 *)(state + 0x40) - lbl_803E5EB4;
        if (*(u8 *)(state + 0x68) < 4) {
            *(u8 *)(state + 0x68) = *(u8 *)(state + 0x68) + 1;
        } else {
            fn_801F4D54(obj, state);
        }
        *(f32 *)(state + 0x4) = *(f32 *)(state + 0x8);
        *(f32 *)(state + 0x14) = *(f32 *)(state + 0x18);
        *(f32 *)(state + 0x24) = *(f32 *)(state + 0x28);
        *(f32 *)(state + 0x8) = *(f32 *)(state + 0xc);
        *(f32 *)(state + 0x18) = *(f32 *)(state + 0x1c);
        *(f32 *)(state + 0x28) = *(f32 *)(state + 0x2c);
        *(f32 *)(state + 0xc) = *(f32 *)(state + 0x10);
        *(f32 *)(state + 0x1c) = *(f32 *)(state + 0x20);
        *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x30);
        *(f32 *)(state + 0x44) = lbl_803E5ED8 * (f32)(int)randomGetRange(0xa0, 0xb4);
        *(f32 *)(state + 0x10) = *(f32 *)(state + 0x34);
        *(f32 *)(state + 0x20) = *(f32 *)(state + 0x38);
        *(f32 *)(state + 0x30) = *(f32 *)(state + 0x3c);
    }
    *(f32 *)(obj + 0xc) = mathFn_80010ee0((f32 *)(state + 0x4), 0, *(f32 *)(state + 0x40));
    *(f32 *)(obj + 0x10) = mathFn_80010ee0((f32 *)(state + 0x14), 0, *(f32 *)(state + 0x40));
    *(f32 *)(obj + 0x14) = mathFn_80010ee0((f32 *)(state + 0x24), 0, *(f32 *)(state + 0x40));
    *(f32 *)(state + 0x40) = *(f32 *)(state + 0x44) * timeDelta + *(f32 *)(state + 0x40);
    *(s16 *)obj = (s16)getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80),
                                 *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
    if (*(u8 *)(state + 0x66) == 1 || *(u8 *)(state + 0x66) == 4) {
        ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0x1a0, 0, 1, -1, 0);
    } else {
        ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0x1bd, 0, 1, -1, 0);
    }
    if (Vec_xzDistance((f32 *)(player + 0x18), (f32 *)(*(int *)(obj + 0x4c) + 0x8)) < *(f32 *)(state + 0x4c)) {
        if (*(u8 *)(state + 0x66) == 4) {
            ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0x19f, 0, 1, -1, 0);
        } else if (*(u8 *)(state + 0x66) == 3) {
            ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0x1bc, 0, 1, -1, 0);
        } else if (*(u8 *)(state + 0x66) == 5) {
            ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0x1bc, 0, 1, -1, 0);
        }
        if (*(f32 *)(state + 0x48) < lbl_803E5EE0) {
            *(f32 *)(state + 0x48) = *(f32 *)(state + 0x48) + lbl_803E5EE4;
            if (*(f32 *)(state + 0x48) > lbl_803E5EE0) {
                *(f32 *)(state + 0x48) = lbl_803E5EE0;
            }
        }
    } else {
        if (*(f32 *)(state + 0x48) > lbl_803E5EE8) {
            *(f32 *)(state + 0x48) = *(f32 *)(state + 0x48) - lbl_803E5EE4;
            if (*(f32 *)(state + 0x48) < lbl_803E5EE8) {
                *(f32 *)(state + 0x48) = lbl_803E5EE8;
            }
        }
    }
    if ((*(u8 *)(state + 0x7c) & 1) == 0) {
        f32 dy = *(f32 *)(obj + 0x10) - *(f32 *)(player + 0x10);
        if (dy < lbl_803E5EEC && dy > lbl_803E5EC4) {
            if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < lbl_803E5EF0) {
                *(u8 *)(state + 0x7c) = (u8)(*(u8 *)(state + 0x7c) | 1);
                if (GameBit_Get(0xd28) == 0) {
                    *(s16 *)(state + 0x80) = -1;
                    ObjMsg_SendToObject(player, 0x7000a, obj, (void *)(state + 0x80));
                    GameBit_Set(0xd28, 1);
                } else {
                    *(s16 *)(obj + 0x6) = (s16)(*(s16 *)(obj + 0x6) | 0x4000);
                    *(f32 *)(state + 0x70) = lbl_803E5EA8;
                    gameBitIncrement(0x13d);
                    gameBitIncrement(0x5d6);
                    Sfx_PlayFromObject(obj, 0x49);
                }
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void firefly_free(int obj)
{
    fn_8001CB3C(*(void **)(obj + 0xB8));
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void firefly_update(int obj)
{
    int *state;
    int *def;
    int msg[2];
    u8 isActive;

    state = *(int **)(obj + 0xB8);
    def = *(int **)(obj + 0x4C);
    while (ObjMsg_Pop(obj, msg, 0, 0) != 0) {
        if (msg[0] == 0x7000B) {
            *(s16 *)(obj + 0x6) = (s16)(*(s16 *)(obj + 0x6) | 0x4000);
            *(f32 *)((u8 *)state + 0x70) = lbl_803E5EA8;
            gameBitIncrement(0x13D);
            gameBitIncrement(0x5D6);
            Sfx_PlayFromObject(obj, 0x49);
        }
    }

    if ((*(u8 *)((u8 *)state + 0x6C) & 0x80) != 0) {
        if (timerCountDown((u8 *)state + 0x74) != 0) {
            *(f32 *)((u8 *)state + 0x70) = lbl_803E5EA8;
        }
        if (*(f32 *)((u8 *)state + 0x70) > lbl_803E5EC4) {
            *(f32 *)((u8 *)state + 0x70) -= timeDelta;
            if ((f32)lbl_803DC128 < *(f32 *)((u8 *)state + 0x70)) {
                itemPickupDoParticleFx(obj, lbl_803E5EDC, 4, 5);
            }
            if (*(f32 *)((u8 *)state + 0x70) <= lbl_803E5EC4) {
                Obj_FreeObject(obj);
            }
        } else {
            FireFlyFn_801f4f88(obj);
        }
    } else {
        isActive = 0;
        if ((*(s16 *)((u8 *)def + 0x20) == -1) || (GameBit_Get(*(s16 *)((u8 *)def + 0x20)) != 0)) {
            isActive = 1;
        }
        *(u8 *)((u8 *)state + 0x6C) =
            (u8)((*(u8 *)((u8 *)state + 0x6C) & 0x7F) | (isActive << 7));
        if ((*(u8 *)((u8 *)state + 0x6C) & 0x80) != 0) {
            *state = fn_8001CC9C(obj, 100, 0xFF, 100, 0);
        }
    }
}

void firefly_init(int obj, int def)
{
    void *state;

    state = *(void **)(obj + 0xB8);
    fn_801F4C28(obj, state);
    *(u8 *)(obj + 0x36) = 0;
    *(void **)(obj + 0xBC) = fn_801F4C04;
    ObjMsg_AllocQueue(obj, 1);
    storeZeroToFloatParam((u8 *)state + 0x74);
    if (*(s16 *)(def + 0x1A) == 0x7F) {
        s16toFloat((u8 *)state + 0x74, 0xE10);
    }
}

/* Pattern wrappers. */
int firefly_getExtraSize(void) { return 0x88; }
int firefly_getObjectTypeId(void) { return 0x0; }
void firefly_render(void) {}
void firefly_hitDetect(void) {}
void firefly_release(void) {}
void firefly_initialise(void) {}
