#include "main/dll/dll_80220608_shared.h"
#include "main/mapEventTypes.h"

#define PB_IFACE (*(int *)(*(int *)(*(int *)(state + 0x268) + 0x68)))

#pragma peephole on
#pragma scheduling on
int wcpushblock_getExtraSize(void) { return 0x288; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcpushblock_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcpushblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D54);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcpushblock_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(obj + 0x36) = 0;
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    ObjHitbox_SetStateIndex(obj, *(int *)(obj + 0x54), (s8)*(u8 *)(obj + 0xad));
    *(u8 *)(state + 0x283) = (u8)*(s16 *)(setup + 0x1a);
    *(f32 *)(state + 0x274) = lbl_803E6DA0 + *(f32 *)(setup + 0xc);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpushblock_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();
    f32 range = lbl_803E6D58;
    f32 dist;
    int *tex;
    int moved;

    if (*(void **)(state + 0x268) == 0) {
        *(int *)(state + 0x268) = ObjGroup_FindNearestObject(9, obj, &range);
        *(u8 *)(obj + 0x36) = 0;
        return;
    }
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) {
        *tex = 0;
    }
    *(u16 *)(obj + 0xb0) &= ~0x100;

    if (((PushBlockFlags *)(state + 0x285))->phase != 6) {
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            if ((u32)GameBit_Get(2066) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 6;
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x34))(
                    *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x20))(
                    obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
            } else if ((u32)GameBit_Get(2056) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 3;
            }
        } else {
            if ((u32)GameBit_Get(2067) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 6;
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x50))(
                    *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x3c))(
                    obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
            } else if ((u32)GameBit_Get(2057) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 3;
            }
        }
    }

    {
        u32 ph = ((PushBlockFlags *)(state + 0x285))->phase;
        if (ph != 3 && ph != 5) {
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                fn_80097B30(obj, 1, 3, 1, lbl_803E6D5C, lbl_803E6D60, lbl_803E6D5C, lbl_803E6D60,
                            50, 0, 0);
            } else {
                fn_80097B30(obj, 1, 1, 1, lbl_803E6D5C, lbl_803E6D60, lbl_803E6D5C, lbl_803E6D60,
                            50, 0, 0);
            }
        }
    }

    switch (((PushBlockFlags *)(state + 0x285))->phase) {
    case 0:
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            (*(void (**)(int, int, int, int))(PB_IFACE + 0x30))(
                *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
            (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x20))(
                obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
        } else {
            (*(void (**)(int, int, int, int))(PB_IFACE + 0x4c))(
                *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
            (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x3c))(
                obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
        }
        ((PushBlockFlags *)(state + 0x285))->phase = 1;
        break;
    case 1:
        {
            int a = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (a > 255) {
                a = 255;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        {
            f32 zero = lbl_803E6D64;
            *(f32 *)(obj + 0x24) = zero;
            *(f32 *)(obj + 0x2c) = zero;
        }
        if (fn_80296414(player, obj, state + 0x282) != 0) {
            u32 dir = *(u8 *)(state + 0x282);
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                if (dir == 0) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), -1, 0, PB_IFACE);
                } else if (dir == 1) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 1, 0, PB_IFACE);
                } else if (dir == 2) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, -1, PB_IFACE);
                } else if (dir == 3) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, 1, PB_IFACE);
                }
            } else {
                if (dir == 0) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), -1, 0, PB_IFACE);
                } else if (dir == 1) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 1, 0, PB_IFACE);
                } else if (dir == 2) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, -1, PB_IFACE);
                } else if (dir == 3) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, 1, PB_IFACE);
                }
            }
            if (*(f32 *)(state + 0x26c) == *(f32 *)(obj + 0xc) &&
                *(f32 *)(state + 0x270) == *(f32 *)(obj + 0x10)) {
                ;
            } else {
                ((PushBlockFlags *)(state + 0x285))->phase = 2;
            }
        }
        break;
    case 2:
        if (lbl_803E6D64 != *(f32 *)(obj + 0x24) || lbl_803E6D64 != *(f32 *)(obj + 0x2c)) {
            f32 speed = sqrtf(*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) +
                              *(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c)) -
                        lbl_803E6D68;
            if (speed < lbl_803E6D64) {
                speed = lbl_803E6D64;
            }
            dist = lbl_803E6D54 + lbl_803E6D6C * speed / lbl_803E6D70;
            if (dist > lbl_803E6D74) {
                dist = lbl_803E6D74;
            }
            Sfx_KeepAliveLoopedObjectSound(obj, 200);
            Sfx_SetObjectSfxVolume(obj, 200, (int)dist, lbl_803E6D78);
            ((PushBlockFlags *)(state + 0x285))->sfxActive = 1;
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, lbl_803E6D64,
                *(f32 *)(obj + 0x2c) * timeDelta);
        moved = 0;
        {
            u32 dir = *(u8 *)(state + 0x282);
            if (dir == 0) {
                if (*(f32 *)(obj + 0x24) < lbl_803E6D7C) {
                    *(f32 *)(obj + 0x24) = lbl_803E6D80 * timeDelta + *(f32 *)(obj + 0x24);
                }
                if (*(f32 *)(obj + 0xc) >= *(f32 *)(state + 0x26c)) {
                    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x26c);
                    moved = 1;
                }
            } else if (dir == 1) {
                if (*(f32 *)(obj + 0x24) > lbl_803E6D84) {
                    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) - lbl_803E6D80 * timeDelta;
                }
                if (*(f32 *)(obj + 0xc) <= *(f32 *)(state + 0x26c)) {
                    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x26c);
                    moved = 1;
                }
            } else if (dir == 2) {
                if (*(f32 *)(obj + 0x2c) < lbl_803E6D7C) {
                    *(f32 *)(obj + 0x2c) = lbl_803E6D80 * timeDelta + *(f32 *)(obj + 0x2c);
                }
                if (*(f32 *)(obj + 0x14) >= *(f32 *)(state + 0x270)) {
                    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x270);
                    moved = 1;
                }
            } else if (dir == 3) {
                if (*(f32 *)(obj + 0x2c) > lbl_803E6D84) {
                    *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) - lbl_803E6D80 * timeDelta;
                }
                if (*(f32 *)(obj + 0x14) <= *(f32 *)(state + 0x270)) {
                    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x270);
                    moved = 1;
                }
            }
        }
        if (*(f32 *)(obj + 0x24) > lbl_803E6D7C) {
            *(f32 *)(obj + 0x24) = lbl_803E6D7C;
        }
        if (*(f32 *)(obj + 0x24) < lbl_803E6D84) {
            *(f32 *)(obj + 0x24) = lbl_803E6D84;
        }
        if (*(f32 *)(obj + 0x2c) > lbl_803E6D7C) {
            *(f32 *)(obj + 0x2c) = lbl_803E6D7C;
        }
        if (*(f32 *)(obj + 0x2c) < lbl_803E6D84) {
            *(f32 *)(obj + 0x2c) = lbl_803E6D84;
        }
        if (moved == 0) {
            break;
        }
        {
            f32 zero = lbl_803E6D64;
            *(f32 *)(obj + 0x24) = zero;
            *(f32 *)(obj + 0x2c) = zero;
        }
        {
            u32 r = *(u8 *)(state + 0x284);
            if (r == 2) {
                ((PushBlockFlags *)(state + 0x285))->phase = 4;
                if ((s8)*(u8 *)(obj + 0xad) == 1) {
                    if (gameBitIncrement(2064) != 4) {
                        Sfx_PlayFromObject(0, 202);
                    }
                } else {
                    if (gameBitIncrement(2065) != 4) {
                        Sfx_PlayFromObject(0, 202);
                    }
                }
            } else if (r == 1) {
                ((PushBlockFlags *)(state + 0x285))->phase = 1;
                if (((PushBlockFlags *)(state + 0x285))->sfxActive != 0) {
                    ((PushBlockFlags *)(state + 0x285))->sfxActive = 0;
                    Sfx_PlayFromObject(obj, 201);
                }
            } else {
                if ((s8)*(u8 *)(obj + 0xad) == 1) {
                    GameBit_Set(2056, 1);
                } else {
                    GameBit_Set(2057, 1);
                }
            }
        }
        if (((PushBlockFlags *)(state + 0x285))->phase != 3) {
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x28))(
                    0, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280), PB_IFACE);
                (*(void (**)(int, f32, f32, int, int, int))(PB_IFACE + 0x24))(
                    obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14), state + 0x27e, state + 0x280,
                    PB_IFACE);
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x28))(
                    *(u8 *)(state + 0x283), *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    PB_IFACE);
            } else {
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x44))(
                    0, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280), PB_IFACE);
                (*(void (**)(int, f32, f32, int, int, int))(PB_IFACE + 0x40))(
                    obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14), state + 0x27e, state + 0x280,
                    PB_IFACE);
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x44))(
                    *(u8 *)(state + 0x283), *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    PB_IFACE);
            }
        }
        break;
    case 3:
        ObjHits_DisableObject(obj);
        if (*(u8 *)(obj + 0x36) == 255) {
            Sfx_PlayFromObject(obj, 203);
        }
        {
            int a = *(u8 *)(obj + 0x36) - framesThisStep * 8;
            if (a < 0) {
                a = 0;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            if (fn_802242A8(obj, state, Obj_GetPlayerObject()) != 0) {
                if ((s8)*(u8 *)(obj + 0xad) == 1) {
                    (*(void (**)(int, int, int, int))(PB_IFACE + 0x30))(
                        *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                    (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x20))(
                        obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                        (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
                } else {
                    (*(void (**)(int, int, int, int))(PB_IFACE + 0x4c))(
                        *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                    (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x3c))(
                        obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                        (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
                }
                ((PushBlockFlags *)(state + 0x285))->phase = 5;
            }
        }
        break;
    case 5:
        if (*(u8 *)(obj + 0x36) == 0) {
            ObjHits_EnableObject(obj);
            Sfx_PlayFromObject(0, 204);
        }
        {
            int a = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (a > 255) {
                a = 255;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        if (*(u8 *)(obj + 0x36) >= 0xff) {
            ((PushBlockFlags *)(state + 0x285))->phase = 1;
        }
        break;
    case 6:
        *(u8 *)(obj + 0x36) = 255;
    case 4:
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) {
            *tex = 256;
        }
        *(u16 *)(obj + 0xb0) |= 256;
        break;
    }

    *(u16 *)(state + 0x27c) = lbl_803E6D88 * timeDelta + (f32)(u32) * (u16 *)(state + 0x27c);
    *(f32 *)(state + 0x278) =
        lbl_803E6D8C * fn_80293E80(lbl_803E6D90 * (f32)(u32) * (u16 *)(state + 0x27c) / lbl_803E6D94);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x274) + *(f32 *)(state + 0x278);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_802251B4(int obj, int state)
{
    int scratch;

    (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&scratch);
    switch (*(u8 *)(state + 0xc)) {
    case 6:
        gameTimerInit(0x1d, 0x50);
        timerSetToCountUp();
        *(u8 *)(state + 0xc) = 4;
        break;
    case 4:
        if ((u32)GameBit_Get(0x2a5) != 0) {
            int player;
            GameBit_Set(0x274, 1);
            GameBit_Set(0xef1, 0);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
            *(u16 *)(state + 0x1a) |= 0x40;
            *(u8 *)(state + 0xc) = 0;
            Sfx_PlayFromObject(0, 0x7e);
            gameTimerStop();
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x274, 0);
            GameBit_Set(0xef1, 0);
            if ((u32)GameBit_Get(0x34d) == 0) {
                GameBit_Set(0x2b1, 0);
                GameBit_Set(0x226, 1);
                GameBit_Set(0x2a6, 1);
                GameBit_Set(0x206, 1);
                GameBit_Set(0x25f, 1);
                *(u8 *)(state + 0xc) = 0;
            }
        }
        break;
    default:
        if (!(*(u16 *)(state + 0x1a) & 0x40) && (u32)GameBit_Get(0x2b1) != 0) {
            GameBit_Set(0xef1, 1);
            GameBit_Set(0xe6d, 0);
            if ((u32)GameBit_Get(0x204) != 0) {
                GameBit_Set(0x226, 0);
                GameBit_Set(0x2a6, 0);
                GameBit_Set(0x206, 0);
                GameBit_Set(0x25f, 0);
                GameBit_Set(0x274, 1);
                *(u8 *)(state + 0xc) = 6;
            }
        }
        break;
    }

    if (!(*(u16 *)(state + 0x1a) & 0x10)) {
        if ((u8)GameBit_Get(0x810) == 4) {
            GameBit_Set(0x812, 1);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x10;
        } else if ((u32)GameBit_Get(0x808) != 0) {
            if (*(f32 *)(state + 8) <= lbl_803E6DA8) {
                GameBit_Set(0x810, 0);
                memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
                *(f32 *)(state + 8) = lbl_803E6DAC;
            }
        }
        if (*(f32 *)(state + 8) > lbl_803E6DA8) {
            *(f32 *)(state + 8) -= timeDelta;
            if (*(f32 *)(state + 8) <= lbl_803E6DA8)
                GameBit_Set(0x808, 0);
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x20)) {
        if ((u8)GameBit_Get(0x811) == 4) {
            GameBit_Set(0x813, 1);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x20;
        } else if ((u32)GameBit_Get(0x809) != 0) {
            if (*(f32 *)(state + 4) <= lbl_803E6DA8) {
                GameBit_Set(0x811, 0);
                memcpy(lbl_803AD298, lbl_8032B088, 0x40);
                *(f32 *)(state + 4) = lbl_803E6DAC;
            }
        }
        if (*(f32 *)(state + 4) > lbl_803E6DA8) {
            *(f32 *)(state + 4) -= timeDelta;
            if (*(f32 *)(state + 4) <= lbl_803E6DA8)
                GameBit_Set(0x809, 0);
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x80)) {
        if ((u32)GameBit_Get(0xc58) != 0 && (u32)GameBit_Get(0xc59) != 0 &&
            (u32)GameBit_Get(0xc5a) != 0) {
            GameBit_Set(0x205, 1);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x80;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b40 &&
                   (u32)GameBit_Get(0xc58) != 0) {
            Sfx_PlayFromObject(0, 0x109);
            ((WclevelcontFlags *)(state + 0x14))->b40 = 1;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b20 &&
                   (u32)GameBit_Get(0xc59) != 0) {
            Sfx_PlayFromObject(0, 0x109);
            ((WclevelcontFlags *)(state + 0x14))->b20 = 1;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b18 &&
                   (u32)GameBit_Get(0xc5a) != 0) {
            Sfx_PlayFromObject(0, 0x109);
            ((WclevelcontFlags *)(state + 0x14))->b18 = 1;
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x100)) {
        if ((u32)GameBit_Get(0xbcf) != 0) {
            int player;
            GameBit_Set(0xbc8, 0);
            GameBit_Set(0x2f0, 1);
            GameBit_Set(0xeec, 0);
            GameBit_Set(0xbd0, 0);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x100;
        }
    }

    *(u16 *)(state + 0x1a) &= ~1;
    if ((u32)GameBit_Get(0xc92) != 0) {
        GameBit_Set(0x4e4, 0);
        GameBit_Set(0x4e5, 0);
        if ((u32)GameBit_Get(0x4e3) == 0xff)
            GameBit_Set(0x4e3, randomGetRange(6, 7));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpushblock_updateLevelControlState(int obj, int state)
{
    if (*(u16 *)(state + 0x1a) & 0x2)
        return;
    *(u8 *)(state + 0xd) = *(u8 *)(state + 0xc);
    switch (*(u8 *)(state + 0xc)) {
    case 1:
        if (*(u16 *)(state + 0x1a) & 0x1) {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedd, 1);
        } else if ((u32)GameBit_Get(0x7f9) != 0) {
            *(u16 *)(state + 0x1a) |= 0x4;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7fa) != 0)
                Sfx_PlayFromObject(0, 0x7e);
            else
                Sfx_PlayFromObject(0, 0x109);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            if ((u32)GameBit_Get(0x7fa) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                *(u8 *)(state + 0xc) = 3;
            } else {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 0xc) = 0;
            }
            *(u16 *)(state + 0x1a) |= 0x2;
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x7ef, 0);
            GameBit_Set(0x7ed, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            *(u8 *)(state + 0xc) = 0;
        }
        break;
    case 2:
        if (*(u16 *)(state + 0x1a) & 0x1) {
            gameTimerInit(0x1d, 0x50);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedc, 1);
        } else if ((u32)GameBit_Get(0x7fa) != 0) {
            *(u16 *)(state + 0x1a) |= 0x8;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7f9) != 0)
                Sfx_PlayFromObject(0, 0x7e);
            else
                Sfx_PlayFromObject(0, 0x109);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            if ((u32)GameBit_Get(0x7f9) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                *(u8 *)(state + 0xc) = 3;
            } else {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 0xc) = 0;
            }
            *(u16 *)(state + 0x1a) |= 0x2;
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x7f0, 0);
            GameBit_Set(0x7ee, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            *(u8 *)(state + 0xc) = 0;
        }
        break;
    case 3:
        if ((u32)GameBit_Get(0xcac) != 0) {
            int player;
            GameBit_Set(0xda9, 0);
            GameBit_Set(0xc37, 1);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
            *(u8 *)(state + 0xc) = 7;
        }
        break;
    case 7:
        break;
    default:
        if (!(*(u16 *)(state + 0x1a) & 0x4) && (u32)GameBit_Get(0x7ed) != 0) {
            GameBit_Set(0x7ef, 1);
            *(f32 *)(state + 0) = lbl_803E6DB0;
            *(u8 *)(state + 0xc) = 1;
            *(u16 *)(state + 0x1a) |= 0x2;
            break;
        }
        if (!(*(u16 *)(state + 0x1a) & 0x8) && (u32)GameBit_Get(0x7ee) != 0) {
            GameBit_Set(0x7f0, 1);
            *(f32 *)(state + 0) = lbl_803E6DB0;
            *(u8 *)(state + 0xc) = 2;
            *(u16 *)(state + 0x1a) |= 0x2;
        }
        break;
    }
    *(u16 *)(state + 0x1a) &= ~1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcpushblock_levelControlTriggerCallback(int obj, int p2, int p3)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(u16 *)(state + 0x1a) |= 0x1;
    *(u16 *)(state + 0x1a) &= ~0x2;
    if (*(u8 *)(state + 0xd) == 1) {
        f32 t = *(f32 *)(state + 0) - timeDelta;
        *(f32 *)(state + 0) = t;
        if (t <= lbl_803E6DA8) {
            int player;
            GameBit_Set(0x7f7, 1);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
        }
    } else if (*(u8 *)(state + 0xd) == 2) {
        f32 t = *(f32 *)(state + 0) - timeDelta;
        *(f32 *)(state + 0) = t;
        if (t <= lbl_803E6DA8) {
            int player;
            GameBit_Set(0x802, 1);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
        }
    }
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        if (*(u8 *)(p3 + (i + 0x81)) == 1)
            *(u8 *)(state + 0xc) = 6;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80225D2C(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0) {
        int bi = b;
        if (dx == -1) {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + lbl_803E6DBC);
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        } else {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + lbl_803E6DA8);
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx) {
            if (lbl_803AD298[i][b] != 0) {
                if (lbl_803AD298[i][b] <= 4) {
                    f32 pz, px;
                    i += dx;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    } else {
        int ai = a;
        if (dy == -1) {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + lbl_803E6DBC);
            b += 1;
            limit = 8;
        } else {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + lbl_803E6DA8);
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy) {
            if (lbl_803AD298[a][i] != 0) {
                if (lbl_803AD298[a][i] <= 4) {
                    f32 pz, px;
                    i += dy;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
}
#pragma scheduling reset
#pragma peephole reset

#undef PB_IFACE
