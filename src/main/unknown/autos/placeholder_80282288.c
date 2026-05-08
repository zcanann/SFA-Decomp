#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282288.h"

extern u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key);
extern int fn_80276A08(int state, int useExCtrl, u32 index);
extern u32 lbl_803DE278;
extern u32 lbl_803DE27C;

/*
 * Evaluate a controller expression list and cache its 14-bit result.
 */
u16 _GetInputValue(void *statePtr, void *slotPtr, u8 midiSlot, u8 midiKey)
{
    int state;
    u8 *slot;
    u8 *entry;
    u32 value;
    u32 result;
    u32 i;
    int signedMode;

    state = (int)statePtr;
    slot = (u8 *)slotPtr;
    result = 0;
    i = 0;
    entry = slot;
    signedMode = 0;
    do {
        if (slot[0x22] <= i) {
            *(s16 *)(slot + 0x20) = (s16)result;
            return result & 0xffff;
        }
        if ((entry[1] & 0x10) == 0) {
            u8 ctrl = entry[0];
            if (ctrl == 0x80 || ctrl == 1 || ctrl == 10 || (u8)(ctrl + 0x60) < 2 ||
                ctrl == 0x83) {
                if (ctrl < 0xa2 && ctrl > 0x9f) {
                    int signedValue;
                    if (state == 0) {
                        signedValue = 0;
                    } else {
                        signedValue = *(s16 *)(state + (u32)ctrl * 0xc - 0x5bc) << 1;
                        *(u8 *)(state + ctrl + 0x134) = 1;
                    }
                    value = signedValue;
                    goto signed_input;
                } else {
                    value = (inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff) - 0x2000;
                    goto signed_input;
                }
            }

            if (ctrl == 0xa3) {
                if (state == 0) {
                    value = 0;
                } else {
                    value = *(u32 *)(state + 0x158) >> 9;
                }
            } else if (ctrl < 0xa3) {
                if (ctrl < 0xa2) {
                    value = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
                } else if (state == 0) {
                    value = 0;
                } else {
                    value = (u32)*(u8 *)(state + 0x12f) << 7;
                }
            } else {
                if (ctrl > 0xa4) {
                    value = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
                } else if (state == 0) {
                    value = 0;
                } else {
                    u32 hi = lbl_803DE278 -
                             ((u32)(lbl_803DE27C < *(u32 *)(state + 0x94)) +
                              *(u32 *)(state + 0x90));
                    u32 lo = lbl_803DE27C - *(u32 *)(state + 0x94);
                    value = (u32)((((u64)hi << 32) | lo) >> 8);
                    if ((int)value > 0x3fff) {
                        value = 0x3fff;
                    }
                    *(u8 *)(state + 0xa8) = 1;
                }
            }

            value = (int)(value * (*(int *)(entry + 4) >> 1)) >> 0xf;
            if ((int)value > 0x3fff) {
                value = 0x3fff;
            }
            switch (entry[1] & 0xf) {
            case 0:
                signedMode = 0;
                result = value;
                break;
            case 1:
                if (signedMode == 0) {
                    result += value;
                    if (result > 0x3fff) {
                        result = 0x3fff;
                    }
                } else {
                    int v = result + value - 0x2000;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            case 2:
                if (signedMode == 0) {
                    result = (result * value) >> 0xe;
                    if (result > 0x3fff) {
                        result = 0x3fff;
                    }
                } else {
                    int v = (int)(value * (result - 0x2000)) >> 0xe;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            case 3:
                if (signedMode == 0) {
                    result -= value;
                    if ((int)result >= 0x4000) {
                        result = 0x3fff;
                    } else if ((int)result < 0) {
                        result = 0;
                    }
                } else {
                    int v = (result - 0x2000) - value;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            }
        } else {
            int signedValue;
            if (state == 0) {
                signedValue = 0;
            } else {
                signedValue = fn_80276A08(state, 0, entry[0]);
            }
signed_input:
            signedValue = (int)(signedValue * (*(int *)(entry + 4) >> 1)) >> 0xf;
            if (signedValue < -0x2000) {
                signedValue = -0x2000;
            } else if (signedValue > 0x1fff) {
                signedValue = 0x1fff;
            }
            switch (entry[1] & 0xf) {
            case 0:
                signedMode = 1;
                result = signedValue + 0x2000;
                break;
            case 1:
                if (signedMode == 0) {
                    result += signedValue;
                    if ((int)result >= 0x4000) {
                        result = 0x3fff;
                    } else if ((int)result < 0) {
                        result = 0;
                    }
                } else {
                    int v = result + signedValue - 0x2000;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            case 2:
                if (signedMode == 0) {
                    result = (signedValue * result) >> 0xd;
                    signedMode = 1;
                } else {
                    result = (int)((result - 0x2000) * signedValue) >> 0xd;
                }
                if ((int)result < -0x2000) {
                    result = 0xffffe000;
                } else if ((int)result > 0x1fff) {
                    result = 0x1fff;
                }
                result += 0x2000;
                break;
            case 3:
                if (signedMode == 0) {
                    result -= signedValue;
                    if ((int)result >= 0x4000) {
                        result = 0x3fff;
                    } else if ((int)result < 0) {
                        result = 0;
                    }
                } else {
                    int v = (result - 0x2000) - signedValue;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            }
        }
        entry += 8;
        i++;
    } while (1);
}

/*
 * Volume accessor: bit 0x1, slot at +0x218, cached u16 at +0x238.
 *
 * EN v1.0 Address: 0x80282078
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802824F8
 * EN v1.1 Size: 72b
 */
u16 inpGetVolume(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x1) == 0) {
        return *(u16 *)(state + 0x238);
    }
    *(u32 *)(state + 0x214) = flags & ~0x1;
    return _GetInputValue((void *)state, (void *)(state + 0x218),
                          *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Panning accessor: bit 0x2, slot at +0x23c, cached u16 at +0x25c.
 *
 * EN v1.1 Address: 0x80282540
 * EN v1.1 Size: 72b
 */
u16 inpGetPanning(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x2) == 0) {
        return *(u16 *)(state + 0x25c);
    }
    *(u32 *)(state + 0x214) = flags & ~0x2;
    return _GetInputValue((void *)state, (void *)(state + 0x23c),
                          *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}
