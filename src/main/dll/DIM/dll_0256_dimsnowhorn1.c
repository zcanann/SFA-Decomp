#include "main/dll/DIM/dll_802B9780_shared.h"

void DIMSnowHorn1_func23(void) {}

int fn_802B9784(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
int fn_802BA6E0(int obj, int state)
{
    f32 k = lbl_803E8234;
    int idx;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        idx = randomGetRange(0, 1);
        *(f32 *)((char *)state + 0x2a0) = lbl_803DC740[idx];
        ObjAnim_SetCurrentMove(obj, lbl_803DC73C[idx], lbl_803E8234, 0);
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        return -2;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
            randomGetRange(0, 2) + 6, obj, -1);
        buttonDisable(0, 0x100);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BABB4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);

    switch (*(u8 *)((char *)inner + 0xa8c)) {
    case 0:
        if (GameBit_Get(0xf3)) {
            *(u8 *)((char *)inner + 0xa8e) |= 0x20;
        }
        return 2;
    case 5:
        return 3;
    case 4:
        if (GameBit_Get(0x1db)) return 8;
        return 6;
    case 1:
        if (GameBit_Get(0x16f)) return 8;
        if (GameBit_Get(0x28)) return 7;
        if (GameBit_Get(0x27)) return 7;
        return 6;
    case 3:
        return 8;
    default:
        return 8;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BA938(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k = lbl_803E8234;
    s16 v;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;

    if (*(s16 *)((char *)obj + 0xa0) != lbl_803DC748) {
        ObjAnim_SetCurrentMove(obj, lbl_803DC748, k, 0);
    }

    *(s16 *)((char *)inner + 0xa84) = randomGetRange(0x4b0, 0x960);
    v = *(s16 *)((char *)inner + 0xa84) - (int)fv;
    *(s16 *)((char *)inner + 0xa84) = v;
    if (v <= 0) {
        return -4;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
            randomGetRange(0, 2) + 6, obj, -1);
        buttonDisable(0, 0x100);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BA7EC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k = lbl_803E8234;
    int idx;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        idx = randomGetRange(0, 1);
        *(f32 *)((char *)state + 0x2a0) = lbl_803DC740[idx];
        ObjAnim_SetCurrentMove(obj, lbl_803DC73C[idx], lbl_803E8234, 0);
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        return -1;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        if (*(u8 *)((char *)inner + 0xa8e) & 0x20) {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                randomGetRange(0, 2) + 6, obj, -1);
        } else {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                5, obj, -1);
        }
        buttonDisable(0, 0x100);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BAA54(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k = lbl_803E8234;
    s16 v;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
        if (*(s16 *)((char *)obj + 0xa0) != lbl_803DC748) {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, lbl_803E8234, 0);
        }
        *(s16 *)((char *)inner + 0xa84) = randomGetRange(0x4b0, 0x960);
    }

    v = *(s16 *)((char *)inner + 0xa84) - (int)fv;
    *(s16 *)((char *)inner + 0xa84) = v;
    if (v <= 0) {
        return -3;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        if (*(u8 *)((char *)inner + 0xa8e) & 0x20) {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                randomGetRange(0, 2) + 6, obj, -1);
        } else {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                5, obj, -1);
        }
        buttonDisable(0, 0x100);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802B978C(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub = *(int *)((char *)obj + 0x54);
    f32 k = lbl_803E8234;

    *(u32 *)((char *)state) |= 0x200000;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(u8 *)((char *)inner + 0xa8e) &= ~0x8;
        *(s16 *)((char *)sub + 0x60) |= 0x200;
        ObjAnim_SetCurrentMove(obj, 0x204, k, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8238;
        Sfx_PlayFromObject(obj, 0x3b3);
    }
    if ((*(s16 *)((char *)sub + 0x60) & 0x200) && (*(s8 *)((char *)sub + 0xad) & 2)) {
        *(u8 *)((char *)inner + 0xa8e) |= 0x8;
    }
    if (*(u8 *)((char *)inner + 0xa8e) & 0x8) {
        *(u8 *)((char *)sub + 0x6e) = 0;
        *(u8 *)((char *)sub + 0x6f) = 0;
        *(s16 *)((char *)sub + 0x60) &= ~0x200;
    } else {
        *(u8 *)((char *)sub + 0x6e) = 0xb;
        *(u8 *)((char *)sub + 0x6f) = 1;
        *(s16 *)((char *)sub + 0x60) |= 0x200;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E823C) {
        return 8;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802B9CC4(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int near;
    f32 sp = lbl_803E8240;
    s16 d;

    near = ObjGroup_FindNearestObject(0x13, obj, &sp);
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s16 *)((char *)state + 0x334) < *(s16 *)((char *)inner + 0xa86) ||
        lbl_803E8234 == *(f32 *)((char *)state + 0x298)) {
        return 8;
    }

    if (*(s16 *)((char *)state + 0x336) < -0xaf) {
        *(s16 *)((char *)state + 0x336) = -*(s16 *)((char *)state + 0x336);
    }
    d = *(s16 *)((char *)state + 0x336);
    if (d > 0) {
        if (*(s16 *)((char *)obj + 0xa0) != 0x201) {
            ObjAnim_SetCurrentMove(obj, 0x201, lbl_803E8234, 0);
        }
    } else if (d <= 0) {
        if (*(s16 *)((char *)obj + 0xa0) != 0x200) {
            ObjAnim_SetCurrentMove(obj, 0x200, lbl_803E8234, 0);
        }
    }
    *(f32 *)((char *)state + 0x2a0) = lbl_803E8278;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 8);

    if (*(int *)((char *)state + 0x31c) & 0x100) {
        if (near == 0 || (*(u8 *)((char *)near + 0xaf) & 4) == 0) {
            return 0xc;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802B9E38(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);

    *(u32 *)((char *)state) |= 0x200000;
    *(u8 *)((char *)obj + 0xaf) |= 0x8;

    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x206:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            if (*(f32 *)((char *)state + 0x2a0) > lbl_803E8234) {
                ObjAnim_SetCurrentMove(obj, 0x205, lbl_803E8234, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
            } else {
                return 8;
            }
        }
        if (*(s16 *)((char *)inner + 0xa88) != 0 &&
            *(f32 *)((char *)state + 0x2a0) > lbl_803E8234) {
            if (*(int *)((char *)state + 0x31c) != 0 ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x290) ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x28c)) {
                *(f32 *)((char *)state + 0x2a0) = -*(f32 *)((char *)state + 0x2a0);
            }
        }
        break;
    case 0x205:
        if (*(s16 *)((char *)inner + 0xa88) != 0) {
            if (*(int *)((char *)state + 0x31c) != 0 ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x290) ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x28c)) {
                ObjAnim_SetCurrentMove(obj, 0x207, lbl_803E8234, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E8280;
            }
        }
        break;
    case 0x207:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            return 8;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0x206, lbl_803E8234, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8280;
        break;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802B9FC0(int obj, int state)
{
    void *near;
    int inner;
    f32 sp = lbl_803E8240;
    f32 fz;

    near = (void *)ObjGroup_FindNearestObject(0x13, obj, &sp);
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)obj + 0xaf) |= 0x8;
    fz = lbl_803E8234;
    *(f32 *)((char *)state + 0x294) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(u32 *)((char *)state) |= 0x200000;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x338) = 0;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
        *(f32 *)((char *)state + 0x2b8) = lbl_803E8284;
        if (*(s16 *)((char *)obj + 0xa0) != lbl_803DC748) {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, fz, 0);
        }
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x209:
    case 0x20a:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, lbl_803E8234, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
        }
        break;
    }
    if (*(f32 *)((char *)state + 0x298) < lbl_803E824C) {
        *(s16 *)((char *)state + 0x334) = 0;
        *(s16 *)((char *)state + 0x336) = 0;
        *(f32 *)((char *)state + 0x298) = lbl_803E8234;
    }
    {
        f32 v = *(f32 *)((char *)state + 0x29c);
        if (v > lbl_803E8234 && *(f32 *)((char *)state + 0x298) > lbl_803E8234 &&
            *(s16 *)((char *)state + 0x334) >= *(s16 *)((char *)inner + 0xa86)) {
            return 0xa;
        }
        if (v > lbl_803E8288 && *(f32 *)((char *)state + 0x298) > lbl_803E8288 &&
            *(s16 *)((char *)state + 0x334) < *(s16 *)((char *)inner + 0xa86)) {
            return 0xb;
        }
    }
    if (*(int *)((char *)state + 0x31c) & 0x100) {
        if (near == NULL || (*(u8 *)((char *)near + 0xaf) & 4) == 0) {
            return 0xc;
        }
    }
    if (GameBit_Get(0x3e3) != 0) {
        if (RandomTimer_UpdateRangeTrigger(inner + 0xd04, lbl_803E8244, lbl_803E8248) != 0) {
            Sfx_PlayFromObject(obj, 0x43a);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BA1D4(int obj, int state)
{
    int inner;
    f32 fz;

    fz = lbl_803E8234;
    *(f32 *)((char *)state + 0x294) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(u32 *)((char *)state) |= 0x200000;
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    *(u8 *)((char *)obj + 0xe4) = GameBit_Get(0x170) != 0;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
        if (*(s16 *)((char *)obj + 0xa0) != 0x13) {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E8234, 0);
        }
    }
    if (*(u8 *)((char *)obj + 0xaf) & 4) {
        if ((*(int (*)(int))(*(int *)(*gGameUIInterface + 0x20)))(0x170) != 0) {
            u8 bit170 = GameBit_Get(0x170);
            if (GameBit_Get(0x28) == 0) {
                switch (bit170) {
                case 1:
                    GameBit_Set(0x28, 1);
                    *(u8 *)((char *)inner + 0xa8d) = 2;
                    break;
                case 2:
                    *(u8 *)((char *)inner + 0xa8d) = 4;
                    GameBit_Set(0x16f, 1);
                    break;
                }
            } else {
                *(u8 *)((char *)inner + 0xa8d) = 4;
                GameBit_Set(0x16f, 1);
            }
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                *(u8 *)((char *)inner + 0xa8d), obj, -1);
            GameBit_Set(0x170, GameBit_Get(0x170) - bit170);
            buttonDisable(0, 0x100);
        } else {
            if (*(u8 *)((char *)obj + 0xaf) & 1) {
                if (GameBit_Get(0x28) != 0) {
                    *(u8 *)((char *)inner + 0xa8d) = 3;
                } else {
                    *(u8 *)((char *)inner + 0xa8d) = 1;
                }
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                    *(u8 *)((char *)inner + 0xa8d), obj, -1);
                buttonDisable(0, 0x100);
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BA3EC(int obj, int state)
{
    int inner;
    int id_a, id_b, id_c, id_d;
    void *player;
    int bit_a, bit_b;
    int *o1;
    int *o2;
    int v;
    f32 f;

    f = lbl_803E8234;
    *(f32 *)((char *)state + 0x294) = f;
    *(f32 *)((char *)state + 0x284) = f;
    *(f32 *)((char *)state + 0x280) = f;
    *(f32 *)((char *)obj + 0x24) = f;
    *(f32 *)((char *)obj + 0x28) = f;
    *(f32 *)((char *)obj + 0x2c) = f;
    *(int *)state |= 0x200000;

    inner = *(int *)((char *)obj + 0xb8);
    player = (void *)Obj_GetPlayerObject();
    switch (*(u8 *)((char *)inner + 0xa8c)) {
    case 1:
        id_a = 0x1602;
        id_b = 0x454bc;
        id_c = 0x454b8;
        id_d = 0x454b9;
        bit_a = 0x172;
        bit_b = 0x9ed;
        break;
    case 4:
        id_a = 0x4963b;
        id_b = 0x4963c;
        id_c = 0x4963d;
        id_d = 0x4963e;
        bit_a = 0x8f9;
        bit_b = 0x85d;
        break;
    }

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
        if (*(s16 *)((char *)obj + 0xa0) != 0x13) {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E8234, 0);
        }
    }

    if (GameBit_Get(bit_a) != 0 && GameBit_Get(bit_b) != 0 && player != NULL &&
        Vec_distance((char *)player + 0x18, (char *)obj + 0x18) < lbl_803E828C) {
        switch (*(u8 *)((char *)inner + 0xa8c)) {
        case 1:
            *(u8 *)((char *)inner + 0xa8d) = 0;
            GameBit_Set(0x245, 1);
            GameBit_Set(0x27, 1);
            break;
        case 4:
            *(u8 *)((char *)inner + 0xa8d) = 9;
            GameBit_Set(0x1db, 1);
            break;
        }
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
            *(u8 *)((char *)inner + 0xa8d), obj, -1);
        buttonDisable(0, 0x100);
    } else {
        *(u8 *)((char *)obj + 0xaf) |= 8;
        v = *(u8 *)((char *)inner + 0xa91);
        switch (v) {
        case 1:
            if (Vec_distance((char *)player + 0x18, (char *)obj + 0x18) < lbl_803E8290) {
                o1 = ObjList_FindObjectById(id_a);
                if (o1 != NULL) fn_8014C63C(o1);
                o1 = ObjList_FindObjectById(id_b);
                if (o1 != NULL) fn_8014C63C(o1);
                *(u8 *)((char *)inner + 0xa91) = 2;
            }
            break;
        case 0:
        case 2:
            if (v != 0 &&
                Vec_distance((char *)player + 0x18, (char *)obj + 0x18) <= lbl_803E8240) {
                if (RandomTimer_UpdateRangeTrigger((int)((char *)inner + 0xd08),
                                                   lbl_803E8294, lbl_803E8284) != 0) {
                    Sfx_PlayFromObject(obj, 0x375);
                }
            } else {
                o1 = ObjList_FindObjectById(id_a);
                o2 = ObjList_FindObjectById(id_c);
                if (o1 != NULL && o2 != NULL) fn_8014C66C(o1, (int)o2);
                o1 = ObjList_FindObjectById(id_b);
                o2 = ObjList_FindObjectById(id_d);
                if (o1 != NULL && o2 != NULL) fn_8014C66C(o1, (int)o2);
                *(u8 *)((char *)inner + 0xa91) = 1;
            }
            break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802B98F0(int obj, int state, f32 t)
{
    int near;
    int inner;
    int phase;
    int changed;
    int useNormal;
    f32 v;
    f32 target;
    f32 f2;
    f32 blend;
    f32 nearDist;
    s16 moveId;

    nearDist = lbl_803E8240;
    near = ObjGroup_FindNearestObject(0x13, obj, &nearDist);
    inner = *(int *)((char *)obj + 0xb8);
    if (GameBit_Get(0x3e3) != 0) {
        if (RandomTimer_UpdateRangeTrigger(inner + 0xd04, lbl_803E8244, lbl_803E8248) != 0) {
            Sfx_PlayFromObject(obj, 0x43a);
        }
    }
    *(int *)((char *)state + 0) |= 0x200000;
    if (*(f32 *)((char *)state + 0x298) < lbl_803E824C) {
        *(s16 *)((char *)state + 0x334) = 0;
        *(s16 *)((char *)state + 0x336) = 0;
        *(f32 *)((char *)state + 0x298) = lbl_803E8234;
    }
    if (*(s16 *)((char *)state + 0x334) >= 0x5a) {
        return 8;
    }

    *(s16 *)((char *)obj + 0) = (s16)(s32)(
        lbl_803E8250 * ((f32)(s16) * (s16 *)((char *)state + 0x336) * t / lbl_803E8254) +
        (f32)(s16) * (s16 *)((char *)obj + 0));

    v = *(f32 *)((char *)state + 0x298);
    if (v < lbl_803E8234) {
        v = lbl_803E8234;
    }
    if (v > lbl_803E8258) {
        v = lbl_803E8258;
    }
    if (*(s16 *)((char *)inner + 0xa88) == 0) {
        v = lbl_803E8234;
    }
    target = lbl_803E825C * v;
    if (target < lbl_803E8234) {
        target = lbl_803E8234;
    }
    *(f32 *)((char *)state + 0x294) =
        t * ((target - *(f32 *)((char *)state + 0x294)) / *(f32 *)((char *)state + 0x2b8)) +
        *(f32 *)((char *)state + 0x294);

    if (*(s16 *)((char *)obj + 2) > 0) {
        target = target -
                 lbl_803E8260 * fn_80293E80(lbl_803E8264 * (f32)(s16) * (s16 *)((char *)obj + 2) /
                                            lbl_803E8268);
    } else {
        target = target -
                 lbl_803E826C * fn_80293E80(lbl_803E8264 * (f32)(s16) * (s16 *)((char *)obj + 2) /
                                            lbl_803E8268);
    }
    if (target < lbl_80335128[2]) {
        target = lbl_80335128[2];
    }
    *(f32 *)((char *)state + 0x280) =
        t * ((target - *(f32 *)((char *)state + 0x280)) / *(f32 *)((char *)state + 0x2b8)) +
        *(f32 *)((char *)state + 0x280);

    changed = 0;
    blend = *(f32 *)((char *)obj + 0x98);
    moveId = *(s16 *)((char *)obj + 0xa0);
    phase = 0;
    while (phase < 2 && (&lbl_803DC748)[phase] != moveId) {
        phase++;
    }
    if (phase >= 2) {
        phase = 0;
    }
    if (moveId == 0x208) {
        phase = 1;
    }

    f2 = *(f32 *)((char *)state + 0x294);
    if (f2 < lbl_80335128[phase * 2]) {
        if (phase == 1) {
            return 8;
        }
        phase--;
        changed = 1;
    } else if (f2 >= lbl_80335128[phase * 2 + 1]) {
        if (phase == 0) {
            blend = lbl_803E8234;
        }
        phase++;
        changed = 1;
    }

    useNormal = 1;
    if (*(s8 *)((char *)state + 0x346) != 0 && moveId == 0x208) {
        changed = 1;
        useNormal = 0;
    }
    if (changed != 0) {
        if (phase == 1 && useNormal != 0) {
            ObjAnim_SetCurrentMove(obj, 0x208, blend, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, (&lbl_803DC748)[phase], blend, 0);
        }
    }

    ObjAnim_SampleRootCurvePhase(*(f32 *)((char *)state + 0x280), (ObjAnimComponent *)obj,
                                 (f32 *)((char *)state + 0x2a0));
    if ((*(int *)((char *)state + 0x31c) & 0x100) == 0) {
        return 0;
    }
    if (near != 0 && (*(u8 *)((char *)near + 0xaf) & 0x4)) {
        return 0;
    }
    return 0xc;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Empty stub.
 */
void DIMSnowHorn1_func21(void) {}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns 0.
 */
int DIMSnowHorn1_func20(void) { return 0; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns floored neg-velocity-Y in *out, or a constant if mode != 10;
 * also returns f1 = constant.
 */
f32 DIMSnowHorn1_func19(int obj, f32 *out)
{
    int state = *(int *)(obj + 0xb8);
    if (*(s16 *)(state + 0x274) == 0xa) {
        *out = -*(f32 *)(state + 0x2a0);
    } else {
        *out = lbl_803E827C;
    }
    return lbl_803E8234;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Sets *out_f = 0.0f, *out_i = 0.
 */
void DIMSnowHorn1_func18(void *unused, f32 *out_f, int *out_i)
{
    (void)unused;
    *out_f = lbl_803E8234;
    *out_i = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Stores arg at obj->state[0xa8a] (low byte).
 */
void DIMSnowHorn1_func17(int obj, int value)
{
    u8 mode = (u8)value;
    *(u8 *)(*(int *)(obj + 0xb8) + 0xa8a) = mode;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns 0.
 */
int DIMSnowHorn1_func16(void) { return 0; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void DIMSnowHorn1_func15(s16 *packed, undefined4 outX, undefined4 outY, undefined4 outZ)
{
    extern void setMatrixFromObjectPos(void *matrix, void *packedTransform);
    extern void Matrix_TransformPoint(double x, double y, double z, void *matrix, undefined4 outX, undefined4 outY, undefined4 outZ);
    struct {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } transform;
    f32 matrix[16];

    transform.x = *(f32 *)(packed + 6);
    transform.y = *(f32 *)(packed + 8);
    transform.z = *(f32 *)(packed + 10);
    transform.rotX = packed[0];
    transform.rotY = packed[1];
    transform.rotZ = packed[2];
    transform.scale = lbl_803E8258;
    setMatrixFromObjectPos(matrix, &transform);
    Matrix_TransformPoint(lbl_803E8234, lbl_803E8298, lbl_803E829C, matrix, outX, outY, outZ);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns 2 if state->[0xa8f] != 0, else 1.
 */
int DIMSnowHorn1_func14(int obj)
{
    if (*(u8 *)(*(int *)(obj + 0xb8) + 0xa8f) != 0) {
        return 2;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * If bit 1 of state->[0xa8e] is set, set GameBit 0x3e3 to 0, clear
 * the bit, and return 1. Otherwise return 0.
 */
int DIMSnowHorn1_render2(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if ((*(u8 *)(state + 0xa8e) & 0x2) != 0) {
        GameBit_Set(0x3e3, 0);
        *(u8 *)(state + 0xa8e) = (u8)(*(u8 *)(state + 0xa8e) & ~0x2);
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Read 3 floats from state into the 3 output pointers.
 */
void DIMSnowHorn1_modelMtxFn(int obj, f32 *out_x, f32 *out_y, f32 *out_z)
{
    int state = *(int *)(obj + 0xb8);
    *out_x = *(f32 *)(state + 0x9e8);
    *out_y = *(f32 *)(state + 0x9ec);
    *out_z = *(f32 *)(state + 0x9f0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns 1 if state->[0xa90] != 0, else 2.
 */
int gdev_cc_initinterrupts(int obj)
{
    if (*(u8 *)(*(int *)(obj + 0xb8) + 0xa90) != 0) {
        return 1;
    }
    return 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int ddh_cc_initinterrupts(int obj, undefined4 unused, int setup)
{
    int state;
    int animState;
    int i;
    f32 fz;

    (void)unused;
    state = *(int *)(obj + 0xb8);
    *(u8 *)(obj + 0xaf) |= 8;

    switch (*(u8 *)(state + 0xa8c)) {
        case 0:
            *(u8 *)(setup + 0x56) = 0;
            if (*(s16 *)(obj + 0xb4) == -1) {
                for (i = 0; i < (int)(u32)*(u8 *)(setup + 0x8b); i++) {
                    GameBit_Set(0x17b, 1);
                    *(u8 *)(state + 0xa8e) |= 0x20;
                }
            }
            (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, state, 1);
            break;
        case 5:
            *(u8 *)(setup + 0x56) = 0;
            (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, state, 2);
            break;
        case 4:
            *(u8 *)(setup + 0x56) = 0;
            (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, state, 7);
            break;
        case 1:
            *(u8 *)(setup + 0x56) = 0;
            if (*(s16 *)(obj + 0xb4) != -1) {
                switch (*(u8 *)(state + 0xa8d)) {
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                        animState = 6;
                        break;
                    case 4:
                    default:
                        animState = 7;
                        break;
                }
            } else {
                animState = 7;
            }
            (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, state, animState);
            break;
        case 3:
            *(u8 *)(setup + 0x56) = 0;
            *(u8 *)(state + 0x27a) = 1;
            (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, state, 7);
            break;
        default:
            break;
    }

    (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, state + 4);
    fz = lbl_803E8234;
    *(f32 *)(state + 0x294) = fz;
    *(f32 *)(state + 0x284) = fz;
    *(f32 *)(state + 0x280) = fz;
    *(f32 *)(obj + 0x24) = fz;
    *(f32 *)(obj + 0x28) = fz;
    *(f32 *)(obj + 0x2c) = fz;
    return (u32)(-*(s8 *)(setup + 0x56) | *(s8 *)(setup + 0x56)) >> 0x1f;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void DIMSnowHorn1_func22(int obj, f32 scale)
{
    void *pathMtx;
    struct {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } transform;
    f32 x;
    f32 y;
    f32 z;

    pathMtx = (void *)ObjPath_GetPointModelMtx(obj, 1);
    ObjPath_GetPointLocalPosition(obj, 1, &x, &y, &z);
    transform.x = x;
    transform.y = y;
    transform.z = z;
    transform.rotX = 0;
    transform.rotY = 0;
    transform.rotZ = 0;
    transform.scale = scale / *(f32 *)(*(int *)(obj + 0x50) + 4);
    setMatrixFromObjectPos((f32 *)lbl_803DB0F0, (s16 *)&transform);
    mtx44_mult(lbl_803DB0F0, pathMtx, lbl_803DB0F0);
    fn_8003B950(lbl_803DB0F0);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int DIMSnowHorn1_setScale(int obj)
{
    int state;
    f32 range;
    void *nearest;

    state = *(int *)(obj + 0xb8);
    range = lbl_803E8240;

    switch (*(u8 *)(state + 0xa8c)) {
    case 0:
    case 5:
        return 0;
    }
    if (*(s16 *)(state + 0x274) != 7) {
        return 0;
    }
    if (*(void **)(obj + 0xc0) != NULL) {
        return 0;
    }

    nearest = (void *)ObjGroup_FindNearestObject(0x13, obj, &range);
    if ((nearest != NULL) && ((*(u8 *)((int)nearest + 0xaf) & 4) != 0)) {
        buttonDisable(0, 0x100);
        return 1;
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_802BB998(int obj, int pointState, int inputState)
{
    extern u16 audioPickSoundEffect_8006ed24(u8 id, int bank);
    extern void Sfx_PlayFromObject(int obj, u16 sfxId);
    u8 flags;
    u8 pointIndex;
    u8 count;
    s32 inputFlags;
    u16 sfxId;
    struct {
        undefined4 unk0;
        undefined4 unk4;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } args;

    flags = 0;
    inputFlags = *(s32 *)(inputState + 0x314);
    if ((inputFlags & 2) != 0) {
        flags |= 1;
    }
    if ((inputFlags & 4) != 0) {
        flags |= 2;
    }

    pointIndex = 0;
    while (flags != 0) {
        if ((flags & 1) != 0) {
            args.x = *(f32 *)(pointState + 0x9b0 + pointIndex * 0xc);
            args.y = *(f32 *)(pointState + 0x9b4 + pointIndex * 0xc);
            args.z = *(f32 *)(pointState + 0x9b8 + pointIndex * 0xc);
            args.scale = lbl_803E82A0;

            count = (u8)randomGetRange(2, 6);
            while (count != 0) {
                (*(void (**)(int, int, void *, int, int, int))(*(int *)gPartfxInterface + 8))(
                    obj, randomGetRange(0, 1) + 0x1f9, &args, 0x10001, -1, 0);
                count--;
            }

            sfxId = audioPickSoundEffect_8006ed24((u8)(s8)*(u8 *)(inputState + 0xbc), 9);
            Sfx_PlayFromObject(obj, sfxId);
            doRumble(lbl_803E8244);
        }
        flags >>= 1;
        pointIndex++;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns 0xd0c.
 */
int DIMSnowHorn1_getExtraSize(void) { return 0xd0c; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Returns 0x43.
 */
int DIMSnowHorn1_getObjectTypeId(void) { return 0x43; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * Wrapper for ObjGroup_RemoveObject(obj, 0xa).
 */
void DIMSnowHorn1_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0xa);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void DIMSnowHorn1_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);

    if (visible == -1) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E8258);
        ObjPath_GetPointWorldPosition(obj, 1, (f32 *)(state + 0x9e8), (f32 *)(state + 0x9ec),
                                      (f32 *)(state + 0x9f0), 0);
        ObjPath_GetPointWorldPositionArray(obj, 2, 4, (f32 *)(state + 0x9b0));
    }

    if ((*(u8 *)(state + 0xa8a) != 2) && (visible != 0)) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E8258);
        ObjPath_GetPointWorldPosition(obj, 1, (f32 *)(state + 0x9e8), (f32 *)(state + 0x9ec),
                                      (f32 *)(state + 0x9f0), 0);
        ObjPath_GetPointWorldPositionArray(obj, 2, 4, (f32 *)(state + 0x9b0));
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

/*
 * Empty stub.
 *
 * EN v1.1 Address: 0x802BB4B0, size 4b
 */
void DIMSnowHorn1_hitDetect(void) {}

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_802BB4B4(int obj, int a, int slot)
{
    extern u32 getButtonsJustPressed(int controller);
    extern u32 getButtonsHeld(int controller);
    int matchFrame = (slot == -1) ? 1 : ((framesThisStep - 1 - slot) == 0);
    int *viewSlot = (int *)Camera_GetCurrentViewSlot();
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(state + 0x354) = 0;
    *(u32 *)state &= ~0x8000;

    if (*(u8 *)(state + 0xa8a) == 2) {
        if (GameBit_Get(0x3e2) != 0) {
            *(s16 *)(state + 0xa88) -= 1;
        } else {
            *(s16 *)(state + 0xa88) = 0x3e8;
        }
        (*(void (**)(int))(*(int *)gGameUIInterface + 0x5c))(*(s16 *)(state + 0xa88));
        if (GameBit_Get(0x3e9) != 0) {
            GameBit_Set(0x3e9, 0);
            *(s16 *)(state + 0xa88) = 0x3e8;
        }
        if (*(s16 *)(state + 0xa88) < 0) {
            *(s16 *)(state + 0xa88) = 0;
            (*(void (**)(void))(*(int *)gMapEventInterface + 0x28))();
        }
        *(f32 *)(state + 0x290) = (f32)(s8)padGetStickX(0);
        *(f32 *)(state + 0x28c) = (f32)(s8)padGetStickY(0);
        *(u32 *)(state + 0x31c) = getButtonsJustPressed(0);
        *(u32 *)(state + 0x318) = getButtonsHeld(0);
        *(s16 *)(state + 0x330) = *(s16 *)viewSlot;
    } else {
        *(f32 *)(state + 0x290) = lbl_803E8234;
        *(f32 *)(state + 0x28c) = lbl_803E8234;
        *(u32 *)(state + 0x31c) = 0;
        *(u32 *)(state + 0x318) = 0;
        *(u16 *)(state + 0x330) = 0;
    }

    *(u32 *)state |= 0x00400000;
    if (matchFrame != 0) {
        *(u32 *)state &= ~0x00400000;
    }

    if (*(s8 *)(state + 0x25f) != 0) {
        *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) - lbl_803E82A4 * (f32)a;
    }

    {
        f32 cur = *(f32 *)(obj + 0x28);
        if (cur < lbl_803E82A8) {
            cur = lbl_803E82A8;
        } else if (cur > lbl_803E8234) {
            cur = lbl_803E8234;
        }
        *(f32 *)(obj + 0x28) = cur;
    }

    (*(void (**)(int, int, f32, f32, int *, f32 *))(*(int *)gPlayerInterface + 0x8))
        (obj, state, timeDelta, timeDelta, lbl_803DB130, &lbl_803DE4C4);
    fn_802BB998(obj, state, state);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DIMSnowHorn1_update(int obj)
{
    f32 nearDist;
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    u8 *base = lbl_80335030;
    int player = (int)Obj_GetPlayerObject();
    int data;
    s8 c = -1;
    char *found;
    int inner;
    char *p2;
    int p;
    s16 d;
    u32 flip;
    int flags;

    data = *(int *)((char *)obj + 0xb8);
    *(s16 *)((char *)data + 0xa86) = 5;
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    *(s16 *)((char *)*(int *)((char *)obj + 0x54) + 0xb2) = 9;
    flags = ((SnowHornFlags *)(base + *(s16 *)((char *)data + 0x274)))->flag;
    if (!(flags & 8)) {
        ObjHitReactEntry *arm;
        if (flags & 2) {
            arm = (ObjHitReactEntry *)(base + 0x80);
        } else {
            arm = (ObjHitReactEntry *)(base + 0x6c);
        }
        *(u8 *)((char *)data + 0xd00) = ((u8 (*)(int, ObjHitReactEntry *, u32, u32, f32 *))ObjHitReact_Update)(obj, arm, 1, *(u8 *)((char *)data + 0xd00), (f32 *)((char *)data + 0xa94));
        if (*(u8 *)((char *)data + 0xd00) != 0) {
            fn_8003A168(obj, data + 0x980);
            characterDoEyeAnims(obj, data + 0x980);
            return;
        }
    }
    if (*(u8 *)((char *)data + 0xa8a) == 2) {
        *(u8 *)((char *)data + 0x25f) = 1;
        fn_802BB4B4(obj, framesThisStep, -1);
    } else {
        f32 fz;
        *(u8 *)((char *)data + 0x25f) = 0;
        fz = lbl_803E8234;
        *(f32 *)((char *)data + 0x294) = fz;
        *(f32 *)((char *)data + 0x284) = fz;
        *(f32 *)((char *)data + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, data + 4);
        fn_802BB4B4(obj, framesThisStep, -1);
    }
    if (*(u8 *)((char *)data + 0xa8a) == 0) {
        (*(void (*)(int))(*(int *)(*gNewCloudsInterface + 0x20)))(0);
    } else {
        (*(void (*)(int))(*(int *)(*gNewCloudsInterface + 0x20)))(1);
    }
    switch (*(u8 *)((char *)data + 0xa8c)) {
    case 0:
    case 5:
        inner = *(int *)((char *)obj + 0xb8);
        p2 = (char *)Obj_GetPlayerObject();
        if (p2 != NULL
            && Vec_distance((void *)((int)p2 + 0x18), (void *)(obj + 0x18)) < lbl_803E8240
            && *(u8 *)((char *)inner + 0xa8a) == 0) {
            *(u8 *)((char *)inner + 0x980) = 1;
            *(f32 *)((char *)inner + 0x984) = *(f32 *)(p2 + 0xc);
            *(f32 *)((char *)inner + 0x988) = *(f32 *)(p2 + 0x10);
            *(f32 *)((char *)inner + 0x98c) = *(f32 *)(p2 + 0x14);
        } else {
            *(u8 *)((char *)inner + 0x980) = 0;
        }
        fn_8003B500(obj, data + 0x980, lbl_803E8234);
        break;
    }
    switch (*(u8 *)((char *)data + 0xa8c)) {
    case 1:
    case 3:
    case 4:
        nearDist = lbl_803E8240;
        found = (char *)ObjGroup_FindNearestObject(0x13, obj, &nearDist);
        if (*(u8 *)((char *)data + 0xa8a) == 0 && *(s16 *)((char *)data + 0x274) == 7
            && getXZDistance(player + 0x18, obj + 0x18) < lbl_803E82B4) {
            if (found != NULL && (*(u8 *)(found + 0xaf) & 4)) {
                setAButtonIcon(0x14);
                if (*(u8 *)(found + 0xaf) & 1) {
                    int layer = getCurMapLayer();
                    (*(void (*)(int, int, int, int))(*(int *)(*gMapEventInterface + 0x24)))(player + 0xc, 0x584, layer, 0);
                    buttonDisable(0, 0x100);
                    GameBit_Set(0x3e3, 1);
                    d = *(s16 *)((char *)obj + 0) - (u16)*(s16 *)found;
                    if (d > 0x8000) {
                        d = d - 0xffff;
                    }
                    if (d < -0x8000) {
                        d = d + 0xffff;
                    }
                    if (d > 0x4000 || d < -0x4000) {
                        GameBit_Set(0x18, 1);
                    } else {
                        GameBit_Set(0x5ba, 1);
                    }
                    if (*(u8 *)((char *)data + 0xa8c) == 3) {
                        *(s16 *)((char *)data + 0xa88) = 1000;
                        (*(void (*)(int, int))(*(int *)(*gGameUIInterface + 0x58)))(1000, 0x5d0);
                    }
                }
            }
        } else if (*(u8 *)((char *)data + 0xa8a) == 2) {
            if (found != NULL && (*(u8 *)(found + 0xaf) & 4)) {
                setAButtonIcon(0x15);
                if (*(u8 *)(found + 0xaf) & 1) {
                    buttonDisable(0, 0x100);
                    GameBit_Set(0x3e3, 0);
                    switch (*(u8 *)((char *)data + 0xa8c)) {
                    case 1:
                        c = 0;
                        break;
                    case 3:
                        c = 1;
                        break;
                    case 4:
                        c = 2;
                        break;
                    }
                    d = *(s16 *)((char *)obj + 0) - (u16)*(s16 *)found;
                    if (d > 0x8000) {
                        d = d - 0xffff;
                    }
                    if (d < -0x8000) {
                        d = d + 0xffff;
                    }
                    if (c >= 0) {
                        SnowHornEntry *tbl = (SnowHornEntry *)base;
                        int bit2;
                        int cc;
                        GameBit_Set(tbl[c].h1e, *(s16 *)(*(int *)(found + 0x4c) + 0x1a));
                        bit2 = tbl[c].h20;
                        cc = c;
                        flip = 0;
                        if (d > 0x4000 || d < -0x4000) {
                            flip = 1;
                        }
                        GameBit_Set(bit2, cc ^ flip);
                    }
                    if (d > 0x4000 || d < -0x4000) {
                        GameBit_Set(0x19, 1);
                    } else {
                        GameBit_Set(0x5bb, 1);
                    }
                    *(int *)((char *)data + 0x31c) = 0;
                    (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
                    (*(void (*)(void))(*(int *)(*gMapEventInterface + 0x2c)))();
                }
            } else {
                setAButtonIcon(0x13);
            }
        }
        break;
    }
    characterDoEyeAnims(obj, data + 0x980);
    v.mat[1] = *(f32 *)((char *)obj + 0xc);
    v.mat[2] = *(f32 *)((char *)obj + 0x10);
    v.mat[3] = *(f32 *)((char *)obj + 0x14);
    v.angles[0] = *(s16 *)((char *)obj + 0);
    v.angles[1] = *(s16 *)((char *)obj + 2);
    v.angles[2] = *(s16 *)((char *)obj + 4);
    v.mat[0] = lbl_803E8258;
    setMatrixFromObjectPos(matrix, v.angles);
    p = *(int *)((char *)obj + 0x64);
    Matrix_TransformPoint(matrix, lbl_803E8234, lbl_803E82AC, lbl_803E82B0,
                          (f32 *)((char *)p + 0x20), (f32 *)((char *)p + 0x24), (f32 *)((char *)p + 0x28));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DIMSnowHorn1_release(void)
{
    void **p = &lbl_803DE4C0;
    void *v = *p;
    if (v != NULL) {
        textureFree((int)v);
    }
    *p = NULL;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DIMSnowHorn1_initialise(void)
{
    s16 *src = &lbl_803DC730;
    void **dst = &lbl_803DE4C0;
    ((void **)lbl_803DB130)[0] = (void *)fn_802BABB4;
    ((void **)lbl_803DB130)[1] = (void *)fn_802BAA54;
    ((void **)lbl_803DB130)[2] = (void *)fn_802BA938;
    ((void **)lbl_803DB130)[3] = (void *)fn_802BA7EC;
    ((void **)lbl_803DB130)[4] = (void *)fn_802BA6E0;
    ((void **)lbl_803DB130)[5] = (void *)fn_802BA3EC;
    ((void **)lbl_803DB130)[6] = (void *)fn_802BA1D4;
    ((void **)lbl_803DB130)[7] = (void *)fn_802B9FC0;
    ((void **)lbl_803DB130)[8] = (void *)fn_802B9E38;
    ((void **)lbl_803DB130)[9] = (void *)fn_802B9CC4;
    ((void **)lbl_803DB130)[10] = (void *)fn_802B98F0;
    ((void **)lbl_803DB130)[11] = (void *)fn_802B978C;
    *(void * *)&lbl_803DE4C4 = (void *)fn_802B9784;
    *dst = (void *)textureLoad(*src, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DIMSnowHorn1_init(int obj, int p2, int p3)
{
    extern int GameBit_Get(int id);
    u8 *base = lbl_80335030;
    int stk = lbl_803E8230;
    int inner;
    int q;
    s8 idx;
    *(s16 *)((char *)obj + 0) = (s16)((s8)*(s8 *)((char *)p2 + 0x18) << 8);
    *(int *)((char *)obj + 0xbc) = (int)ddh_cc_initinterrupts;
    ObjGroup_AddObject(obj, 0xa);
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xa8c) = *(u8 *)((char *)p2 + 0x19);
    *(s16 *)((char *)inner + 0xa86) = 5;
    *(s16 *)((char *)inner + 0xa88) = 0x3e8;
    if (*(void **)((char *)obj + 0x64) != NULL) {
        *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) |= 0xa10;
    }
    if (*(void **)((char *)obj + 0x54) != NULL) {
        *(s16 *)((char *)*(int *)((char *)obj + 0x54) + 0xb2) = 9;
    }
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 0xc, 1);
    *(f32 *)((char *)inner + 0x2a4) = lbl_803E82B8;
    q = inner + 0x4;
    *(u8 *)((char *)q + 0x25b) = 0;
    switch (*(u8 *)((char *)inner + 0xa8c)) {
    case 1:
    case 3:
    case 4:
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 3, 0x200020, 1);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 2, (int)(base + 0xe0), (int)&lbl_803DC734, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 4, (int)(base + 0xa0), (int)(base + 0xd0), &stk);
        (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, q);
        break;
    case 2:
        break;
    }
    dll_2E_func05(obj, inner + 0x35c, -0x2000, 0x2aaa, 3);
    *(u8 *)((char *)inner + 0x96d) |= 8;
    if (p3 == 0) {
        idx = -1;
        switch (*(u8 *)((char *)inner + 0xa8c)) {
        case 1:
            if (GameBit_Get(0x16f)) {
                idx = 0;
            }
            break;
        case 3:
            idx = 1;
            break;
        case 4:
            if (GameBit_Get(0x1db)) {
                idx = 2;
            }
            break;
        }
        if (idx >= 0) {
            SnowHornEntry *e = &((SnowHornEntry *)base)[idx];
            if (GameBit_Get(e->h1e)) {
                *(f32 *)((char *)obj + 0xc) = e->f10;
                *(f32 *)((char *)obj + 0x10) = e->f14;
                *(f32 *)((char *)obj + 0x14) = e->f18;
                *(s16 *)((char *)obj + 0) = e->h1c;
            } else {
                *(f32 *)((char *)obj + 0xc) = e->f0;
                *(f32 *)((char *)obj + 0x10) = e->f4;
                *(f32 *)((char *)obj + 0x14) = e->f8;
                *(s16 *)((char *)obj + 0) = e->hc;
            }
            if (GameBit_Get(e->h20)) {
                *(s16 *)((char *)obj + 0) += 0x8000;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
