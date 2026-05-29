#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_80295318.h"
#include "main/dll/player_80295318_shared.h"

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

