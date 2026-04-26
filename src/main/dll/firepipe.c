#include "ghidra_import.h"
#include "main/dll/firepipe.h"

extern undefined4 fn_8001CB3C(int param_1);
extern undefined4 GameBit_Get(int eventId);
extern undefined4 fn_800221A0(int param_1, int param_2);
extern undefined4 fn_8002CBC4(int param_1);
extern undefined4 fn_80035F20(int param_1);
extern undefined4 fn_80036FA4(int param_1, int param_2);
extern undefined4 fn_80037200(int param_1, int param_2);
extern undefined4 fn_8003B8F4(double scale, int param_1, int param_2, int param_3, int param_4, int param_5);
extern undefined4 fn_800604B4(void);
extern undefined4 fn_8008016C(int param_1);
extern undefined4 fn_80080178(int param_1, int param_2);
extern undefined4 fn_8021FAEC(void);

extern f32 lbl_803DC340;
extern f32 lbl_803E6B74;
extern f32 lbl_803E6B78;
extern f64 lbl_803E6BA0;
extern f32 lbl_803E6BA8;

int firepipe_getExtraSize(void)
{
    return 0x44;
}

undefined4 fn_80220138(void)
{
    fn_8021FAEC();
    return 0;
}

int firepipe_func08(void)
{
    return 1;
}

void firepipe_free(int param_1)
{
    undefined4 *extra;
    undefined4 *iter;
    int i;

    extra = *(undefined4 **)(param_1 + 0xb8);
    fn_80036FA4(param_1, 0x4a);
    iter = extra;
    for (i = 0; i < (int)(uint)*(byte *)((int)extra + 0x20); i++) {
        fn_8002CBC4(*iter);
        iter = iter + 1;
    }
    if (extra[0xb] != 0) {
        fn_8001CB3C((int)(extra + 0xb));
    }
}

void firepipe_render(int obj, int param_2, int param_3, int param_4, int param_5, char param_6)
{
    int *extra;
    int subObj;

    extra = *(int **)(obj + 0xb8);
    subObj = *(int *)((int)extra + 0x2c);
    if (subObj != 0 && *(byte *)(subObj + 0x2f8) != 0 && *(byte *)(subObj + 0x4c) != 0) {
        fn_800604B4();
    }
    if (param_6 != '\0' && ((*(byte *)((int)extra + 0x41) >> 1) & 1) != 0) {
        fn_8003B8F4((double)lbl_803E6B78, obj, param_2, param_3, param_4, param_5);
    }
}

void firepipe_update(int obj)
{
    *(byte *)(obj + 0xaf) = (u8)(*(byte *)(obj + 0xaf) | 8);
    fn_8021FAEC();
}

void firepipe_init(int obj, int iVar6)
{
    short sVar1;
    short sVar5;
    undefined4 *extra;
    undefined4 uVar3;

    extra = *(undefined4 **)(obj + 0xb8);
    if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(obj + 8) =
            lbl_803E6BA8 *
            (float)((double)CONCAT44(0x43300000, (int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                    lbl_803E6BA0) * *(float *)(*(int *)(obj + 0x50) + 4);
    }
    if (*(short *)(iVar6 + 0x1e) == -1) {
        *(byte *)((int)extra + 0x41) = *(byte *)((int)extra + 0x41) & 0xbf | 0x40;
    }
    else {
        uVar3 = GameBit_Get((int)*(short *)(iVar6 + 0x1e));
        *(byte *)((int)extra + 0x41) =
            (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)extra + 0x41) & 0xbf;
    }
    *(undefined4 (**)(void))(obj + 0xbc) = fn_80220138;
    {
        int iVar7 = *(int *)(obj + 0x4c);
        int iVar8 = *(int *)(obj + 0xb8);
        fn_8008016C(iVar8 + 0x24);
        sVar5 = *(short *)(iVar7 + 0x1a);
        if (sVar5 != 0) {
            sVar1 = *(short *)(iVar7 + 0x20);
            if (sVar1 == 0) {
                fn_80080178(iVar8 + 0x24, (int)(short)(sVar5 * 0x3c));
            }
            else if (sVar1 < 0) {
                sVar5 = fn_800221A0(1, sVar5 * 0x3c);
                fn_80080178(iVar8 + 0x24, (int)sVar5);
            }
            else {
                fn_80080178(iVar8 + 0x24, (int)(short)(sVar1 * 0x3c));
                if (*(short *)(iVar7 + 0x1a) <= *(short *)(iVar7 + 0x20)) {
                    *(byte *)(iVar8 + 0x41) = *(byte *)(iVar8 + 0x41) & 0xbf;
                }
            }
        }
        *(short *)((int)extra + 0x3c) = 0;
        *(short *)((int)extra + 0x3e) = 0;
        sVar5 = *(short *)(obj + 0x46);
        if (sVar5 != 0x70a) {
            if (sVar5 < 0x70a) {
                if (sVar5 == 0x6f9) {
                    extra[0xd] = 10;
                    *(byte *)(extra + 0x10) = 1;
                    extra[0xe] = *(undefined4 *)&lbl_803DC340;
                    goto done_switch;
                }
            }
            else {
                if (sVar5 == 0x731) {
                    extra[0xd] = 0xd;
                    *(byte *)(extra + 0x10) = 2;
                    extra[0xe] = *(undefined4 *)&lbl_803E6B74;
                    goto done_switch;
                }
                if (sVar5 < 0x731) {
                    if (0x72f < sVar5) {
                        extra[0xd] = 0xc;
                        *(byte *)(extra + 0x10) = 2;
                        extra[0xe] = *(undefined4 *)&lbl_803E6B74;
                        goto done_switch;
                    }
                }
                else if (sVar5 < 0x733) {
                    extra[0xd] = 0xe;
                    *(byte *)(extra + 0x10) = 2;
                    extra[0xe] = *(undefined4 *)&lbl_803E6B74;
                    goto done_switch;
                }
            }
        }
        extra[0xd] = 9;
        *(byte *)(extra + 0x10) = 0;
        {
            f32 neg = -lbl_803DC340;
            extra[0xe] = *(undefined4 *)&neg;
        }
        *(short *)((int)extra + 0x3c) = 0x32c;
        *(short *)((int)extra + 0x3e) = 0x32e;
    done_switch:
        {
            int zero = 0;
            extra[0] = zero;
            extra[1] = zero;
            extra[2] = zero;
            extra[3] = zero;
            extra[4] = zero;
            extra[5] = zero;
            extra[6] = zero;
            extra[7] = zero;
            *(byte *)(extra + 8) = zero;
        }
        *(short *)(obj + 4) = 0;
        *(short *)(obj + 0) = (short)((int)*(char *)(iVar6 + 0x18) << 8);
        *(short *)(obj + 2) = (ushort)*(byte *)(iVar6 + 0x19) << 8;
        fn_80035F20(obj);
        *(byte *)((int)extra + 0x41) = *(byte *)((int)extra + 0x41) & 0xef;
        extra[0xc] = 0;
        uVar3 = GameBit_Get((int)*(short *)(iVar6 + 0x1e));
        {
            uint clz = countLeadingZeros(uVar3);
            *(byte *)((int)extra + 0x41) =
                (byte)((clz >> 5 & 0xff) << 7) | *(byte *)((int)extra + 0x41) & 0x7f;
        }
        *(byte *)((int)extra + 0x41) =
            ((*(byte *)(iVar6 + 0x22) & 1) == 0) << 1 | *(byte *)((int)extra + 0x41) & 0xfd;
        *(byte *)((int)extra + 0x41) =
            (*(byte *)(iVar6 + 0x22) & 2) == 0 | *(byte *)((int)extra + 0x41) & 0xfe;
        fn_8008016C((int)(extra + 10));
        fn_80080178((int)(extra + 10), 0x14);
        fn_80037200(obj, 0x4a);
        *(byte *)((int)extra + 0x41) = *(byte *)((int)extra + 0x41) & 0xfb;
        extra[0xb] = 0;
    }
}
