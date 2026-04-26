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

undefined4 firepipe_stateCallback(void)
{
    fn_8021FAEC();
    return 0;
}

int firepipe_func08(void)
{
    return 1;
}

void firepipe_free(FirePipeObject *obj)
{
    FirePipeExtra *extra;
    int *iter;
    int i;

    extra = obj->extra;
    fn_80036FA4((int)obj, 0x4a);
    iter = extra->effectObjs;
    for (i = 0; i < (int)(uint)extra->effectCount; i++) {
        fn_8002CBC4(*iter);
        iter = iter + 1;
    }
    if (extra->subObj != 0) {
        fn_8001CB3C((int)&extra->subObj);
    }
}

void firepipe_render(FirePipeObject *obj, int param_2, int param_3, int param_4, int param_5, char param_6)
{
    FirePipeExtra *extra;
    int subObj;

    extra = obj->extra;
    subObj = extra->subObj;
    if (subObj != 0 && *(byte *)(subObj + 0x2f8) != 0 && *(byte *)(subObj + 0x4c) != 0) {
        fn_800604B4();
    }
    if (param_6 != '\0' && ((extra->flags >> 1) & 1) != 0) {
        fn_8003B8F4((double)lbl_803E6B78, (int)obj, param_2, param_3, param_4, param_5);
    }
}

void firepipe_update(FirePipeObject *obj)
{
    obj->statusFlags = (u8)(obj->statusFlags | 8);
    fn_8021FAEC();
}

void firepipe_init(FirePipeObject *obj, FirePipeMapData *mapData)
{
    short sVar1;
    short sVar5;
    FirePipeExtra *extra;
    undefined4 uVar3;

    extra = obj->extra;
    if ((int)mapData->scale != 0) {
        obj->scale = lbl_803E6BA8 * (float)mapData->scale * *(float *)((int)obj->model + 4);
    }
    if (mapData->gameBit == -1) {
        extra->flags = extra->flags & 0xbf | 0x40;
    }
    else {
        uVar3 = GameBit_Get((int)mapData->gameBit);
        extra->flags = (byte)((uVar3 & 0xff) << 6) & 0x40 | extra->flags & 0xbf;
    }
    obj->callback = firepipe_stateCallback;
    {
        int iVar7 = (int)obj->objectDef;
        FirePipeExtra *iVar8 = obj->extra;
        fn_8008016C((int)iVar8->cycleTimer);
        sVar5 = *(short *)(iVar7 + 0x1a);
        if (sVar5 != 0) {
            sVar1 = *(short *)(iVar7 + 0x20);
            if (sVar1 == 0) {
                fn_80080178((int)iVar8->cycleTimer, (int)(short)(sVar5 * 0x3c));
            }
            else if (sVar1 < 0) {
                sVar5 = fn_800221A0(1, sVar5 * 0x3c);
                fn_80080178((int)iVar8->cycleTimer, (int)sVar5);
            }
            else {
                fn_80080178((int)iVar8->cycleTimer, (int)(short)(sVar1 * 0x3c));
                if (*(short *)(iVar7 + 0x1a) <= *(short *)(iVar7 + 0x20)) {
                    iVar8->flags = iVar8->flags & 0xbf;
                }
            }
        }
        extra->clearVolumeA = 0;
        extra->clearVolumeB = 0;
        sVar5 = obj->objectId;
        if (sVar5 != 0x70a) {
            if (sVar5 < 0x70a) {
                if (sVar5 == 0x6f9) {
                    extra->effectType = 10;
                    extra->effectMode = 1;
                    extra->effectScale = lbl_803DC340;
                    goto done_switch;
                }
            }
            else {
                if (sVar5 == 0x731) {
                    extra->effectType = 0xd;
                    extra->effectMode = 2;
                    extra->effectScale = lbl_803E6B74;
                    goto done_switch;
                }
                if (sVar5 < 0x731) {
                    if (0x72f < sVar5) {
                        extra->effectType = 0xc;
                        extra->effectMode = 2;
                        extra->effectScale = lbl_803E6B74;
                        goto done_switch;
                    }
                }
                else if (sVar5 < 0x733) {
                    extra->effectType = 0xe;
                    extra->effectMode = 2;
                    extra->effectScale = lbl_803E6B74;
                    goto done_switch;
                }
            }
        }
        extra->effectType = 9;
        extra->effectMode = 0;
        extra->effectScale = -lbl_803DC340;
        extra->clearVolumeA = 0x32c;
        extra->clearVolumeB = 0x32e;
    done_switch:
        {
            int zero = 0;
            extra->effectObjs[0] = zero;
            extra->effectObjs[1] = zero;
            extra->effectObjs[2] = zero;
            extra->effectObjs[3] = zero;
            extra->effectObjs[4] = zero;
            extra->effectObjs[5] = zero;
            extra->effectObjs[6] = zero;
            extra->effectObjs[7] = zero;
            extra->effectCount = zero;
        }
        obj->resetTimer = 0;
        obj->modeX = (short)((int)mapData->modeX << 8);
        obj->modeY = (ushort)mapData->modeY << 8;
        fn_80035F20((int)obj);
        extra->flags = extra->flags & 0xef;
        extra->activeSpawn = 0;
        uVar3 = GameBit_Get((int)mapData->gameBit);
        {
            uint clz = countLeadingZeros(uVar3);
            extra->flags = (byte)((clz >> 5 & 0xff) << 7) | extra->flags & 0x7f;
        }
        extra->flags = ((mapData->flags & 1) == 0) << 1 | extra->flags & 0xfd;
        extra->flags = (mapData->flags & 2) == 0 | extra->flags & 0xfe;
        fn_8008016C((int)extra->emitTimer);
        fn_80080178((int)extra->emitTimer, 0x14);
        fn_80037200((int)obj, 0x4a);
        extra->flags = extra->flags & 0xfb;
        extra->subObj = 0;
    }
}
