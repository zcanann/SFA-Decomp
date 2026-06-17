#include "main/dll/dll_4E.h"

extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de3a8;

extern s16 lbl_803DD8C2;
extern void Sfx_PlayFromObjectLimited(int obj, u16 sfx, int);

void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

undefined4
FUN_8011dafc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte bVar1;
    undefined8 uVar2;

    FUN_80017a98();
    bVar1 = DAT_803dc070;
    if (3 < DAT_803dc070)
    {
        bVar1 = 3;
    }
    if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - bVar1, DAT_803de3a8 < '\x01'))
    {
        uVar2 = FUN_80006b84(1);
        FUN_80053c98(uVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x60, '\x01', param_11,
                     param_12, param_13, param_14, param_15, param_16);
    }
    return 0;
}

void OptionsScreen_frameEnd(void);

#pragma scheduling off
void cMenuPlaySelectedItemSfx(int obj)
{
    int sfx = 0;
    switch (lbl_803DD8C2)
    {
    case 0: sfx = 0x3FB;
        break;
    case 5: sfx = 0x3FA;
        break;
    case 1: sfx = 0x3F8;
        break;
    case 4: sfx = 0x3F9;
        break;
    case 2: sfx = 0x3F7;
        break;
    case 3: sfx = 0x3FC;
        break;
    }
    if (sfx != 0)
    {
        Sfx_PlayFromObjectLimited(obj, (u16)sfx, 1);
    }
}

void WeirdUnusedMenu_initialise(void);
