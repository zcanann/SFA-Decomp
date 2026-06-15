#include "main/audio/sfx_ids.h"
#include "main/dll/dll_4E.h"
#include "main/dll/debug/dimenu.h"
#include "main/screen_transition.h"

extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de3a8;

extern void loadUiDll(int id);
extern u8 framesThisStep;

extern u8 lbl_803DD728;
extern u32 lbl_803DD72C;
extern void textureFree(u32);
extern void warpToMap(int mapId, int spawnId);
extern int Obj_GetPlayerObject(void);

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

void Dummy39_render(void)
{
}

void Dummy39_frameEnd(void)
{
}

void Dummy3A_render(void);

void Dummy39_initialise(void) { lbl_803DD728 = 0x28; }

void Dummy39_release(void) { textureFree(lbl_803DD72C); }

#pragma scheduling off
#pragma peephole off
int Dummy39_run(void)
{
    s32 v;
    u8 cur;
    s8 next;
    Obj_GetPlayerObject();
    v = framesThisStep;
    if (v > 3) v = 3;
    cur = lbl_803DD728;
    if ((s8)cur > 0)
    {
        next = (s8)(cur - v);
        *(s8*)&lbl_803DD728 = next;
        if ((s8)(u8)next <= 0
        )
        {
            loadUiDll(1);
            warpToMap(0x60, 1);
        }
    }
    return 0;
}
