#include "ghidra_import.h"
#include "main/dll/dll_4E.h"

extern undefined4 FUN_80006768();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern void saveFileStruct_resetVolumes(void);

extern undefined4 DAT_803a9430;
extern undefined4 DAT_803a9434;
extern undefined4 DAT_803a9438;
extern undefined4 DAT_803a943c;
extern undefined4 DAT_803a9444;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd724;
extern undefined4 DAT_803de37c;
extern undefined4 DAT_803de384;
extern undefined4 DAT_803de385;
extern undefined4 DAT_803de388;

/*
 * --INFO--
 *
 * Function: FUN_8011bfc8
 * EN v1.0 Address: 0x8011BFC8
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x8011C2AC
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011bfc8(int param_1,int param_2)
{
  int iVar1;
  byte bVar3;
  uint uVar2;
  
  if (((&DAT_803a9430)[param_2] != 0) && (iVar1 = (**(code **)(*DAT_803dd724 + 0x2c))(), iVar1 != 0)
     ) {
    if (param_2 == 3) {
      uVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a943c);
      FUN_8000676c(uVar2 & 0xff,10,0,0,1);
    }
    else if (param_2 < 3) {
      if (param_2 == 1) {
        uVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
        FUN_8000676c(uVar2 & 0xff,10,1,0,0);
        (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
        (**(code **)(*DAT_803dd6f0 + 0x28))();
      }
      else if (param_2 < 1) {
        if (-1 < param_2) {
          bVar3 = (**(code **)(*DAT_803dd724 + 0x24))((&DAT_803a9430)[param_2]);
          FUN_80006768(bVar3,'\x01');
        }
      }
      else {
        uVar2 = (**(code **)(*DAT_803dd724 + 0x24))((&DAT_803a9430)[param_2]);
        FUN_8000676c(uVar2 & 0xff,10,0,1,0);
      }
    }
    else if (param_2 == 5) {
      DAT_803de37c = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9444);
    }
  }
  if (((&DAT_803a9430)[param_2] == 0) || (((param_2 != 2 && (param_2 != 1)) && (param_2 != 3)))) {
    FUN_80006810(0,0x3b9);
  }
  if (param_1 == 0) {
    FUN_80006824(0,0x100);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
    DAT_803de384 = 0x23;
    DAT_803de385 = 1;
  }
  else if ((param_1 == 1) && (param_2 == 4)) {
    saveFileStruct_resetVolumes();
    (**(code **)(*DAT_803dd724 + 0x28))(DAT_803a9434,*(undefined *)(DAT_803de388 + 10));
    (**(code **)(*DAT_803dd724 + 0x28))(DAT_803a9438,*(undefined *)(DAT_803de388 + 0xb));
    (**(code **)(*DAT_803dd724 + 0x28))(DAT_803a943c,*(undefined *)(DAT_803de388 + 0xc));
    uVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
    FUN_8000676c(uVar2 & 0xff,10,0,1,0);
    uVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9438);
    FUN_8000676c(uVar2 & 0xff,10,1,0,0);
    uVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a943c);
    FUN_8000676c(uVar2 & 0xff,10,0,0,1);
    FUN_80006824(0,0x418);
  }
  return;
}

extern int fn_8011C7B4(void);
extern int fn_8011CA74(void);
extern int languageMenuInit(void);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern int* gScreenTransitionInterface;
extern u8 lbl_803DD704;
extern u8 lbl_803DD705;
extern int* gTitleMenuItemInterface;
extern int* gTitleMenuLinkInterface;
extern int* lbl_803A87D0[8];
extern f32 lbl_803E1DD0;
extern s8 lbl_803DBA28;
extern void setWidescreen(u8 enabled);
extern void stopRumble2(void);
extern void setRumbleEnabled(u8 value);
extern void doRumble(f32 val);
extern void creditsStart(void);
extern void Rcp_SetColorFilterEnabled(int enabled);

#pragma scheduling off
#pragma peephole off
void fn_8011C318(int p1, int p2)
{
    int i;
    int **ptr;
    u8 newState;

    if (lbl_803A87D0[p2] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[p2]) != 0) {
        switch (p2) {
        case 0:
            setWidescreen((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]));
            break;
        case 1:
            newState = (u8)!(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            if (newState == 0) {
                stopRumble2();
            }
            setRumbleEnabled(newState);
            if (newState != 0) {
                doRumble(lbl_803E1DD0);
            }
            break;
        case 2:
            if ((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]) == 0) {
                creditsStart();
                if (lbl_803DBA28 != -1) {
                    (*(void(**)(void))(*gTitleMenuLinkInterface + 0x8))();
                    lbl_803DBA28 = -1;
                }
                i = 0;
                ptr = lbl_803A87D0;
                for (; i < 8; i++) {
                    if (*ptr != NULL) {
                        (*(void(**)(int*))(*gTitleMenuItemInterface + 0x10))(*ptr);
                        *ptr = NULL;
                    }
                    ptr++;
                }
            }
            break;
        case 3:
            Rcp_SetColorFilterEnabled((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]));
            break;
        }
    }
    if (p1 == 0) {
        Sfx_PlayFromObject(0, 0x100);
        (*(void(**)(int, int))(*gScreenTransitionInterface + 0x8))(0x14, 5);
        lbl_803DD704 = 0x23;
        lbl_803DD705 = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8011C51C(int p1, int p2)
{
    if (p1 == 1) {
        switch (p2) {
        case 0:
            fn_8011CA74();
            return 1;
        case 2:
            fn_8011C7B4();
            return 1;
        case 3:
            languageMenuInit();
            return 1;
        }
    } else if (p1 == 0) {
        Sfx_PlayFromObject(0, 0x100);
        (*(void(**)(int, int))(*gScreenTransitionInterface + 0x8))(0x14, 5);
        lbl_803DD704 = 0x23;
        lbl_803DD705 = 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
