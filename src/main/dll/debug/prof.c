#include "ghidra_import.h"
#include "main/dll/debug/prof.h"

extern undefined4 FUN_800067b4();
extern undefined4 FUN_80006824();
extern undefined4 saveFileStruct_isCheatActive();
extern int isCheatUnlocked();
extern undefined4 OptionsScreen_render();
extern bool FUN_80245dbc();
extern uint countLeadingZeros();
extern u32 OSGetSoundMode(void);
extern int Rcp_GetColorFilterEnabled(void);
extern int return0x64_8000A378(void);

extern undefined4 DAT_8031b920;
extern undefined4 DAT_8031b940;
extern undefined4 DAT_803a9430;
extern undefined4 DAT_803a9434;
extern undefined4 DAT_803a9438;
extern undefined4 DAT_803a943c;
extern undefined4 DAT_803a9440;
extern undefined4 DAT_803a9444;
extern undefined4 DAT_803dc690;
extern undefined4 DAT_803dd5e8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd720;
extern undefined4* DAT_803dd724;
extern undefined4 DAT_803de384;
extern undefined4 DAT_803de385;
extern undefined4 DAT_803de386;
extern undefined4 DAT_803de388;
extern undefined4* PTR_DAT_8031b918;
extern undefined4* PTR_DAT_8031b938;
extern int *gTitleMenuLinkInterface;
extern int *gTitleMenuItemInterface;
extern s8 lbl_803DBA28;
extern u8 lbl_803DD706;
extern u8 *lbl_803DD708;
extern int lbl_803A87D0[8];

typedef struct OptionsMenuPanels {
  u8 pad00[0x10];
  s8 *audioEntries;
  u32 audioUnused14;
  u8 audioCount;
  u8 pad19[0x20 - 0x19];
  s8 *optionEntries;
  u32 optionUnused24;
  u8 optionCount;
} OptionsMenuPanels;

extern OptionsMenuPanels lbl_8031ACB8;

/*
 * --INFO--
 *
 * Function: FUN_8011c7b4
 * EN v1.0 Address: 0x8011C7B4
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8011C800
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8011c7b4(int param_1,int param_2)
{
  if (param_1 == 1) {
    if (param_2 == 2) {
      FUN_8011ca28();
      return 1;
    }
    if (param_2 < 2) {
      if (param_2 == 0) {
        OptionsScreen_render();
        return 1;
      }
    }
    else if (param_2 < 4) {
      FUN_8011c860();
      return 1;
    }
  }
  else if (param_1 == 0) {
    FUN_80006824(0,0x100);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
    DAT_803de384 = 0x23;
    DAT_803de385 = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8011c860
 * EN v1.0 Address: 0x8011C860
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x8011C8B0
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011c860(void)
{
  uint uVar1;
  undefined4 uVar2;
  
  if (DAT_803dc690 != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc690 = 3;
  uVar1 = countLeadingZeros((uint)*(byte *)(DAT_803de388 + 2));
  DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))(0x36b,0x22,0,1,(int)(short)(uVar1 >> 5));
  uVar1 = isCheatUnlocked(3);
  if ((uVar1 == 0) || (DAT_803dd5e8 != '\0')) {
    PTR_DAT_8031b938[(uint)DAT_8031b940 * 0x3c + -0x5d] = -1;
    *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) | 0x4000;
  }
  else {
    PTR_DAT_8031b938[(uint)DAT_8031b940 * 0x3c + -0x5d] = DAT_8031b940 - 1;
    *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) & 0xbfff;
    uVar2 = saveFileStruct_isCheatActive(3);
    uVar1 = countLeadingZeros(uVar2);
    DAT_803a9434 = (**(code **)(*DAT_803dd724 + 0xc))(0x36b,0x23,0,1,(int)(short)(uVar1 >> 5));
  }
  (**(code **)(*DAT_803dd724 + 0x20))(DAT_803a9430,1);
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b938,DAT_8031b940,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  DAT_803de386 = 2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011ca28
 * EN v1.0 Address: 0x8011CA28
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8011CA98
 * EN v1.1 Size: 704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011ca28(void)
{
  uint uVar1;
  bool bVar3;
  undefined4 uVar2;
  
  if (DAT_803dc690 != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc690 = 1;
  uVar1 = isCheatUnlocked(2);
  if (uVar1 == 0) {
    PTR_DAT_8031b918[0x10b] = -1;
    *(ushort *)(PTR_DAT_8031b918 + 0x142) = *(ushort *)(PTR_DAT_8031b918 + 0x142) | 0x4000;
  }
  else {
    PTR_DAT_8031b918[0x10b] = 5;
    *(ushort *)(PTR_DAT_8031b918 + 0x142) = *(ushort *)(PTR_DAT_8031b918 + 0x142) & 0xbfff;
    PTR_DAT_8031b918[0x146] = 4;
  }
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b918,DAT_8031b920,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  bVar3 = FUN_80245dbc();
  if (bVar3) {
    DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))
                             (0x36c,0x22,0,3,*(undefined *)(DAT_803de388 + 9));
  }
  else {
    DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))(0x36c,0x22,0,3,2);
  }
  DAT_803a9434 = (**(code **)(*DAT_803dd724 + 4))
                           (0x124,0xb2,0,0x7f,*(undefined *)(DAT_803de388 + 10),0x3e);
  DAT_803a9438 = (**(code **)(*DAT_803dd724 + 4))
                           (0x124,0xcc,0,0x7f,*(undefined *)(DAT_803de388 + 0xb),0x3e);
  DAT_803a943c = (**(code **)(*DAT_803dd724 + 4))
                           (0x124,0xe6,0,0x7f,*(undefined *)(DAT_803de388 + 0xc),0x3e);
  *(byte *)(DAT_803a943c + 4) = *(byte *)(DAT_803a943c + 4) | 0x40;
  DAT_803a9440 = 0;
  DAT_803a9444 = 0;
  uVar1 = isCheatUnlocked(2);
  if (uVar1 != 0) {
    uVar2 = FUN_800067b4();
    DAT_803a9444 = (**(code **)(*DAT_803dd724 + 0xc))
                             (0x3cb,0x27,0,(int)(short)((short)uVar2 + -1),0);
    *(byte *)(DAT_803a9444 + 4) = *(byte *)(DAT_803a9444 + 4) | 0x80;
  }
  (**(code **)(*DAT_803dd724 + 0x20))(DAT_803a9430,1);
  DAT_803de386 = 2;
  return;
}

#pragma scheduling off
#pragma peephole off
void fn_8011C7B4(void)
{
  OptionsMenuPanels *panels;
  int item;

  if (lbl_803DBA28 != -1) {
    (*(void (**)(void))(*gTitleMenuLinkInterface + 8))();
  }
  lbl_803DBA28 = 1;
  panels = &lbl_8031ACB8;

  if (isCheatUnlocked(2) != 0) {
    panels->audioEntries[0x10b] = 5;
    *(u16 *)(panels->audioEntries + 0x142) =
        (u16)(*(u16 *)(panels->audioEntries + 0x142) & ~0x4000);
    panels->audioEntries[0x146] = 4;
  } else {
    panels->audioEntries[0x10b] = -1;
    *(u16 *)(panels->audioEntries + 0x142) =
        (u16)(*(u16 *)(panels->audioEntries + 0x142) | 0x4000);
  }

  (*(void (**)(s8 *, u8, int, int, int, int, int, int, int, int, int, int))(
      *gTitleMenuLinkInterface + 4))(panels->audioEntries, panels->audioCount, 0, 0, 0, 0,
                                     0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);

  if (OSGetSoundMode() == 1) {
    item = (*(int (**)(int, int, int, int, u8))(*gTitleMenuItemInterface + 0xc))(
        0x36c, 0x22, 0, 3, lbl_803DD708[9]);
  } else {
    item = (*(int (**)(int, int, int, int, int))(*gTitleMenuItemInterface + 0xc))(
        0x36c, 0x22, 0, 3, 2);
  }
  lbl_803A87D0[0] = item;
  lbl_803A87D0[1] =
      (*(int (**)(int, int, int, int, u8, int))(*gTitleMenuItemInterface + 4))(
          0x124, 0xb2, 0, 0x7f, lbl_803DD708[10], 0x3e);
  lbl_803A87D0[2] =
      (*(int (**)(int, int, int, int, u8, int))(*gTitleMenuItemInterface + 4))(
          0x124, 0xcc, 0, 0x7f, lbl_803DD708[11], 0x3e);
  lbl_803A87D0[3] =
      (*(int (**)(int, int, int, int, u8, int))(*gTitleMenuItemInterface + 4))(
          0x124, 0xe6, 0, 0x7f, lbl_803DD708[12], 0x3e);
  *(u8 *)(lbl_803A87D0[3] + 4) = (u8)(*(u8 *)(lbl_803A87D0[3] + 4) | 0x40);
  lbl_803A87D0[4] = 0;
  lbl_803A87D0[5] = 0;

  if (isCheatUnlocked(2) != 0) {
    lbl_803A87D0[5] =
        (*(int (**)(int, int, int, int, int))(*gTitleMenuItemInterface + 0xc))(
            0x3cb, 0x27, 0, (s16)(return0x64_8000A378() - 1), 0);
    *(u8 *)(lbl_803A87D0[5] + 4) = (u8)(*(u8 *)(lbl_803A87D0[5] + 4) | 0x80);
  }

  (*(void (**)(int, int))(*gTitleMenuItemInterface + 0x20))(lbl_803A87D0[0], 1);
  lbl_803DD706 = 2;
}

void fn_8011CA74(void)
{
  OptionsMenuPanels *panels;
  int lastUnlocked;
  int entryOffset;
  int *slot;
  int cheatId;

  if (lbl_803DBA28 != -1) {
    (*(void (**)(void))(*gTitleMenuLinkInterface + 8))();
  }
  lbl_803DBA28 = 2;
  panels = &lbl_8031ACB8;

  lastUnlocked = -1;
  cheatId = 3;
  entryOffset = 0xb4;
  do {
    if (isCheatUnlocked((u8)(cheatId - 2)) != 0) {
      panels->optionEntries[entryOffset - 0x21] = (s8)cheatId;
      *(u16 *)(panels->optionEntries + entryOffset + 0x16) =
          (u16)(*(u16 *)(panels->optionEntries + entryOffset + 0x16) & ~0x4000);
      lastUnlocked = cheatId;
    } else {
      panels->optionEntries[entryOffset - 0x21] = (s8)lastUnlocked;
      *(u16 *)(panels->optionEntries + entryOffset + 0x16) =
          (u16)(*(u16 *)(panels->optionEntries + entryOffset + 0x16) | 0x4000);
    }
    entryOffset -= 0x3c;
    cheatId--;
  } while (cheatId > 1);

  lastUnlocked = 1;
  cheatId = 2;
  entryOffset = 0x78;
  do {
    if (isCheatUnlocked((u8)(cheatId - 2)) != 0) {
      panels->optionEntries[entryOffset + 0x1a] = (s8)lastUnlocked;
      *(u16 *)(panels->optionEntries + entryOffset + 0x16) =
          (u16)(*(u16 *)(panels->optionEntries + entryOffset + 0x16) & ~0x4000);
      lastUnlocked = cheatId;
    }
    entryOffset += 0x3c;
    cheatId++;
  } while (cheatId < 4);

  (*(void (**)(s8 *, u8, int, int, int, int, int, int, int, int, int, int))(
      *gTitleMenuLinkInterface + 4))(panels->optionEntries, panels->optionCount, 0, 0, 0, 0,
                                     0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);

  lbl_803A87D0[0] =
      (*(int (**)(int, int, int, int, u8))(*gTitleMenuItemInterface + 0xc))(
          0x366, 0x22, 0, 1, lbl_803DD708[6]);
  lbl_803A87D0[1] =
      (*(int (**)(int, int, int, int, s16))(*gTitleMenuItemInterface + 0xc))(
          0x36b, 0x23, 0, 1, (s16)(lbl_803DD708[8] == 0));

  slot = &lbl_803A87D0[2];
  cheatId = 0;
  do {
    if (isCheatUnlocked((u8)cheatId) != 0) {
      if (cheatId == 1) {
        *slot = (*(int (**)(int, int, int, int, s16))(*gTitleMenuItemInterface + 0xc))(
            0x507, cheatId + 0x24, 0, 1, (s16)Rcp_GetColorFilterEnabled());
      } else {
        *slot = (*(int (**)(int, int, int, int, s16))(*gTitleMenuItemInterface + 0xc))(
            0x36b, cheatId + 0x24, 0, 1, (s16)(saveFileStruct_isCheatActive(cheatId) == 0));
      }
    }
    slot++;
    cheatId++;
  } while (cheatId <= 1);

  (*(void (**)(int, int))(*gTitleMenuItemInterface + 0x20))(lbl_803A87D0[0], 1);
  lbl_803DD706 = 2;
}
#pragma peephole reset
#pragma scheduling reset
