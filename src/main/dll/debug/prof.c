#include "ghidra_import.h"
#include "main/dll/debug/prof.h"

extern undefined4 FUN_800067b4();
extern undefined4 FUN_80006824();
extern undefined4 isCheatActive();
extern uint isCheatUnlocked();
extern undefined4 FUN_8011cd54();
extern bool FUN_80245dbc();
extern uint countLeadingZeros();

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
        FUN_8011cd54();
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
    PTR_DAT_8031b938[(uint)DAT_8031b940 * 0x3c + -0x5d] = 0xff;
    *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) | 0x4000;
  }
  else {
    PTR_DAT_8031b938[(uint)DAT_8031b940 * 0x3c + -0x5d] = DAT_8031b940 - 1;
    *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) & 0xbfff;
    uVar2 = isCheatActive(3);
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
    PTR_DAT_8031b918[0x10b] = 0xff;
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
