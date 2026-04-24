// Function: FUN_8011a9b4
// Entry: 8011a9b4
// Size: 216 bytes

void FUN_8011a9b4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar1;
  int iVar2;
  
  DAT_803de330 = DAT_803de328;
  DAT_803dc65c = 0;
  if ((DAT_803dc084 != '\0') &&
     (param_1 = FUN_800e9020(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8),
     DAT_803dc084 != '\0')) {
    DAT_803dc65c = 3;
  }
  iVar2 = DAT_803dc65c * 0x24;
  for (iVar1 = DAT_803dc65c; iVar1 < 3; iVar1 = iVar1 + 1) {
    param_1 = FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           DAT_803de330 + iVar2,&DAT_803dc67c,&DAT_803dc680,in_r6,in_r7,in_r8,in_r9,
                           in_r10);
    *(undefined *)(DAT_803de330 + iVar2 + 5) = 0;
    *(undefined *)(DAT_803de330 + iVar2 + 6) = 0;
    *(undefined *)(DAT_803de330 + iVar2 + 4) = 0;
    *(undefined4 *)(DAT_803de330 + iVar2 + 8) = 0;
    *(undefined *)(DAT_803de330 + iVar2 + 0x21) = 0;
    iVar2 = iVar2 + 0x24;
  }
  return;
}

