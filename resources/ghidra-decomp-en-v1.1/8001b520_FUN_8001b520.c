// Function: FUN_8001b520
// Entry: 8001b520
// Size: 536 bytes

void FUN_8001b520(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int unaff_r31;
  undefined8 extraout_f1;
  undefined8 uVar6;
  int local_28;
  
  if (DAT_803dd684 == 2) {
    if (DAT_803dd670 != 0) {
      unaff_r31 = FUN_80019b4c();
      FUN_80019b54(1,2);
    }
    iVar1 = FUN_80020800();
    if (iVar1 == 0) {
      DAT_803dd690 = DAT_803dd690 + DAT_803dc070;
    }
    FLOAT_803dd68c =
         (float)((double)CONCAT44(0x43300000,DAT_803dd690 ^ 0x80000000) - DOUBLE_803df3a8) /
         FLOAT_803df3a0;
    if ((DAT_803dd688 + 1 < DAT_803dd698) &&
       ((float)(&DAT_8033c6a4)[DAT_803dd688] <= FLOAT_803dd68c)) {
      uVar2 = FUN_80018bfc();
      uVar6 = extraout_f1;
      if (uVar2 != 0) {
        piVar5 = (int *)(uVar2 + local_28 * 0xc);
        do {
          piVar5 = piVar5 + -3;
          iVar1 = local_28 + -1;
          if (local_28 == 0) goto LAB_8001b674;
          local_28 = iVar1;
        } while (*piVar5 != 0xf8ff);
        iVar1 = uVar2 + iVar1 * 0xc;
        DAT_803dd677 = (byte)*(undefined2 *)(iVar1 + 4);
        DAT_803dd676 = (byte)*(undefined2 *)(iVar1 + 6);
        DAT_803dd675 = (byte)*(undefined2 *)(iVar1 + 8);
        DAT_803dd674 = (byte)*(undefined2 *)(iVar1 + 10);
LAB_8001b674:
        uVar3 = FUN_800238f8(0);
        uVar6 = FUN_800238c4(uVar2);
        FUN_800238f8(uVar3);
      }
      iVar1 = DAT_803dd688 + 1;
      iVar4 = DAT_803dd688 + 2;
      DAT_803dd688 = iVar1;
      if (DAT_803dd698 <= iVar4) {
        FUN_8001b7b4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        if (DAT_803dd670 == 0) {
          return;
        }
        FUN_80019b54(unaff_r31,2);
        return;
      }
    }
    FUN_80019940(DAT_803dd677,DAT_803dd676,DAT_803dd675,DAT_803dd674);
    FUN_80015e00((&DAT_8033c2a0)[DAT_803dd688],10,0,0);
    if (DAT_803dd670 != 0) {
      FUN_80019b54(unaff_r31,2);
    }
  }
  return;
}

