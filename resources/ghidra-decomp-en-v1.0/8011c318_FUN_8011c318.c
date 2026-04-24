// Function: FUN_8011c318
// Entry: 8011c318
// Size: 516 bytes

void FUN_8011c318(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  undefined uVar4;
  undefined4 uVar3;
  int *piVar5;
  
  if (((&DAT_803a87d0)[param_2] != 0) && (iVar2 = (**(code **)(*DAT_803dcaa4 + 0x2c))(), iVar2 != 0)
     ) {
    if (param_2 == 2) {
      iVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[2]);
      if (iVar2 == 0) {
        FUN_80134bc4();
        if (DAT_803dba28 != -1) {
          (**(code **)(*DAT_803dcaa0 + 8))();
          DAT_803dba28 = -1;
        }
        iVar2 = 0;
        piVar5 = &DAT_803a87d0;
        do {
          if (*piVar5 != 0) {
            (**(code **)(*DAT_803dcaa4 + 0x10))();
            *piVar5 = 0;
          }
          piVar5 = piVar5 + 1;
          iVar2 = iVar2 + 1;
        } while (iVar2 < 8);
      }
    }
    else if (param_2 < 2) {
      if (param_2 == 0) {
        uVar4 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d0);
        FUN_8005cd54(uVar4);
      }
      else if (-1 < param_2) {
        uVar3 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[param_2]);
        uVar1 = countLeadingZeros(uVar3);
        uVar1 = uVar1 >> 5 & 0xff;
        if (uVar1 == 0) {
          FUN_80014a28();
        }
        FUN_800154a4(uVar1);
        if (uVar1 != 0) {
          FUN_80014aa0((double)FLOAT_803e1dd0);
        }
      }
    }
    else if (param_2 < 4) {
      (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[param_2]);
      FUN_80054f6c();
    }
  }
  if (param_1 == 0) {
    FUN_8000bb18(0,0x100);
    (**(code **)(*DAT_803dca4c + 8))(0x14,5);
    DAT_803dd704 = 0x23;
    DAT_803dd705 = 1;
  }
  return;
}

