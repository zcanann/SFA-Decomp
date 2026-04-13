// Function: FUN_8011c5fc
// Entry: 8011c5fc
// Size: 516 bytes

void FUN_8011c5fc(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  char cVar5;
  undefined4 uVar4;
  int *piVar6;
  
  if (((&DAT_803a9430)[param_2] != 0) && (iVar3 = (**(code **)(*DAT_803dd724 + 0x2c))(), iVar3 != 0)
     ) {
    if (param_2 == 2) {
      iVar3 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9438);
      if (iVar3 == 0) {
        FUN_80134f4c();
        if (DAT_803dc690 != -1) {
          (**(code **)(*DAT_803dd720 + 8))();
          DAT_803dc690 = -1;
        }
        iVar3 = 0;
        piVar6 = &DAT_803a9430;
        do {
          if (*piVar6 != 0) {
            (**(code **)(*DAT_803dd724 + 0x10))();
            *piVar6 = 0;
          }
          piVar6 = piVar6 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
      }
    }
    else if (param_2 < 2) {
      if (param_2 == 0) {
        cVar5 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
        FUN_8005ced0(cVar5);
      }
      else if (-1 < param_2) {
        uVar4 = (**(code **)(*DAT_803dd724 + 0x24))((&DAT_803a9430)[param_2]);
        uVar2 = countLeadingZeros(uVar4);
        uVar1 = uVar2 >> 5 & 0xff;
        if (uVar1 == 0) {
          FUN_80014a54();
        }
        FUN_800154d0((char)(uVar2 >> 5));
        if (uVar1 != 0) {
          FUN_80014acc((double)FLOAT_803e2a50);
        }
      }
    }
    else if (param_2 < 4) {
      uVar4 = (**(code **)(*DAT_803dd724 + 0x24))((&DAT_803a9430)[param_2]);
      FUN_800550e8(uVar4);
    }
  }
  if (param_1 == 0) {
    FUN_8000bb38(0,0x100);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
    DAT_803de384 = 0x23;
    DAT_803de385 = 1;
  }
  return;
}

