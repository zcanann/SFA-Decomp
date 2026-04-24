// Function: FUN_8003e58c
// Entry: 8003e58c
// Size: 360 bytes

void FUN_8003e58c(int param_1,undefined4 param_2,int *param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  uVar7 = (uint)(1 < *(byte *)(param_1 + 0xf3));
  uVar5 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar5 >> 3));
  iVar4 = *param_3 + ((int)uVar5 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar5 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar5 & 7) & 1) == 0) {
    uVar5 = 0;
  }
  else {
    uVar5 = 2;
  }
  uVar6 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar6 >> 3));
  iVar4 = *param_3 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar6 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7) & 1) == 0) {
    uVar6 = 0;
  }
  else {
    uVar6 = 4;
  }
  uVar8 = uVar7 | uVar5 | uVar6;
  if (DAT_803dc0d4 != uVar8) {
    FUN_80257b5c();
    if (uVar7 == 0) {
      FUN_8025d888((uint)DAT_802cbaa8);
    }
    else {
      FUN_802570dc(0,1);
    }
    if (uVar5 == 0) {
      uVar5 = 2;
    }
    else {
      uVar5 = 3;
    }
    FUN_802570dc(9,uVar5);
    if (uVar6 == 0) {
      uVar5 = 2;
    }
    else {
      uVar5 = 3;
    }
    FUN_802570dc(0xd,uVar5);
    DAT_803dc0d4 = uVar8;
  }
  return;
}

