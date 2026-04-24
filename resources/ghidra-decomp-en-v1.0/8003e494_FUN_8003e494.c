// Function: FUN_8003e494
// Entry: 8003e494
// Size: 360 bytes

void FUN_8003e494(int param_1,undefined4 param_2,int *param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar8 = (uint)(1 < *(byte *)(param_1 + 0xf3));
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
    uVar6 = 2;
  }
  uVar7 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar7 >> 3));
  iVar4 = *param_3 + ((int)uVar7 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar7 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar7 & 7) & 1) == 0) {
    uVar7 = 0;
  }
  else {
    uVar7 = 4;
  }
  uVar9 = uVar8 | uVar6 | uVar7;
  if (DAT_803db474 != uVar9) {
    FUN_802573f8();
    if (uVar8 == 0) {
      FUN_8025d124(DAT_802caed0);
    }
    else {
      FUN_80256978(0,1);
    }
    if (uVar6 == 0) {
      uVar5 = 2;
    }
    else {
      uVar5 = 3;
    }
    FUN_80256978(9,uVar5);
    if (uVar7 == 0) {
      uVar5 = 2;
    }
    else {
      uVar5 = 3;
    }
    FUN_80256978(0xd,uVar5);
    DAT_803db474 = uVar9;
  }
  return;
}

