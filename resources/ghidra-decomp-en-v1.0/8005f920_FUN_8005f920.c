// Function: FUN_8005f920
// Entry: 8005f920
// Size: 472 bytes

void FUN_8005f920(char param_1,undefined4 param_2,int param_3,int *param_4)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  uint3 uVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  
  if (param_1 != '\0') {
    FUN_802573f8();
  }
  uVar7 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar7 >> 3));
  iVar5 = *param_4 + ((int)uVar7 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar7 + 1;
  if (param_1 != '\0') {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar7 & 7) & 1) == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 3;
    }
    FUN_80256978(9,uVar6);
  }
  uVar7 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar7 >> 3));
  iVar5 = *param_4 + ((int)uVar7 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar7 + 1;
  if (param_1 != '\0') {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar7 & 7) & 1) == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 3;
    }
    FUN_80256978(0xb,uVar6);
  }
  uVar7 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar7 >> 3));
  iVar5 = *param_4 + ((int)uVar7 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar7 + 1;
  uVar4 = CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar7 & 7);
  if (param_1 != '\0') {
    if ((param_3 == 0) || ((*(uint *)(param_3 + 0x3c) & 0x80000000) != 0)) {
      if ((uVar4 & 1) == 0) {
        uVar6 = 2;
      }
      else {
        uVar6 = 3;
      }
      FUN_80256978(0xd,uVar6);
    }
    else {
      for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x41); iVar5 = iVar5 + 1) {
        if ((uVar4 & 1) == 0) {
          uVar6 = 2;
        }
        else {
          uVar6 = 3;
        }
        FUN_80256978(iVar5 + 0xd,uVar6);
      }
    }
  }
  return;
}

