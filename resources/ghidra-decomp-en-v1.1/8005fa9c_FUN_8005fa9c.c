// Function: FUN_8005fa9c
// Entry: 8005fa9c
// Size: 472 bytes

void FUN_8005fa9c(char param_1,undefined4 param_2,int param_3,int *param_4)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  uint3 uVar4;
  int iVar5;
  uint uVar6;
  
  if (param_1 != '\0') {
    FUN_80257b5c();
  }
  uVar6 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar6 >> 3));
  iVar5 = *param_4 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar6 + 1;
  if (param_1 != '\0') {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7) & 1) == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 3;
    }
    FUN_802570dc(9,uVar6);
  }
  uVar6 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar6 >> 3));
  iVar5 = *param_4 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar6 + 1;
  if (param_1 != '\0') {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7) & 1) == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 3;
    }
    FUN_802570dc(0xb,uVar6);
  }
  uVar6 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar6 >> 3));
  iVar5 = *param_4 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar6 + 1;
  uVar4 = CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7);
  if (param_1 != '\0') {
    if ((param_3 == 0) || ((*(uint *)(param_3 + 0x3c) & 0x80000000) != 0)) {
      if ((uVar4 & 1) == 0) {
        uVar6 = 2;
      }
      else {
        uVar6 = 3;
      }
      FUN_802570dc(0xd,uVar6);
    }
    else {
      for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x41); iVar5 = iVar5 + 1) {
        if ((uVar4 & 1) == 0) {
          uVar6 = 2;
        }
        else {
          uVar6 = 3;
        }
        FUN_802570dc(iVar5 + 0xd,uVar6);
      }
    }
  }
  return;
}

