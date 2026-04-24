// Function: FUN_8028fa2c
// Entry: 8028fa2c
// Size: 204 bytes

uint FUN_8028fa2c(uint param_1,uint param_2,uint param_3)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  
  iVar1 = countLeadingZeros(param_1 ^ param_2);
  iVar1 = param_1 << iVar1;
  if (param_3 < 0x20) {
    if (iVar1 < 0) {
      puVar2 = (undefined *)(param_2 + param_3);
      puVar3 = (undefined *)(param_1 + param_3);
      iVar1 = param_3 + 1;
      while (iVar1 = iVar1 + -1, iVar1 != 0) {
        puVar2 = puVar2 + -1;
        puVar3 = puVar3 + -1;
        *puVar3 = *puVar2;
      }
    }
    else {
      puVar2 = (undefined *)(param_2 - 1);
      puVar3 = (undefined *)(param_1 - 1);
      iVar1 = param_3 + 1;
      while (iVar1 = iVar1 + -1, iVar1 != 0) {
        puVar2 = puVar2 + 1;
        puVar3 = puVar3 + 1;
        *puVar3 = *puVar2;
      }
    }
  }
  else if (((param_1 ^ param_2) & 3) == 0) {
    if (iVar1 < 0) {
      FUN_8028fc6c(param_1,param_2,param_3);
    }
    else {
      FUN_8028fd18(param_1,param_2,param_3);
    }
  }
  else if (iVar1 < 0) {
    FUN_8028faf8(param_1,param_2,param_3);
  }
  else {
    FUN_8028fba8(param_1,param_2,param_3);
  }
  return param_1;
}

