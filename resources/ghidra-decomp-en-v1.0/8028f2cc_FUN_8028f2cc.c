// Function: FUN_8028f2cc
// Entry: 8028f2cc
// Size: 204 bytes

uint FUN_8028f2cc(uint param_1,uint param_2,uint param_3)

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
      FUN_8028f50c();
    }
    else {
      FUN_8028f5b8();
    }
  }
  else if (iVar1 < 0) {
    FUN_8028f398();
  }
  else {
    FUN_8028f448();
  }
  return param_1;
}

