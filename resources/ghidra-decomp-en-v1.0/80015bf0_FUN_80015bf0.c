// Function: FUN_80015bf0
// Entry: 80015bf0
// Size: 200 bytes

undefined * FUN_80015bf0(undefined *param_1,undefined *param_2)

{
  bool bVar1;
  undefined uVar2;
  int iVar3;
  uint uVar4;
  int local_18 [3];
  
  do {
    uVar4 = FUN_80015cb8(param_2,local_18);
    while (iVar3 = local_18[0] + -1, local_18[0] != 0) {
      uVar2 = *param_2;
      param_2 = param_2 + 1;
      *param_1 = uVar2;
      param_1 = param_1 + 1;
      local_18[0] = iVar3;
    }
    local_18[0] = iVar3;
    if ((0xdfff < uVar4) && (uVar4 < 0xf900)) {
      iVar3 = FUN_8001916c(uVar4);
      local_18[0] = iVar3 << 1;
      while (iVar3 = local_18[0] + -1, bVar1 = local_18[0] != 0, local_18[0] = iVar3, bVar1) {
        uVar2 = *param_2;
        param_2 = param_2 + 1;
        *param_1 = uVar2;
        param_1 = param_1 + 1;
      }
    }
  } while (uVar4 != 0);
  return param_1 + -1;
}

