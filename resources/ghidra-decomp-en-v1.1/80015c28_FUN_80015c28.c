// Function: FUN_80015c28
// Entry: 80015c28
// Size: 200 bytes

byte * FUN_80015c28(byte *param_1,byte *param_2)

{
  bool bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  int local_18 [3];
  
  do {
    uVar4 = FUN_80015cf0(param_2,local_18);
    while (iVar3 = local_18[0] + -1, local_18[0] != 0) {
      bVar2 = *param_2;
      param_2 = param_2 + 1;
      *param_1 = bVar2;
      param_1 = param_1 + 1;
      local_18[0] = iVar3;
    }
    local_18[0] = iVar3;
    if ((0xdfff < uVar4) && (uVar4 < 0xf900)) {
      iVar3 = FUN_800191a4(uVar4);
      local_18[0] = iVar3 << 1;
      while (iVar3 = local_18[0] + -1, bVar1 = local_18[0] != 0, local_18[0] = iVar3, bVar1) {
        bVar2 = *param_2;
        param_2 = param_2 + 1;
        *param_1 = bVar2;
        param_1 = param_1 + 1;
      }
    }
  } while (uVar4 != 0);
  return param_1 + -1;
}

