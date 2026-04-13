// Function: FUN_80278d74
// Entry: 80278d74
// Size: 244 bytes

uint FUN_80278d74(int *param_1)

{
  bool bVar1;
  uint uVar2;
  
  uVar2 = param_1[0x45];
  param_1[0x46] = param_1[0x46] | 8;
  if (param_1[0xd] != 0) {
    uVar2 = 0;
    if ((param_1[0x45] & 0x100U) == 0) {
      if ((*(char *)(param_1 + 0x1a) == '\0') || (param_1[0x14] == 0)) {
        bVar1 = false;
      }
      else {
        param_1[0xe] = param_1[0x17];
        param_1[0xd] = param_1[0x14];
        param_1[0x14] = 0;
        uVar2 = FUN_802790f4(param_1);
        bVar1 = true;
      }
      if ((!bVar1) && (uVar2 = param_1[0x46] & 4, uVar2 != 0)) {
        uVar2 = FUN_802790f4(param_1);
      }
    }
    else {
      param_1[0x46] = param_1[0x46];
      param_1[0x45] = param_1[0x45] | 0x400;
    }
  }
  return uVar2;
}

