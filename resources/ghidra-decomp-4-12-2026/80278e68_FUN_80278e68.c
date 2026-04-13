// Function: FUN_80278e68
// Entry: 80278e68
// Size: 268 bytes

void FUN_80278e68(int *param_1,int param_2)

{
  bool bVar1;
  
  if (param_2 == 0) {
    if ((param_1[0xd] != 0) && ((param_1[0x45] & 0x400U) != 0)) {
      if ((*(char *)(param_1 + 0x1a) == '\0') || (param_1[0x14] == 0)) {
        bVar1 = false;
      }
      else {
        param_1[0xe] = param_1[0x17];
        param_1[0xd] = param_1[0x14];
        param_1[0x14] = 0;
        FUN_802790f4(param_1);
        bVar1 = true;
      }
      if ((!bVar1) && ((param_1[0x46] & 4U) != 0)) {
        FUN_802790f4(param_1);
      }
    }
    param_1[0x46] = param_1[0x46];
    param_1[0x45] = param_1[0x45] & 0xfffffaff;
  }
  else {
    param_1[0x45] = param_1[0x45] | 0x100;
  }
  return;
}

