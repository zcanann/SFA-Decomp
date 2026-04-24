// Function: FUN_80279018
// Entry: 80279018
// Size: 220 bytes

void FUN_80279018(int *param_1,int param_2)

{
  int iVar1;
  
  if (param_1[0x27] != 0 || param_1[0x26] != 0) {
    if (param_1[0x27] != -1 || param_1[0x26] != -1) {
      if (param_1[0x12] == 0) {
        DAT_803def58 = param_1[0x11];
      }
      else {
        *(int *)(param_1[0x12] + 0x44) = param_1[0x11];
      }
      if (param_1[0x11] != 0) {
        *(int *)(param_1[0x11] + 0x48) = param_1[0x12];
      }
    }
    if (param_2 == 0) {
      FUN_80271a90(param_1);
    }
    param_1[0x27] = 0;
    param_1[0x26] = 0;
    iVar1 = DAT_803def60;
    param_1[0x29] = DAT_803def64;
    param_1[0x28] = iVar1;
    param_1[0x46] = param_1[0x46] & 0xfffbfffb;
    param_1[0x45] = param_1[0x45];
  }
  return;
}

