// Function: FUN_802790f4
// Entry: 802790f4
// Size: 264 bytes

void FUN_802790f4(int *param_1)

{
  bool bVar1;
  int iVar2;
  
  if (param_1[0x13] != 0) {
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
      FUN_80271a90(param_1);
      param_1[0x27] = 0;
      param_1[0x26] = 0;
      iVar2 = DAT_803def60;
      param_1[0x29] = DAT_803def64;
      param_1[0x28] = iVar2;
      param_1[0x46] = param_1[0x46] & 0xfffbfffb;
      param_1[0x45] = param_1[0x45];
    }
    bVar1 = DAT_803def54 != (int *)0x0;
    param_1[0xf] = (int)DAT_803def54;
    if (bVar1) {
      DAT_803def54[0x10] = (int)param_1;
    }
    param_1[0x10] = 0;
    DAT_803def54 = param_1;
    param_1[0x13] = 0;
  }
  return;
}

