// Function: FUN_802788b4
// Entry: 802788b4
// Size: 220 bytes

void FUN_802788b4(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if ((*(uint *)(param_1 + 0x9c) | *(uint *)(param_1 + 0x98)) != 0) {
    if ((*(uint *)(param_1 + 0x9c) ^ 0xffffffff | *(uint *)(param_1 + 0x98) ^ 0xffffffff) != 0) {
      if (*(int *)(param_1 + 0x48) == 0) {
        DAT_803de2d8 = *(undefined4 *)(param_1 + 0x44);
      }
      else {
        *(undefined4 *)(*(int *)(param_1 + 0x48) + 0x44) = *(undefined4 *)(param_1 + 0x44);
      }
      if (*(int *)(param_1 + 0x44) != 0) {
        *(undefined4 *)(*(int *)(param_1 + 0x44) + 0x48) = *(undefined4 *)(param_1 + 0x48);
      }
    }
    if (param_2 == 0) {
      FUN_8027132c(param_1);
    }
    *(undefined4 *)(param_1 + 0x9c) = 0;
    *(undefined4 *)(param_1 + 0x98) = 0;
    uVar1 = DAT_803de2e0;
    *(undefined4 *)(param_1 + 0xa4) = DAT_803de2e4;
    *(undefined4 *)(param_1 + 0xa0) = uVar1;
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffbfffb;
    *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
  }
  return;
}

