// Function: FUN_802791fc
// Entry: 802791fc
// Size: 252 bytes

void FUN_802791fc(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0x4c) == param_2) {
    return;
  }
  if (*(int *)(param_1 + 0x4c) == 0) {
    if (*(int *)(param_1 + 0x40) == 0) {
      DAT_803def54 = *(undefined4 *)(param_1 + 0x3c);
    }
    else {
      *(undefined4 *)(*(int *)(param_1 + 0x40) + 0x3c) = *(undefined4 *)(param_1 + 0x3c);
    }
    if (*(int *)(param_1 + 0x3c) != 0) {
      *(undefined4 *)(*(int *)(param_1 + 0x3c) + 0x40) = *(undefined4 *)(param_1 + 0x40);
    }
  }
  if (param_2 == 2) {
    if (*(int *)(param_1 + 0x9c) != 0 || *(int *)(param_1 + 0x98) != 0) {
      if (*(int *)(param_1 + 0x9c) != -1 || *(int *)(param_1 + 0x98) != -1) {
        if (*(int *)(param_1 + 0x48) == 0) {
          DAT_803def58 = *(undefined4 *)(param_1 + 0x44);
        }
        else {
          *(undefined4 *)(*(int *)(param_1 + 0x48) + 0x44) = *(undefined4 *)(param_1 + 0x44);
        }
        if (*(int *)(param_1 + 0x44) != 0) {
          *(undefined4 *)(*(int *)(param_1 + 0x44) + 0x48) = *(undefined4 *)(param_1 + 0x48);
        }
      }
      *(undefined4 *)(param_1 + 0x9c) = 0;
      *(undefined4 *)(param_1 + 0x98) = 0;
      uVar1 = DAT_803def60;
      *(undefined4 *)(param_1 + 0xa4) = DAT_803def64;
      *(undefined4 *)(param_1 + 0xa0) = uVar1;
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffbfffb;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
    }
  }
  *(int *)(param_1 + 0x4c) = param_2;
  return;
}

