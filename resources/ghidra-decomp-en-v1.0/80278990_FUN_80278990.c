// Function: FUN_80278990
// Entry: 80278990
// Size: 264 bytes

void FUN_80278990(int param_1)

{
  bool bVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x4c) != 0) {
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
      FUN_8027132c(param_1);
      *(undefined4 *)(param_1 + 0x9c) = 0;
      *(undefined4 *)(param_1 + 0x98) = 0;
      uVar2 = DAT_803de2e0;
      *(undefined4 *)(param_1 + 0xa4) = DAT_803de2e4;
      *(undefined4 *)(param_1 + 0xa0) = uVar2;
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffbfffb;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
    }
    bVar1 = DAT_803de2d4 != 0;
    *(int *)(param_1 + 0x3c) = DAT_803de2d4;
    if (bVar1) {
      *(int *)(DAT_803de2d4 + 0x40) = param_1;
    }
    *(undefined4 *)(param_1 + 0x40) = 0;
    DAT_803de2d4 = param_1;
    *(undefined4 *)(param_1 + 0x4c) = 0;
  }
  return;
}

