// Function: FUN_8003aab8
// Entry: 8003aab8
// Size: 128 bytes

void FUN_8003aab8(int param_1,uint param_2,undefined2 param_3,undefined2 param_4)

{
  uint uVar1;
  
  if ((int)param_2 < 1) {
    return;
  }
  uVar1 = param_2 >> 3;
  if (uVar1 != 0) {
    do {
      *(undefined2 *)(param_1 + 0x14) = param_3;
      *(undefined2 *)(param_1 + 0x44) = param_4;
      *(undefined2 *)(param_1 + 0x74) = param_3;
      *(undefined2 *)(param_1 + 0xa4) = param_4;
      *(undefined2 *)(param_1 + 0xd4) = param_3;
      *(undefined2 *)(param_1 + 0x104) = param_4;
      *(undefined2 *)(param_1 + 0x134) = param_3;
      *(undefined2 *)(param_1 + 0x164) = param_4;
      *(undefined2 *)(param_1 + 0x194) = param_3;
      *(undefined2 *)(param_1 + 0x1c4) = param_4;
      *(undefined2 *)(param_1 + 500) = param_3;
      *(undefined2 *)(param_1 + 0x224) = param_4;
      *(undefined2 *)(param_1 + 0x254) = param_3;
      *(undefined2 *)(param_1 + 0x284) = param_4;
      *(undefined2 *)(param_1 + 0x2b4) = param_3;
      *(undefined2 *)(param_1 + 0x2e4) = param_4;
      param_1 = param_1 + 0x300;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
    param_2 = param_2 & 7;
    if (param_2 == 0) {
      return;
    }
  }
  do {
    *(undefined2 *)(param_1 + 0x14) = param_3;
    *(undefined2 *)(param_1 + 0x44) = param_4;
    param_1 = param_1 + 0x60;
    param_2 = param_2 - 1;
  } while (param_2 != 0);
  return;
}

