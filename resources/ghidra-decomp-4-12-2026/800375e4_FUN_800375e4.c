// Function: FUN_800375e4
// Entry: 800375e4
// Size: 176 bytes

undefined4 FUN_800375e4(int param_1,uint *param_2,uint *param_3,uint *param_4)

{
  uint uVar1;
  uint *puVar2;
  
  if (param_1 == 0) {
    return 0;
  }
  puVar2 = *(uint **)(param_1 + 0xdc);
  if ((puVar2 != (uint *)0x0) && (*puVar2 != 0)) {
    *puVar2 = *puVar2 - 1;
    if (param_2 != (uint *)0x0) {
      *param_2 = puVar2[2];
    }
    if (param_3 != (uint *)0x0) {
      *param_3 = puVar2[3];
    }
    if (param_4 != (uint *)0x0) {
      *param_4 = puVar2[4];
    }
    for (uVar1 = 0; uVar1 < *puVar2; uVar1 = uVar1 + 1) {
      puVar2[uVar1 * 3 + 2] = puVar2[uVar1 * 3 + 5];
      puVar2[uVar1 * 3 + 3] = puVar2[uVar1 * 3 + 6];
      puVar2[uVar1 * 3 + 4] = puVar2[uVar1 * 3 + 7];
    }
    return 1;
  }
  return 0;
}

