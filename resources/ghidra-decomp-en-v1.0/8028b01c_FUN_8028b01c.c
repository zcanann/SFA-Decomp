// Function: FUN_8028b01c
// Entry: 8028b01c
// Size: 188 bytes

void FUN_8028b01c(int param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint *puVar2;
  undefined *puVar3;
  
  param_2 = param_2 & 0xff;
  puVar3 = (undefined *)(param_1 - 1);
  if (0x1f < param_3) {
    uVar1 = ~(uint)puVar3 & 3;
    if (uVar1 != 0) {
      param_3 = param_3 - uVar1;
      do {
        uVar1 = uVar1 - 1;
        puVar3 = puVar3 + 1;
        *puVar3 = (char)param_2;
      } while (uVar1 != 0);
    }
    if (param_2 != 0) {
      param_2 = param_2 | param_2 << 8 | param_2 << 0x18 | param_2 << 0x10;
    }
    puVar2 = (uint *)(puVar3 + -3);
    for (uVar1 = param_3 >> 5; uVar1 != 0; uVar1 = uVar1 - 1) {
      puVar2[1] = param_2;
      puVar2[2] = param_2;
      puVar2[3] = param_2;
      puVar2[4] = param_2;
      puVar2[5] = param_2;
      puVar2[6] = param_2;
      puVar2[7] = param_2;
      puVar2 = puVar2 + 8;
      *puVar2 = param_2;
    }
    for (uVar1 = param_3 >> 2 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
      puVar2 = puVar2 + 1;
      *puVar2 = param_2;
    }
    puVar3 = (undefined *)((int)puVar2 + 3);
    param_3 = param_3 & 3;
  }
  if (param_3 != 0) {
    do {
      param_3 = param_3 - 1;
      puVar3 = puVar3 + 1;
      *puVar3 = (char)param_2;
    } while (param_3 != 0);
    return;
  }
  return;
}

