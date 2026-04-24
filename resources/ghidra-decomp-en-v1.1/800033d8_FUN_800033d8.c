// Function: FUN_800033d8
// Entry: 800033d8
// Size: 188 bytes

void FUN_800033d8(int param_1,byte param_2,uint param_3)

{
  uint uVar1;
  uint *puVar2;
  byte *pbVar3;
  uint uVar4;
  
  uVar4 = (uint)param_2;
  pbVar3 = (byte *)(param_1 + -1);
  if (0x1f < param_3) {
    uVar1 = ~(uint)pbVar3 & 3;
    if (uVar1 != 0) {
      param_3 = param_3 - uVar1;
      do {
        uVar1 = uVar1 - 1;
        pbVar3 = pbVar3 + 1;
        *pbVar3 = param_2;
      } while (uVar1 != 0);
    }
    if (param_2 != 0) {
      uVar4 = uVar4 | uVar4 << 8 | uVar4 << 0x18 | uVar4 << 0x10;
    }
    puVar2 = (uint *)(pbVar3 + -3);
    for (uVar1 = param_3 >> 5; uVar1 != 0; uVar1 = uVar1 - 1) {
      puVar2[1] = uVar4;
      puVar2[2] = uVar4;
      puVar2[3] = uVar4;
      puVar2[4] = uVar4;
      puVar2[5] = uVar4;
      puVar2[6] = uVar4;
      puVar2[7] = uVar4;
      puVar2 = puVar2 + 8;
      *puVar2 = uVar4;
    }
    for (uVar1 = param_3 >> 2 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
      puVar2 = puVar2 + 1;
      *puVar2 = uVar4;
    }
    pbVar3 = (byte *)((int)puVar2 + 3);
    param_3 = param_3 & 3;
  }
  if (param_3 != 0) {
    do {
      param_3 = param_3 - 1;
      pbVar3 = pbVar3 + 1;
      *pbVar3 = (byte)uVar4;
    } while (param_3 != 0);
    return;
  }
  return;
}

