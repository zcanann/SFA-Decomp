// Function: FUN_8028fd18
// Entry: 8028fd18
// Size: 192 bytes

void FUN_8028fd18(int param_1,int param_2,uint param_3)

{
  undefined *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined *puVar5;
  
  puVar5 = (undefined *)(param_2 + -1);
  uVar3 = -param_1 & 3;
  puVar1 = (undefined *)(param_1 + -1);
  if (uVar3 != 0) {
    param_3 = param_3 - uVar3;
    do {
      puVar5 = puVar5 + 1;
      uVar3 = uVar3 - 1;
      puVar1 = puVar1 + 1;
      *puVar1 = *puVar5;
    } while (uVar3 != 0);
  }
  puVar4 = (undefined4 *)(puVar5 + -3);
  puVar2 = (undefined4 *)(puVar1 + -3);
  for (uVar3 = param_3 >> 5; uVar3 != 0; uVar3 = uVar3 - 1) {
    puVar2[1] = puVar4[1];
    puVar2[2] = puVar4[2];
    puVar2[3] = puVar4[3];
    puVar2[4] = puVar4[4];
    puVar2[5] = puVar4[5];
    puVar2[6] = puVar4[6];
    puVar2[7] = puVar4[7];
    puVar4 = puVar4 + 8;
    puVar2 = puVar2 + 8;
    *puVar2 = *puVar4;
  }
  for (uVar3 = param_3 >> 2 & 7; uVar3 != 0; uVar3 = uVar3 - 1) {
    puVar4 = puVar4 + 1;
    puVar2 = puVar2 + 1;
    *puVar2 = *puVar4;
  }
  puVar5 = (undefined *)((int)puVar4 + 3);
  uVar3 = param_3 & 3;
  puVar1 = (undefined *)((int)puVar2 + 3);
  if (uVar3 != 0) {
    do {
      puVar5 = puVar5 + 1;
      uVar3 = uVar3 - 1;
      puVar1 = puVar1 + 1;
      *puVar1 = *puVar5;
    } while (uVar3 != 0);
    return;
  }
  return;
}

