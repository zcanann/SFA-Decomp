// Function: FUN_8028fc6c
// Entry: 8028fc6c
// Size: 172 bytes

void FUN_8028fc6c(int param_1,int param_2,uint param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)(param_1 + param_3);
  puVar2 = (undefined4 *)(param_2 + param_3);
  uVar1 = (uint)puVar3 & 3;
  if (uVar1 != 0) {
    param_3 = param_3 - uVar1;
    do {
      puVar2 = (undefined4 *)((int)puVar2 + -1);
      uVar1 = uVar1 - 1;
      puVar3 = (undefined4 *)((int)puVar3 + -1);
      *(undefined *)puVar3 = *(undefined *)puVar2;
    } while (uVar1 != 0);
  }
  for (uVar1 = param_3 >> 5; uVar1 != 0; uVar1 = uVar1 - 1) {
    puVar3[-1] = puVar2[-1];
    puVar3[-2] = puVar2[-2];
    puVar3[-3] = puVar2[-3];
    puVar3[-4] = puVar2[-4];
    puVar3[-5] = puVar2[-5];
    puVar3[-6] = puVar2[-6];
    puVar3[-7] = puVar2[-7];
    puVar2 = puVar2 + -8;
    puVar3 = puVar3 + -8;
    *puVar3 = *puVar2;
  }
  for (uVar1 = param_3 >> 2 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
    puVar2 = puVar2 + -1;
    puVar3 = puVar3 + -1;
    *puVar3 = *puVar2;
  }
  uVar1 = param_3 & 3;
  if (uVar1 != 0) {
    do {
      puVar2 = (undefined4 *)((int)puVar2 + -1);
      uVar1 = uVar1 - 1;
      puVar3 = (undefined4 *)((int)puVar3 + -1);
      *(undefined *)puVar3 = *(undefined *)puVar2;
    } while (uVar1 != 0);
    return;
  }
  return;
}

