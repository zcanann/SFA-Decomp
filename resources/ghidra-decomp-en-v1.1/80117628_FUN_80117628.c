// Function: FUN_80117628
// Entry: 80117628
// Size: 224 bytes

void FUN_80117628(void)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  int *piVar5;
  int *piVar6;
  undefined4 *local_28 [10];
  
  piVar1 = (int *)FUN_80286838();
  piVar6 = (int *)(*piVar1 + 8);
  piVar5 = (int *)(*piVar1 + DAT_803a6a2c * 4 + 8);
  FUN_80244820((int *)&DAT_803a50e0,local_28,1);
  puVar4 = &DAT_803a69c0;
  for (uVar3 = 0; uVar3 < DAT_803a6a2c; uVar3 = uVar3 + 1) {
    if (puVar4[0x70] == '\x01') {
      iVar2 = FUN_8026c150((undefined2 *)*local_28[0],piVar5,0);
      local_28[0][2] = iVar2;
      local_28[0][1] = *local_28[0];
      local_28[0][3] = piVar1[1];
      FUN_80244758((int *)&DAT_803a50c0,local_28[0],1);
    }
    piVar5 = (int *)((int)piVar5 + *piVar6);
    piVar6 = piVar6 + 1;
    puVar4 = puVar4 + 1;
  }
  FUN_80286884();
  return;
}

