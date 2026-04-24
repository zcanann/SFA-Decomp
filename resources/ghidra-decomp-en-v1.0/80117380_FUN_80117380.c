// Function: FUN_80117380
// Entry: 80117380
// Size: 224 bytes

void FUN_80117380(void)

{
  int *piVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined *puVar4;
  int iVar5;
  int *piVar6;
  undefined4 *local_28 [10];
  
  piVar1 = (int *)FUN_802860d4();
  piVar6 = (int *)(*piVar1 + 8);
  iVar5 = *piVar1 + DAT_803a5dcc * 4 + 8;
  FUN_80244128(&DAT_803a4480,local_28,1);
  puVar4 = &DAT_803a5d60;
  for (uVar3 = 0; uVar3 < DAT_803a5dcc; uVar3 = uVar3 + 1) {
    if (puVar4[0x70] == '\x01') {
      uVar2 = FUN_8026b9ec(*local_28[0],iVar5,0);
      local_28[0][2] = uVar2;
      local_28[0][1] = *local_28[0];
      local_28[0][3] = piVar1[1];
      FUN_80244060(&DAT_803a4460,local_28[0],1);
    }
    iVar5 = iVar5 + *piVar6;
    piVar6 = piVar6 + 1;
    puVar4 = puVar4 + 1;
  }
  FUN_80286120();
  return;
}

