// Function: FUN_80119a40
// Entry: 80119a40
// Size: 328 bytes

void FUN_80119a40(void)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int *local_38 [14];
  
  piVar1 = (int *)FUN_80286830();
  piVar4 = (int *)(*piVar1 + 8);
  iVar3 = *piVar1 + DAT_803a6a2c * 4 + 8;
  FUN_80244820((int *)&DAT_803a7f88,local_38,1);
  puVar2 = &DAT_803a69c0;
  for (uVar5 = 0; uVar5 < DAT_803a6a2c; uVar5 = uVar5 + 1) {
    if (puVar2[0x70] == '\0') {
      DAT_803a6a64 = FUN_80264c10(iVar3,*local_38[0],local_38[0][1],local_38[0][2],DAT_803a6a54);
      if (DAT_803a6a64 != 0) {
        if (DAT_803de314 != 0) {
          FUN_80118e30(0);
          DAT_803de314 = 0;
        }
        FUN_80247054(-0x7fc57058);
      }
      local_38[0][3] = piVar1[1];
      FUN_80244758((int *)&DAT_803a7f68,local_38[0],1);
      FUN_80243e74();
      DAT_803a6a90 = DAT_803a6a90 + 1;
      FUN_80243e9c();
      DAT_803de318 = 0;
    }
    iVar3 = iVar3 + *piVar4;
    piVar4 = piVar4 + 1;
    puVar2 = puVar2 + 1;
  }
  if (DAT_803de314 != 0) {
    FUN_80118e30(1);
    DAT_803de314 = 0;
  }
  FUN_8028687c();
  return;
}

