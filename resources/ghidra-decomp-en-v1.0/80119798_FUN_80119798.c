// Function: FUN_80119798
// Entry: 80119798
// Size: 328 bytes

void FUN_80119798(void)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  undefined4 *local_38 [14];
  
  piVar1 = (int *)FUN_802860cc();
  piVar4 = (int *)(*piVar1 + 8);
  iVar3 = *piVar1 + DAT_803a5dcc * 4 + 8;
  FUN_80244128(&DAT_803a7328,local_38,1);
  puVar2 = &DAT_803a5d60;
  for (uVar5 = 0; uVar5 < DAT_803a5dcc; uVar5 = uVar5 + 1) {
    if (puVar2[0x70] == '\0') {
      DAT_803a5e04 = FUN_802644ac(iVar3,*local_38[0],local_38[0][1],local_38[0][2],DAT_803a5df4);
      if (DAT_803a5e04 != 0) {
        if (DAT_803dd694 != 0) {
          FUN_80118b88(0);
          DAT_803dd694 = 0;
        }
        FUN_802468f0(&DAT_803a8348);
      }
      local_38[0][3] = piVar1[1];
      FUN_80244060(&DAT_803a7308,local_38[0],1);
      FUN_8024377c();
      DAT_803a5e30 = DAT_803a5e30 + 1;
      FUN_802437a4();
      DAT_803dd698 = 0;
    }
    iVar3 = iVar3 + *piVar4;
    piVar4 = piVar4 + 1;
    puVar2 = puVar2 + 1;
  }
  if (DAT_803dd694 != 0) {
    FUN_80118b88(1);
    DAT_803dd694 = 0;
  }
  FUN_80286118();
  return;
}

