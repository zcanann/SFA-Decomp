// Function: FUN_80119520
// Entry: 80119520
// Size: 248 bytes

void FUN_80119520(void)

{
  int **ppiVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int **local_28 [10];
  
  FUN_802860d8();
  piVar5 = (int *)0x0;
  iVar3 = DAT_803a5e14;
  iVar4 = DAT_803a5e10;
  do {
    FUN_80244128(&DAT_803a72d0,local_28,1);
    ppiVar1 = local_28[0];
    iVar2 = FUN_80248f9c(&DAT_803a5d60,*local_28[0],iVar3,iVar4,2);
    if (iVar2 != iVar3) {
      if (iVar2 == -1) {
        DAT_803a5e00 = 0xffffffff;
      }
      if (piVar5 == (int *)0x0) {
        FUN_80118b88(0);
      }
      FUN_802468f0(&DAT_803a6f08);
    }
    ppiVar1[1] = piVar5;
    FUN_80244060(&DAT_803a72b0,ppiVar1,1);
    iVar2 = iVar4 + iVar3;
    iVar3 = **ppiVar1;
    iVar4 = iVar2;
    if ((((int)piVar5 + DAT_803a5e18) -
         ((uint)((int)piVar5 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 == DAT_803a5db0 - 1) &&
       (iVar4 = DAT_803a5dc4, (DAT_803a5dfe & 1) == 0)) {
      FUN_802468f0(&DAT_803a6f08);
      iVar4 = iVar2;
    }
    piVar5 = (int *)((int)piVar5 + 1);
  } while( true );
}

