// Function: FUN_802521a0
// Entry: 802521a0
// Size: 244 bytes

undefined4 FUN_802521a0(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  uVar1 = FUN_8024377c();
  piVar3 = &DAT_803ae3a0;
  iVar4 = 4;
  iVar2 = 0;
  do {
    if (*piVar3 == param_1) {
      (&DAT_803ae3a0)[iVar2] = 0;
      iVar2 = 0;
      if ((((DAT_803ae3a0 == 0) && (iVar2 = 1, DAT_803ae3a4 == 0)) && (iVar2 = 2, DAT_803ae3a8 == 0)
          ) && (iVar2 = 3, DAT_803ae3ac == 0)) {
        iVar2 = 4;
      }
      if (iVar2 == 4) {
        FUN_8025203c(0);
      }
      FUN_802437a4(uVar1);
      return 1;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_802437a4(uVar1);
  return 0;
}

