// Function: FUN_802520d4
// Entry: 802520d4
// Size: 204 bytes

undefined4 FUN_802520d4(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  uVar1 = FUN_8024377c();
  piVar3 = &DAT_803ae3a0;
  iVar4 = 4;
  piVar2 = piVar3;
  do {
    if (*piVar2 == param_1) {
      FUN_802437a4(uVar1);
      return 1;
    }
    piVar2 = piVar2 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  iVar5 = 4;
  iVar4 = 0;
  do {
    if (*piVar3 == 0) {
      (&DAT_803ae3a0)[iVar4] = param_1;
      FUN_8025203c(1);
      FUN_802437a4(uVar1);
      return 1;
    }
    piVar3 = piVar3 + 1;
    iVar4 = iVar4 + 1;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  FUN_802437a4(uVar1);
  return 0;
}

