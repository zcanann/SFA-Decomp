// Function: FUN_8024bb08
// Entry: 8024bb08
// Size: 96 bytes

undefined4 FUN_8024bb08(int *param_1)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  
  FUN_8024377c();
  piVar2 = (int *)param_1[1];
  iVar3 = *param_1;
  if ((piVar2 == (int *)0x0) || (iVar3 == 0)) {
    FUN_802437a4();
    uVar1 = 0;
  }
  else {
    *piVar2 = iVar3;
    *(int **)(iVar3 + 4) = piVar2;
    FUN_802437a4();
    uVar1 = 1;
  }
  return uVar1;
}

