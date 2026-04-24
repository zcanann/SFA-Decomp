// Function: FUN_8011be9c
// Entry: 8011be9c
// Size: 300 bytes

void FUN_8011be9c(void)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  undefined2 *puVar5;
  float local_28 [2];
  double local_20;
  
  DAT_803dd6ec = 2;
  DAT_803dd6ed = 2;
  DAT_803dd6f4 = 0;
  DAT_803dd6f0 = 0;
  DAT_803dd6e8 = 0;
  iVar2 = 0;
  puVar5 = &DAT_8031a880;
  piVar4 = &DAT_803a8730;
  piVar3 = &DAT_803a8690;
  do {
    uVar1 = FUN_80019444(*puVar5);
    FUN_800186f0((double)FLOAT_803e1dcc,uVar1,local_28,0,0,0,0xffffffff);
    local_20 = (double)(longlong)(int)local_28[0];
    *piVar4 = (int)local_28[0];
    *piVar3 = DAT_803dd6e8;
    DAT_803dd6e8 = DAT_803dd6e8 + *piVar4;
    puVar5 = puVar5 + 1;
    piVar4 = piVar4 + 1;
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x28);
  DAT_803dd6e4 = 0;
  local_20 = (double)CONCAT44(0x43300000,DAT_803a8730 / 2 ^ 0x80000000);
  FLOAT_803dd6e0 = (float)(local_20 - DOUBLE_803e1da8);
  DAT_803dd6da = 0;
  DAT_803dd6dc = DAT_803dd6e8;
  FUN_8000bb18(0,0x418);
  return;
}

