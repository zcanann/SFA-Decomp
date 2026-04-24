// Function: FUN_800413d4
// Entry: 800413d4
// Size: 248 bytes

void FUN_800413d4(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  
  DAT_803dd8c0 = 1;
  piVar2 = (int *)FUN_8002b660(param_1);
  uVar1 = DAT_803dd8a4;
  DAT_803dd8bd = (undefined)(int)FLOAT_803dd8b8;
  FUN_80028600((int)piVar2,FUN_8003c360);
  for (DAT_803dd8c4 = 0; DAT_803dd8c4 < 0x10; DAT_803dd8c4 = DAT_803dd8c4 + DAT_803dd8c0) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    FUN_800404b8(param_1,iVar3,*piVar2,8);
    DAT_803dd8a4 = uVar1;
  }
  DAT_803dd8a4 = 0;
  FUN_80028600((int)piVar2,0);
  FLOAT_803dd8b8 = FLOAT_803dd8b8 + FLOAT_803dc074;
  if (FLOAT_803df6e0 < FLOAT_803dd8b8) {
    FLOAT_803dd8b8 = FLOAT_803dd8b8 - FLOAT_803df6dc;
  }
  return;
}

