// Function: FUN_800412dc
// Entry: 800412dc
// Size: 248 bytes

void FUN_800412dc(int param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  DAT_803dcc40 = 1;
  puVar2 = (undefined4 *)FUN_8002b588();
  uVar1 = DAT_803dcc24;
  DAT_803dcc3d = (undefined)(int)FLOAT_803dcc38;
  FUN_8002853c(puVar2,FUN_8003c268);
  for (DAT_803dcc44 = 0; DAT_803dcc44 < 0x10; DAT_803dcc44 = DAT_803dcc44 + DAT_803dcc40) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    FUN_800403c0(param_1,iVar3,*puVar2,8);
    DAT_803dcc24 = uVar1;
  }
  DAT_803dcc24 = 0;
  FUN_8002853c(puVar2,0);
  FLOAT_803dcc38 = FLOAT_803dcc38 + FLOAT_803db414;
  if (FLOAT_803dea60 < FLOAT_803dcc38) {
    FLOAT_803dcc38 = FLOAT_803dcc38 - FLOAT_803dea5c;
  }
  return;
}

