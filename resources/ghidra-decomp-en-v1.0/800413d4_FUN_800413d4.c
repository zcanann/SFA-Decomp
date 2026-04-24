// Function: FUN_800413d4
// Entry: 800413d4
// Size: 224 bytes

void FUN_800413d4(int param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  DAT_803dcc40 = 4;
  puVar2 = (undefined4 *)FUN_8002b588();
  uVar1 = DAT_803dcc24;
  DAT_803dcc3d = (undefined)(int)FLOAT_803dcc38;
  for (DAT_803dcc44 = 0; DAT_803dcc44 < 0x10; DAT_803dcc44 = DAT_803dcc44 + DAT_803dcc40) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    DAT_803dcc24 = uVar1;
    FUN_800403c0(param_1,iVar3,*puVar2,2);
  }
  FLOAT_803dcc38 = FLOAT_803dcc38 + FLOAT_803db414;
  if (FLOAT_803dea60 < FLOAT_803dcc38) {
    FLOAT_803dcc38 = FLOAT_803dcc38 - FLOAT_803dea5c;
  }
  DAT_803dcc24 = 0;
  return;
}

