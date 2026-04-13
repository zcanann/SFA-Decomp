// Function: FUN_800a0108
// Entry: 800a0108
// Size: 84 bytes

void FUN_800a0108(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint *puVar2;
  
  FUN_8009b4e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  iVar1 = 0;
  puVar2 = &DAT_8039c9b8;
  do {
    FUN_800238c4(*puVar2);
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x50);
  return;
}

