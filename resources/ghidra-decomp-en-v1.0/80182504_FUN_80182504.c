// Function: FUN_80182504
// Entry: 80182504
// Size: 144 bytes

void FUN_80182504(int param_1)

{
  undefined2 *puVar1;
  int iVar2;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  puVar1 = (undefined2 *)FUN_8002b9ec();
  *(undefined *)(iVar2 + 6) = 0;
  *(undefined *)(iVar2 + 5) = 0;
  *(undefined *)(iVar2 + 9) = 1;
  *(float *)(param_1 + 0x28) = FLOAT_803e3958;
  *(float *)(param_1 + 0x2c) = FLOAT_803e3974;
  local_1c = FLOAT_803e3938;
  local_18 = FLOAT_803e3938;
  local_14 = FLOAT_803e3938;
  local_20 = FLOAT_803e3950;
  local_24 = 0;
  local_26 = 0;
  local_28 = *puVar1;
  FUN_80021ac8(&local_28,param_1 + 0x24);
  return;
}

