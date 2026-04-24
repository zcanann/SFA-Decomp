// Function: FUN_801a7cc4
// Entry: 801a7cc4
// Size: 176 bytes

void FUN_801a7cc4(int param_1)

{
  undefined2 *puVar1;
  int iVar2;
  int iVar3;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  puVar1 = (undefined2 *)FUN_8002b9ec();
  local_1c = FLOAT_803e4554;
  iVar2 = *(int *)(puVar1 + 0x5c);
  *(float *)(param_1 + 0x24) = FLOAT_803e4554;
  *(float *)(param_1 + 0x28) = FLOAT_803e4570 * *(float *)(iVar2 + 0x298) + FLOAT_803e456c;
  *(float *)(param_1 + 0x2c) = FLOAT_803e4578 * *(float *)(iVar2 + 0x298) + FLOAT_803e4574;
  local_18 = local_1c;
  local_14 = local_1c;
  local_20 = FLOAT_803e457c;
  local_24 = 0;
  local_26 = 0;
  local_28 = *puVar1;
  FUN_80021ac8(&local_28,param_1 + 0x24);
  *(ushort *)(iVar3 + 0x24) = *(ushort *)(iVar3 + 0x24) | 0x40;
  return;
}

