// Function: FUN_801f2dbc
// Entry: 801f2dbc
// Size: 188 bytes

void FUN_801f2dbc(undefined2 *param_1,undefined2 *param_2)

{
  undefined uVar1;
  undefined4 *puVar2;
  
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801f2a70;
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *(char *)((int)puVar2 + 0x26) = (char)*param_2;
  puVar2[7] = 0;
  *(undefined2 *)(puVar2 + 6) = 0;
  *puVar2 = *(undefined4 *)(param_2 + 4);
  puVar2[1] = *(undefined4 *)(param_2 + 6);
  puVar2[2] = *(undefined4 *)(param_2 + 8);
  uVar1 = FUN_8001ffb4(0xd0);
  *(undefined *)(puVar2 + 9) = uVar1;
  *(undefined *)((int)puVar2 + 0x27) = 0;
  *(undefined *)((int)puVar2 + 0x22) = 1;
  *(undefined *)((int)puVar2 + 0x23) = 0xc;
  *(undefined2 *)(puVar2 + 8) = 300;
  puVar2[3] = FLOAT_803e5d98;
  puVar2[5] = FLOAT_803e5dc0;
  return;
}

