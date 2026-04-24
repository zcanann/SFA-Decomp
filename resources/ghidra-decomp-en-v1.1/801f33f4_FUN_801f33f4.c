// Function: FUN_801f33f4
// Entry: 801f33f4
// Size: 188 bytes

void FUN_801f33f4(undefined2 *param_1,undefined2 *param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801f30a8;
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *(char *)((int)puVar2 + 0x26) = (char)*param_2;
  puVar2[7] = 0;
  *(undefined2 *)(puVar2 + 6) = 0;
  *puVar2 = *(undefined4 *)(param_2 + 4);
  puVar2[1] = *(undefined4 *)(param_2 + 6);
  puVar2[2] = *(undefined4 *)(param_2 + 8);
  uVar1 = FUN_80020078(0xd0);
  *(char *)(puVar2 + 9) = (char)uVar1;
  *(undefined *)((int)puVar2 + 0x27) = 0;
  *(undefined *)((int)puVar2 + 0x22) = 1;
  *(undefined *)((int)puVar2 + 0x23) = 0xc;
  *(undefined2 *)(puVar2 + 8) = 300;
  puVar2[3] = FLOAT_803e6a30;
  puVar2[5] = FLOAT_803e6a58;
  return;
}

