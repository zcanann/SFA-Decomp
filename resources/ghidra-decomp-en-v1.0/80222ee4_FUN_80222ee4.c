// Function: FUN_80222ee4
// Entry: 80222ee4
// Size: 280 bytes

void FUN_80222ee4(undefined2 *param_1,int param_2)

{
  undefined4 *puVar1;
  undefined4 local_18 [3];
  
  local_18[0] = 1;
  puVar1 = *(undefined4 **)(param_1 + 0x5c);
  if (*(char *)(param_2 + 0x19) == '\0') {
    *(undefined *)(param_2 + 0x19) = 10;
  }
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(undefined2 *)(param_2 + 0x1a) = 100;
  }
  *puVar1 = 5;
  puVar1[2] = 0;
  *(byte *)((int)puVar1 + 0x12a) = *(byte *)((int)puVar1 + 0x12a) & 0x7f;
  *(ushort *)(puVar1 + 0x4a) = (ushort)*(byte *)(param_2 + 0x19);
  puVar1[4] = FLOAT_803e6ca4;
  puVar1[1] = 0xfffffffd;
  *(byte *)((int)puVar1 + 0x12a) = *(byte *)((int)puVar1 + 0x12a) & 0xbf;
  FUN_8008016c(puVar1 + 3);
  FUN_80080178(puVar1 + 3,(int)*(short *)(param_2 + 0x1a));
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  (**(code **)(*DAT_803dca9c + 0x8c))((double)FLOAT_803e6cd0,puVar1 + 8,param_1,local_18,0);
  *(undefined4 *)(param_1 + 6) = puVar1[0x22];
  *(undefined4 *)(param_1 + 10) = puVar1[0x24];
  *(undefined4 *)(param_1 + 8) = puVar1[0x23];
  return;
}

