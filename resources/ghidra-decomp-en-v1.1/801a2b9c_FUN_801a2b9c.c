// Function: FUN_801a2b9c
// Entry: 801a2b9c
// Size: 464 bytes

void FUN_801a2b9c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 7) = *(byte *)(iVar1 + 7) | 2;
  (**(code **)(*DAT_803dd740 + 4))(param_1,iVar1,5);
  FUN_800372f8(param_1,0x19);
  FUN_800372f8(param_1,0x16);
  FUN_80037a5c(param_1,8);
  *(undefined4 *)(param_1 + 0xf8) = 0;
  *(undefined2 *)(iVar1 + 0x44) = 0;
  *(undefined2 *)(iVar1 + 0x46) = 0;
  *(undefined *)(iVar1 + 0x15) = 0;
  *(undefined2 *)(iVar1 + 0x3c) = 0;
  *(undefined *)(iVar1 + 0x16) = 0;
  *(undefined *)(iVar1 + 0x17) = 0;
  *(undefined *)(iVar1 + 0x3e) = 0;
  *(undefined4 *)(iVar1 + 0x40) = 0;
  *(float *)(iVar1 + 0x30) = FLOAT_803e4f58;
  *(undefined *)(iVar1 + 0x49) = 0;
  FUN_800803f8((undefined4 *)(iVar1 + 0x18));
  FUN_800803f8((undefined4 *)(iVar1 + 0x1c));
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) | 1;
  *(byte *)(iVar1 + 0x48) =
       (*(char *)(param_2 + 0x19) < '\x01') << 7 | *(byte *)(iVar1 + 0x48) & 0x7f;
  *(byte *)(iVar1 + 0x48) = (*(short *)(param_2 + 0x1c) != 0) << 6 | *(byte *)(iVar1 + 0x48) & 0xbf;
  FUN_80036018(param_1);
  *(float *)(iVar1 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,
                                (int)*(short *)(*(int *)(param_1 + 0x54) + 0x5a) ^ 0x80000000) -
              DOUBLE_803e4f98);
  *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xdf;
  *(float *)(iVar1 + 0x38) = FLOAT_803e4f58;
  *(undefined4 *)(iVar1 + 0x10) = 0;
  (**(code **)(*DAT_803dd740 + 0x2c))(iVar1,1);
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x54) + 0xb2) = 1;
  }
  if (*(short *)(param_1 + 0x46) == 0x754) {
    *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xfb | 4;
  }
  return;
}

