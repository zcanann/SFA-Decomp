// Function: FUN_80200750
// Entry: 80200750
// Size: 256 bytes

undefined4 FUN_80200750(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  *(byte *)(iVar1 + 0x15) = *(byte *)(iVar1 + 0x15) | 4;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e62e8;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,param_1,0x11,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 0x1f;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_2 + 0x2d0);
    *(undefined2 *)(iVar1 + 0x1c) = 0x24;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    FUN_800378c4(*(undefined4 *)(iVar1 + 0x18),0x11,param_1,0x12);
    FUN_8000bb18(param_1,0x1eb);
  }
  if (FLOAT_803e62ec < *(float *)(param_1 + 0x98)) {
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  return 0;
}

