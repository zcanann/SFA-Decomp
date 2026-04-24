// Function: FUN_8015e8bc
// Entry: 8015e8bc
// Size: 396 bytes

undefined4 FUN_8015e8bc(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2dc8,param_1,0xb,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) == '\0') {
    FUN_80035df4(param_1,10,1,0xffffffff);
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6c) = 10;
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6d) = 1;
    FUN_8003393c(param_1);
  }
  else {
    *(undefined *)(param_2 + 0x25f) = 1;
    FUN_800200e8((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e2de8 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e2dc0) /
         FLOAT_803e2dec;
    FUN_80035f20(param_1);
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 8) = *(byte *)(iVar1 + 8) | 4;
  }
  if (*(float *)(param_1 + 0x98) < FLOAT_803e2df0) {
    *(byte *)(iVar1 + 8) = *(byte *)(iVar1 + 8) | 2;
  }
  return 0;
}

