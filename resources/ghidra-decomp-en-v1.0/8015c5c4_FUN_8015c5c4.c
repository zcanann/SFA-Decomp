// Function: FUN_8015c5c4
// Entry: 8015c5c4
// Size: 240 bytes

undefined4 FUN_8015c5c4(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
  FUN_8003393c();
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2d14,param_1,4,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2d28;
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x10;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  return 0;
}

