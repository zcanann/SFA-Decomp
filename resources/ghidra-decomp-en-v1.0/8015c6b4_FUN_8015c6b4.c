// Function: FUN_8015c6b4
// Entry: 8015c6b4
// Size: 276 bytes

undefined4 FUN_8015c6b4(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(short *)(param_2 + 0x276) != 4) && (*(char *)(param_2 + 0x27a) != '\0')) {
    FUN_80030334((double)FLOAT_803e2d14,param_1,0xe,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) | 0xc;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e2d38;
    *(float *)(param_2 + 0x280) = FLOAT_803e2d14;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    FUN_800200e8((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_80030334((double)FLOAT_803e2d14,param_1,8,0);
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(undefined *)(param_2 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return 0;
}

