// Function: FUN_8015e798
// Entry: 8015e798
// Size: 292 bytes

undefined4 FUN_8015e798(int param_1,int param_2)

{
  int unaff_r29;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2dc8,param_1,0xe,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (FLOAT_803e2de4 < *(float *)(param_1 + 0x98)) {
    unaff_r29 = *(int *)(iVar1 + 0x40c);
    *(byte *)(unaff_r29 + 8) = *(byte *)(unaff_r29 + 8) | 2;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f00(param_1);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e2dd8;
    *(float *)(param_2 + 0x280) = FLOAT_803e2dc8;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    FUN_800200e8((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_80030334((double)FLOAT_803e2dc8,param_1,8,0);
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(undefined *)(param_2 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    if ((*(byte *)(unaff_r29 + 9) & 2) == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  return 0;
}

