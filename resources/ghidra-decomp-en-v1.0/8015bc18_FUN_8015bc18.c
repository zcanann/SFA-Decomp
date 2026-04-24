// Function: FUN_8015bc18
// Entry: 8015bc18
// Size: 276 bytes

undefined4 FUN_8015bc18(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      *(undefined2 *)(iVar1 + 0x402) = 3;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e2d14,param_1,2,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(undefined2 *)(iVar1 + 0x402) = 2;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e2d34;
  }
  iVar1 = *(int *)(iVar1 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x10;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  *(undefined4 *)(param_2 + 0x280) = *(undefined4 *)(param_1 + 0x98);
  return 0;
}

