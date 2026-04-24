// Function: FUN_8015c4ac
// Entry: 8015c4ac
// Size: 280 bytes

undefined4 FUN_8015c4ac(short *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2d14,param_1,9,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    *(undefined2 *)(iVar2 + 0x402) = 4;
  }
  *param_1 = (short)(int)(FLOAT_803e2d5c *
                          (((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x336) ^ 0x80000000)
                                   - DOUBLE_803e2d68) * FLOAT_803db414) / FLOAT_803e2d60) +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e2d68));
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2d38;
  *(float *)(param_2 + 0x280) = FLOAT_803e2d48;
  return 0;
}

