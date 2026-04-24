// Function: FUN_8015bb00
// Entry: 8015bb00
// Size: 280 bytes

undefined4 FUN_8015bb00(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
  FUN_8003393c();
  if (*(byte *)(iVar2 + 0x406) < 0x33) {
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e2d14,param_1,0xe,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2d14,param_1,4,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2d28;
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 0xc;
  fVar1 = FLOAT_803e2d14;
  *(float *)(param_2 + 0x280) = FLOAT_803e2d14;
  *(float *)(param_2 + 0x284) = fVar1;
  if ((*(byte *)(iVar2 + 0x404) & 2) == 0) {
    *(float *)(param_2 + 0x280) = FLOAT_803e2d30 + *(float *)(param_1 + 0x98);
  }
  return 0;
}

