// Function: FUN_801e2a88
// Entry: 801e2a88
// Size: 160 bytes

void FUN_801e2a88(int param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  uVar1 = FUN_800221a0(0x5a,0xf0);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5828);
  pfVar2[1] = FLOAT_803e5810;
  pfVar2[2] = 1.681558e-42;
  *(undefined *)(pfVar2 + 3) = 4;
  *(char *)(param_1 + 0xad) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(param_1 + 0x46) != 0x69c) {
    DAT_803ddc40 = param_1;
  }
  return;
}

