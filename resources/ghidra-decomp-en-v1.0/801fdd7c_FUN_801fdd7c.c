// Function: FUN_801fdd7c
// Entry: 801fdd7c
// Size: 272 bytes

void FUN_801fdd7c(int param_1,int param_2)

{
  double dVar1;
  uint uVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)(param_2 + 0x1e);
  uVar2 = FUN_800221a0(10,0x19);
  dVar1 = DOUBLE_803e61b8;
  *pfVar3 = FLOAT_803e61b4 *
            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e61b8);
  *(undefined2 *)((int)pfVar3 + 0xe) = 0x14;
  *(float *)(param_1 + 0x10) =
       *(float *)(param_2 + 0xc) +
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) - dVar1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  uVar2 = FUN_800221a0(0x1e,0x3c);
  pfVar3[1] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e61b8);
  uVar2 = FUN_800221a0(100,200);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e61b8);
  return;
}

