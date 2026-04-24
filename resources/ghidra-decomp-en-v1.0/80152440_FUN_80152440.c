// Function: FUN_80152440
// Entry: 80152440
// Size: 212 bytes

void FUN_80152440(int param_1,int param_2,undefined4 param_3,int param_4)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((param_4 != 0x10) && (param_4 != 0x11)) {
    FUN_8000bb18(param_1,0x23);
    FUN_8000bb18(param_1,0x31b);
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    *(float *)(param_2 + 0x32c) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 0x2c) & 0xffff) -
                DOUBLE_803e2818);
    FUN_8014d08c((double)FLOAT_803e2810,param_1,param_2,1,0,0);
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) & 0xffffffdf;
    fVar1 = FLOAT_803e2814;
    *(float *)(param_1 + 0x2c) = FLOAT_803e2814;
    *(float *)(param_1 + 0x28) = fVar1;
    *(float *)(param_1 + 0x24) = fVar1;
  }
  return;
}

