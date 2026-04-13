// Function: FUN_801ad838
// Entry: 801ad838
// Size: 380 bytes

void FUN_801ad838(int param_1,int param_2)

{
  float fVar1;
  float *pfVar2;
  int iVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0xb8);
  *(undefined *)(puVar4 + 3) = 0;
  puVar4[2] = *(undefined4 *)(param_1 + 0x10);
  *(undefined2 *)(puVar4 + 4) = *(undefined2 *)(param_2 + 0x1e);
  *(float *)(param_1 + 8) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e5390) /
       FLOAT_803e53c8;
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    fVar1 = *(float *)(param_1 + 8);
    FUN_80035c48(param_1,(short)(int)((float)((double)CONCAT44(0x43300000,
                                                               (int)*(short *)(iVar3 + 0x5a) ^
                                                               0x80000000) - DOUBLE_803e53c0) *
                                     fVar1),
                 (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar3 + 0x5c) ^ 0x80000000) -
                                     DOUBLE_803e53c0) * fVar1),
                 (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar3 + 0x5e) ^ 0x80000000) -
                                     DOUBLE_803e53c0) * fVar1));
    FUN_80035ff8(param_1);
  }
  pfVar2 = *(float **)(param_1 + 100);
  if (pfVar2 != (float *)0x0) {
    pfVar2[0xc] = (float)((uint)pfVar2[0xc] | 0xb0);
    pfVar2[0xc] = (float)((uint)pfVar2[0xc] | 0xc00);
    pfVar2[8] = *(float *)(param_1 + 0xc);
    pfVar2[10] = *(float *)(param_1 + 0x14);
    *pfVar2 = *pfVar2 * *(float *)(param_1 + 8);
  }
  if (*(short *)(param_1 + 0x46) == 0x600) {
    *puVar4 = &DAT_80324304;
  }
  else {
    *puVar4 = &DAT_803242f8;
  }
  return;
}

