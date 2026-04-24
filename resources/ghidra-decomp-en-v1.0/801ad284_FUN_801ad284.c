// Function: FUN_801ad284
// Entry: 801ad284
// Size: 380 bytes

void FUN_801ad284(int param_1,int param_2)

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
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e46f8) /
       FLOAT_803e4730;
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    fVar1 = *(float *)(param_1 + 8);
    FUN_80035b50(param_1,(int)((float)((double)CONCAT44(0x43300000,
                                                        (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000)
                                      - DOUBLE_803e4728) * fVar1),
                 (int)((float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(iVar3 + 0x5c) ^ 0x80000000) -
                              DOUBLE_803e4728) * fVar1),
                 (int)((float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(iVar3 + 0x5e) ^ 0x80000000) -
                              DOUBLE_803e4728) * fVar1));
    FUN_80035f00(param_1);
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
    *puVar4 = &DAT_803236c4;
  }
  else {
    *puVar4 = &DAT_803236b8;
  }
  return;
}

