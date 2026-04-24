// Function: FUN_80162ca0
// Entry: 80162ca0
// Size: 684 bytes

void FUN_80162ca0(short *param_1)

{
  float fVar1;
  undefined uVar3;
  uint uVar2;
  float *pfVar4;
  int iVar5;
  undefined2 uVar6;
  int iVar7;
  float *pfVar8;
  undefined auStack_38 [4];
  float local_34;
  float local_30;
  int local_2c [7];
  
  iVar7 = *(int *)(param_1 + 0x5c);
  pfVar4 = (float *)FUN_80037048(0x17,local_2c);
  if (local_2c[0] != 0) {
    pfVar8 = *(float **)(iVar7 + 0x40c);
    pfVar8[0xd] = 0.0;
    pfVar8[0xf] = FLOAT_803e3bb8;
    for (iVar7 = 0; iVar7 < local_2c[0]; iVar7 = iVar7 + 1) {
      iVar5 = (**(code **)(**(int **)((int)*pfVar4 + 0x68) + 0x30))
                        ((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                         (double)*(float *)(param_1 + 10),*pfVar4,&local_30,&local_34,auStack_38);
      if ((iVar5 != 0) && (local_30 < pfVar8[0xf])) {
        pfVar8[0xd] = *pfVar4;
        pfVar8[0xf] = local_30;
        pfVar8[0x10] = local_34;
      }
      pfVar4 = pfVar4 + 1;
    }
    if (pfVar8[0xd] != 0.0) {
      pfVar8[0xe] = pfVar8[0xd];
      pfVar8[0x12] = pfVar8[0x10];
      (**(code **)(**(int **)((int)pfVar8[0xe] + 0x68) + 0x20))(pfVar8[0xe],pfVar8 + 3);
      (**(code **)(**(int **)((int)pfVar8[0xe] + 0x68) + 0x24))
                ((double)pfVar8[0x12],pfVar8[0xe],pfVar8 + 7,pfVar8 + 8,pfVar8 + 9);
      uVar6 = (**(code **)(**(int **)((int)pfVar8[0xe] + 0x68) + 0x34))();
      *(undefined2 *)(pfVar8 + 0x16) = uVar6;
      pfVar8[0x13] = pfVar8[0x12];
      *(undefined *)((int)pfVar8 + 0x46) = 0;
      pfVar8[1] = pfVar8[8];
      pfVar8[2] = *(float *)(param_1 + 8);
      *pfVar8 = pfVar8[1] - pfVar8[2];
      iVar7 = (int)*param_1 - (uint)*(ushort *)(pfVar8 + 0x16);
      if (0x8000 < iVar7) {
        iVar7 = iVar7 + -0xffff;
      }
      if (iVar7 < -0x8000) {
        iVar7 = iVar7 + 0xffff;
      }
      uVar3 = 0;
      if ((iVar7 < 0x3ffd) && (-0x3ffd < iVar7)) {
        uVar3 = 1;
      }
      *(undefined *)((int)pfVar8 + 0x45) = uVar3;
      uVar2 = countLeadingZeros((int)*(char *)((int)pfVar8 + 0x45));
      *param_1 = *(short *)(pfVar8 + 0x16) + (short)((uVar2 >> 5) << 0xf);
      uVar2 = FUN_80022264(10,0x3c);
      pfVar8[0x15] = -((float)((double)CONCAT44(0x43300000,
                                                *(char *)((int)pfVar8 + 0x45) * 2 - 1U ^ 0x80000000)
                              - DOUBLE_803e3b70) *
                       ((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3b70) /
                       FLOAT_803e3bbc) - pfVar8[0x12]);
      fVar1 = FLOAT_803e3b54;
      if (FLOAT_803e3b54 < pfVar8[0x15]) {
        fVar1 = pfVar8[0x15];
      }
      pfVar8[0x15] = fVar1;
      fVar1 = FLOAT_803e3ba4;
      if (pfVar8[0x15] < FLOAT_803e3ba4) {
        fVar1 = pfVar8[0x15];
      }
      pfVar8[0x15] = fVar1;
    }
  }
  return;
}

