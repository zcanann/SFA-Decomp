// Function: FUN_8009b6d4
// Entry: 8009b6d4
// Size: 756 bytes

void FUN_8009b6d4(undefined2 *param_1)

{
  float fVar1;
  undefined2 *puVar2;
  uint uVar3;
  undefined2 uVar4;
  int iVar5;
  undefined2 uVar6;
  undefined2 uVar7;
  undefined2 uVar8;
  double local_18;
  double local_8;
  
  iVar5 = (&DAT_8039b4e0)[(uint)(*(byte *)(param_1 + 0x45) >> 1) * 4];
  *(byte *)((int)param_1 + 0x8b) = *(byte *)((int)param_1 + 0x8b) & 0xfe;
  *(byte *)((int)param_1 + 0x8b) = *(byte *)((int)param_1 + 0x8b) & 0xfd | 2;
  uVar3 = *(uint *)(param_1 + 0x3e);
  if ((uVar3 & 0x8000000) == 0) {
    puVar2 = (undefined2 *)0x8030fa00;
  }
  else {
    puVar2 = &DAT_8030f9e8;
  }
  if ((uVar3 & 0x40000000) != 0) {
    fVar1 = *(float *)(param_1 + 0x3a);
    if (fVar1 < FLOAT_803df3b4) {
      if (((uVar3 & 0x1000000) == 0) || (FLOAT_803df3b4 <= fVar1)) {
        *(float *)(param_1 + 0x3a) = -(FLOAT_803df3bc * FLOAT_803db414 - *(float *)(param_1 + 0x3a))
        ;
      }
      else {
        *(float *)(param_1 + 0x3a) = -(FLOAT_803df3b8 * FLOAT_803db414 - fVar1);
      }
      goto LAB_8009b7f8;
    }
  }
  if (((uVar3 & 0x1000000) == 0) || (*(float *)(param_1 + 0x3a) <= FLOAT_803df3c0)) {
    if (((uVar3 & 8) != 0) && (FLOAT_803df3c0 < *(float *)(param_1 + 0x3a))) {
      *(float *)(param_1 + 0x3a) = FLOAT_803df3bc * FLOAT_803db414 + *(float *)(param_1 + 0x3a);
    }
  }
  else {
    *(float *)(param_1 + 0x3a) = FLOAT_803df3b8 * FLOAT_803db414 + *(float *)(param_1 + 0x3a);
  }
LAB_8009b7f8:
  fVar1 = FLOAT_803df3c4;
  *(float *)(param_1 + 0x2c) =
       *(float *)(param_1 + 0x38) * FLOAT_803df3c4 + *(float *)(param_1 + 0x2c);
  *(float *)(param_1 + 0x2e) = *(float *)(param_1 + 0x3a) * fVar1 + *(float *)(param_1 + 0x2e);
  *(float *)(param_1 + 0x30) = *(float *)(param_1 + 0x3c) * fVar1 + *(float *)(param_1 + 0x30);
  if ((*(uint *)(param_1 + 0x3e) & 0x100000) == 0) {
    if ((*(uint *)(param_1 + 0x40) & 0x2000) != 0) {
      local_8 = (double)CONCAT44(0x43300000,(uint)(ushort)param_1[0x44]);
      param_1[0x42] =
           (short)(int)-((float)(local_8 - DOUBLE_803df378) * fVar1 -
                        (float)((double)CONCAT44(0x43300000,(uint)(ushort)param_1[0x42]) -
                               DOUBLE_803df378));
    }
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)(ushort)param_1[0x44]);
    param_1[0x42] =
         (short)(int)((float)(local_18 - DOUBLE_803df378) * fVar1 +
                     (float)((double)CONCAT44(0x43300000,(uint)(ushort)param_1[0x42]) -
                            DOUBLE_803df378));
  }
  if (iVar5 != 0) {
    uVar6 = 0;
    uVar4 = 0;
    uVar8 = 0;
    uVar7 = 0;
    if (iVar5 != 0) {
      uVar8 = 0x80;
      uVar6 = 0x80;
      uVar7 = 0;
      if ((*(uint *)(param_1 + 0x3e) & 0x80) != 0) {
        uVar7 = 0x80;
        uVar8 = 0;
      }
      if ((*(uint *)(param_1 + 0x3e) & 0x40) != 0) {
        uVar4 = 0x80;
        uVar6 = 0;
      }
    }
    *param_1 = *puVar2;
    param_1[1] = puVar2[1];
    param_1[2] = puVar2[2];
    param_1[4] = uVar8;
    param_1[5] = uVar6;
    param_1[8] = puVar2[3];
    param_1[9] = puVar2[4];
    param_1[10] = puVar2[5];
    param_1[0xc] = uVar7;
    param_1[0xd] = uVar6;
    param_1[0x10] = puVar2[6];
    param_1[0x11] = puVar2[7];
    param_1[0x12] = puVar2[8];
    param_1[0x14] = uVar7;
    param_1[0x15] = uVar4;
    param_1[0x18] = puVar2[9];
    param_1[0x19] = puVar2[10];
    param_1[0x1a] = puVar2[0xb];
    param_1[0x1c] = uVar8;
    param_1[0x1d] = uVar4;
  }
  else {
    FUN_801378a8(s_notexture_8030fc1c);
  }
  return;
}

