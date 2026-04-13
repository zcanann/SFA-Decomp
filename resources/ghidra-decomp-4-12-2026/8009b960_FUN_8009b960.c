// Function: FUN_8009b960
// Entry: 8009b960
// Size: 756 bytes

void FUN_8009b960(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  double dVar1;
  undefined2 *puVar2;
  uint uVar3;
  undefined2 uVar4;
  int iVar5;
  undefined2 uVar6;
  undefined4 in_r8;
  undefined2 uVar7;
  undefined4 in_r9;
  undefined2 uVar8;
  undefined4 in_r10;
  double dVar9;
  double dVar10;
  undefined8 local_18;
  undefined8 local_8;
  
  iVar5 = (&DAT_8039c140)[(uint)(*(byte *)(param_9 + 0x45) >> 1) * 4];
  *(byte *)((int)param_9 + 0x8b) = *(byte *)((int)param_9 + 0x8b) & 0xfe;
  *(byte *)((int)param_9 + 0x8b) = *(byte *)((int)param_9 + 0x8b) & 0xfd | 2;
  uVar3 = *(uint *)(param_9 + 0x3e);
  if ((uVar3 & 0x8000000) == 0) {
    puVar2 = (undefined2 *)0x803105c0;
  }
  else {
    puVar2 = &DAT_803105a8;
  }
  if ((uVar3 & 0x40000000) != 0) {
    param_2 = (double)*(float *)(param_9 + 0x3a);
    if (param_2 < (double)FLOAT_803e0034) {
      if (((uVar3 & 0x1000000) == 0) || ((double)FLOAT_803e0034 <= param_2)) {
        param_2 = (double)FLOAT_803e003c;
        *(float *)(param_9 + 0x3a) =
             -(float)(param_2 * (double)FLOAT_803dc074 - (double)*(float *)(param_9 + 0x3a));
      }
      else {
        *(float *)(param_9 + 0x3a) =
             -(float)((double)FLOAT_803e0038 * (double)FLOAT_803dc074 - param_2);
      }
      goto LAB_8009ba84;
    }
  }
  if (((uVar3 & 0x1000000) == 0) ||
     (param_2 = (double)*(float *)(param_9 + 0x3a), param_2 <= (double)FLOAT_803e0040)) {
    if (((uVar3 & 8) != 0) &&
       (param_2 = (double)*(float *)(param_9 + 0x3a), (double)FLOAT_803e0040 < param_2)) {
      *(float *)(param_9 + 0x3a) =
           (float)((double)FLOAT_803e003c * (double)FLOAT_803dc074 + param_2);
    }
  }
  else {
    *(float *)(param_9 + 0x3a) = (float)((double)FLOAT_803e0038 * (double)FLOAT_803dc074 + param_2);
  }
LAB_8009ba84:
  dVar10 = (double)FLOAT_803e0044;
  *(float *)(param_9 + 0x2c) =
       (float)((double)*(float *)(param_9 + 0x38) * dVar10 + (double)*(float *)(param_9 + 0x2c));
  *(float *)(param_9 + 0x2e) =
       (float)((double)*(float *)(param_9 + 0x3a) * dVar10 + (double)*(float *)(param_9 + 0x2e));
  dVar9 = (double)*(float *)(param_9 + 0x3c);
  *(float *)(param_9 + 0x30) = (float)(dVar9 * dVar10 + (double)*(float *)(param_9 + 0x30));
  dVar1 = DOUBLE_803dfff8;
  if ((*(uint *)(param_9 + 0x3e) & 0x100000) == 0) {
    if ((*(uint *)(param_9 + 0x40) & 0x2000) != 0) {
      uVar3 = 0x43300000;
      local_8 = (double)CONCAT44(0x43300000,(uint)(ushort)param_9[0x44]);
      dVar9 = (double)(float)(local_8 - DOUBLE_803dfff8);
      param_9[0x42] =
           (short)(int)-(float)(dVar9 * dVar10 -
                               (double)(float)((double)CONCAT44(0x43300000,
                                                                (uint)(ushort)param_9[0x42]) -
                                              DOUBLE_803dfff8));
      param_2 = dVar1;
    }
  }
  else {
    uVar3 = 0x43300000;
    local_18 = (double)CONCAT44(0x43300000,(uint)(ushort)param_9[0x44]);
    dVar9 = (double)(float)(local_18 - DOUBLE_803dfff8);
    param_9[0x42] =
         (short)(int)(dVar9 * dVar10 +
                     (double)(float)((double)CONCAT44(0x43300000,(uint)(ushort)param_9[0x42]) -
                                    DOUBLE_803dfff8));
    param_2 = dVar1;
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
      if ((*(uint *)(param_9 + 0x3e) & 0x80) != 0) {
        uVar7 = 0x80;
        uVar8 = 0;
      }
      if ((*(uint *)(param_9 + 0x3e) & 0x40) != 0) {
        uVar4 = 0x80;
        uVar6 = 0;
      }
    }
    *param_9 = *puVar2;
    param_9[1] = puVar2[1];
    param_9[2] = puVar2[2];
    param_9[4] = uVar8;
    param_9[5] = uVar6;
    param_9[8] = puVar2[3];
    param_9[9] = puVar2[4];
    param_9[10] = puVar2[5];
    param_9[0xc] = uVar7;
    param_9[0xd] = uVar6;
    param_9[0x10] = puVar2[6];
    param_9[0x11] = puVar2[7];
    param_9[0x12] = puVar2[8];
    param_9[0x14] = uVar7;
    param_9[0x15] = uVar4;
    param_9[0x18] = puVar2[9];
    param_9[0x19] = puVar2[10];
    param_9[0x1a] = puVar2[0xb];
    param_9[0x1c] = uVar8;
    param_9[0x1d] = uVar4;
  }
  else {
    FUN_80137c30(dVar9,param_2,dVar10,param_4,param_5,param_6,param_7,param_8,s_notexture_803107dc,
                 &DAT_80310458,puVar2,uVar3,0,in_r8,in_r9,in_r10);
  }
  return;
}

