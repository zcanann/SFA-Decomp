// Function: FUN_8015a478
// Entry: 8015a478
// Size: 1112 bytes

void FUN_8015a478(short *param_1,int *param_2)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f8;
  undefined auStack_4c [6];
  undefined2 local_46;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar7 = *param_2;
  if ((param_2[0xd0] != 0) && (param_2[0xd0] == param_2[0xa7])) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    param_2[0xcc] = (int)FLOAT_803e390c;
  }
  param_2[0xba] = param_2[0xba] | 0x100;
  local_40 = FLOAT_803e38c8;
  local_3c = FLOAT_803e38cc;
  local_38 = FLOAT_803e38c8;
  local_44 = FLOAT_803e38bc;
  local_46 = 0x605;
  if ((param_1[0x58] & 0x800U) != 0) {
    in_r8 = 0;
    in_r9 = *DAT_803dd708;
    (**(code **)(in_r9 + 8))(param_1,1999,auStack_4c,2,0xffffffff);
    piVar5 = (int *)param_2[0xda];
    if (piVar5 != (int *)0x0) {
      FUN_8001de4c((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                   (double)*(float *)(param_1 + 10),piVar5);
    }
    else {
      if (piVar5 == (int *)0x0) {
        piVar5 = FUN_8001f58c(0,'\x01');
        param_2[0xda] = (int)piVar5;
      }
      if (param_2[0xda] != 0) {
        FUN_8001dbf0(param_2[0xda],2);
        FUN_8001de4c((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),(int *)param_2[0xda]);
        FUN_8001dbb4(param_2[0xda],0xc0,0x40,0xff,0xff);
        FUN_8001dadc(param_2[0xda],0xc0,0x40,0xff,0xff);
        FUN_8001dcfc((double)FLOAT_803e38a8,(double)FLOAT_803e38ac,param_2[0xda]);
        FUN_8001dc18(param_2[0xda],1);
        FUN_8001dc30((double)FLOAT_803e38b0,param_2[0xda],'\x01');
        FUN_8001d6e4(param_2[0xda],0,0);
        FUN_8001de04(param_2[0xda],0);
      }
    }
  }
  if ((param_2[0xb7] & 0x80000000U) != 0) {
    *(undefined *)((int)param_2 + 0x33a) = 3;
    param_2[0xb7] = param_2[0xb7] | 0x40000000;
  }
  iVar6 = param_2[0xa7];
  dVar10 = (double)FLOAT_803e38e0;
  dVar8 = (double)(float)(dVar10 + (double)*(float *)(iVar6 + 0x1c));
  dVar9 = (double)*(float *)(iVar6 + 0x20);
  dVar11 = (double)FLOAT_803e3910;
  dVar12 = (double)FLOAT_803e38e8;
  dVar13 = (double)(float)param_2[0xc1];
  FUN_8014cd98((double)*(float *)(iVar6 + 0x18),dVar8,dVar9,dVar10,dVar11,dVar12,dVar13,(int)param_1
              );
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    iVar6 = (uint)*(byte *)((int)param_2 + 0x33a) * 0xc;
    FUN_8014d504((double)*(float *)(&DAT_803207c0 + iVar6),dVar8,dVar9,dVar10,dVar11,dVar12,dVar13,
                 in_f8,(int)param_1,(int)param_2,(uint)(byte)(&DAT_803207c8)[iVar6],0,0,in_r8,in_r9,
                 in_r10);
    *(undefined *)((int)param_2 + 0x33a) =
         (&DAT_803207c9)[(uint)*(byte *)((int)param_2 + 0x33a) * 0xc];
  }
  dVar8 = (double)FUN_802932a4((double)(float)param_2[0xc1],(double)FLOAT_803dc074);
  uStack_2c = (int)param_1[1] ^ 0x80000000;
  local_30 = 0x43300000;
  iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e38c0) * dVar8);
  local_28 = (longlong)iVar6;
  param_1[1] = (short)iVar6;
  dVar8 = (double)FUN_802932a4((double)(float)param_2[0xc1],(double)FLOAT_803dc074);
  local_20 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  param_1[2] = (short)(int)((double)(float)(local_20 - DOUBLE_803e38c0) * dVar8);
  if (FLOAT_803e3908 <= (float)param_2[0xc9]) {
    param_2[0xc9] = (int)FLOAT_803e3908;
  }
  else {
    param_2[0xc9] = (int)(FLOAT_803e38ec * FLOAT_803dc074 + (float)param_2[0xc9]);
  }
  local_18 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  iVar6 = (int)((float)param_2[0xc9] * FLOAT_803dc074 + (float)(local_18 - DOUBLE_803e38c0));
  local_20 = (double)(longlong)iVar6;
  *param_1 = (short)iVar6;
  param_2[0xca] = (int)FLOAT_803e38d0;
  if ((param_2[0xb7] & 0x2000U) != 0) {
    fVar2 = *(float *)(iVar7 + 0x68) - *(float *)(param_1 + 0xc);
    fVar3 = *(float *)(iVar7 + 0x6c) - *(float *)(param_1 + 0xe);
    fVar4 = *(float *)(iVar7 + 0x70) - *(float *)(param_1 + 0x10);
    dVar8 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
    param_2[0xcb] = (int)(float)dVar8;
    if (FLOAT_803e38d8 < (float)param_2[0xcb]) {
      param_2[0xb9] = param_2[0xb9] | 0x10000;
      param_2[0xcc] = (int)FLOAT_803e38c8;
    }
  }
  if ((float)param_2[0xc9] <= FLOAT_803e38c8) {
    FUN_8000b844((int)param_1,1000);
  }
  else {
    FUN_8000bb38((uint)param_1,1000);
    iVar7 = (int)((FLOAT_803e3904 * (float)param_2[0xc9]) / FLOAT_803e3908);
    local_18 = (double)(longlong)iVar7;
    FUN_8000b9bc((double)((float)param_2[0xc9] / FLOAT_803e3908),(int)param_1,1000,(byte)iVar7);
  }
  if ((param_2[0xd0] != 0) &&
     ((sVar1 = *(short *)(param_2[0xd0] + 0x46), sVar1 == 0x1f || (sVar1 == 0)))) {
    FUN_8000bb38((uint)param_1,0x23d);
  }
  return;
}

