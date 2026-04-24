// Function: FUN_80159fcc
// Entry: 80159fcc
// Size: 1112 bytes

void FUN_80159fcc(short *param_1,int *param_2)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  undefined auStack76 [6];
  undefined2 local_46;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  double local_20;
  double local_18;
  
  iVar6 = *param_2;
  if ((param_2[0xd0] != 0) && (param_2[0xd0] == param_2[0xa7])) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    param_2[0xcc] = (int)FLOAT_803e2c74;
  }
  param_2[0xba] = param_2[0xba] | 0x100;
  local_40 = FLOAT_803e2c30;
  local_3c = FLOAT_803e2c34;
  local_38 = FLOAT_803e2c30;
  local_44 = FLOAT_803e2c24;
  local_46 = 0x605;
  if ((param_1[0x58] & 0x800U) != 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,1999,auStack76,2,0xffffffff,0);
    if (param_2[0xda] != 0) {
      FUN_8001dd88((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                   (double)*(float *)(param_1 + 10));
    }
    else {
      if (param_2[0xda] == 0) {
        iVar5 = FUN_8001f4c8(0,1);
        param_2[0xda] = iVar5;
      }
      if (param_2[0xda] != 0) {
        FUN_8001db2c(param_2[0xda],2);
        FUN_8001dd88((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),param_2[0xda]);
        FUN_8001daf0(param_2[0xda],0xc0,0x40,0xff,0xff);
        FUN_8001da18(param_2[0xda],0xc0,0x40,0xff,0xff);
        FUN_8001dc38((double)FLOAT_803e2c10,(double)FLOAT_803e2c14,param_2[0xda]);
        FUN_8001db54(param_2[0xda],1);
        FUN_8001db6c((double)FLOAT_803e2c18,param_2[0xda],1);
        FUN_8001d620(param_2[0xda],0,0);
        FUN_8001dd40(param_2[0xda],0);
      }
    }
  }
  if ((param_2[0xb7] & 0x80000000U) != 0) {
    *(undefined *)((int)param_2 + 0x33a) = 3;
    param_2[0xb7] = param_2[0xb7] | 0x40000000;
  }
  iVar5 = param_2[0xa7];
  FUN_8014c920((double)*(float *)(iVar5 + 0x18),
               (double)(float)((double)FLOAT_803e2c48 + (double)*(float *)(iVar5 + 0x1c)),
               (double)*(float *)(iVar5 + 0x20),(double)FLOAT_803e2c48,(double)FLOAT_803e2c78,
               (double)FLOAT_803e2c50,(double)(float)param_2[0xc1],param_1);
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    iVar5 = (uint)*(byte *)((int)param_2 + 0x33a) * 0xc;
    FUN_8014d08c((double)*(float *)(&DAT_8031fb70 + iVar5),param_1,param_2,(&DAT_8031fb78)[iVar5],0,
                 0);
    *(undefined *)((int)param_2 + 0x33a) =
         (&DAT_8031fb79)[(uint)*(byte *)((int)param_2 + 0x33a) * 0xc];
  }
  dVar7 = (double)FUN_80292b44((double)(float)param_2[0xc1],(double)FLOAT_803db414);
  uStack44 = (int)param_1[1] ^ 0x80000000;
  local_30 = 0x43300000;
  iVar5 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e2c28) * dVar7);
  local_28 = (longlong)iVar5;
  param_1[1] = (short)iVar5;
  dVar7 = (double)FUN_80292b44((double)(float)param_2[0xc1],(double)FLOAT_803db414);
  local_20 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  param_1[2] = (short)(int)((double)(float)(local_20 - DOUBLE_803e2c28) * dVar7);
  if (FLOAT_803e2c70 <= (float)param_2[0xc9]) {
    param_2[0xc9] = (int)FLOAT_803e2c70;
  }
  else {
    param_2[0xc9] = (int)(FLOAT_803e2c54 * FLOAT_803db414 + (float)param_2[0xc9]);
  }
  local_18 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  iVar5 = (int)((float)param_2[0xc9] * FLOAT_803db414 + (float)(local_18 - DOUBLE_803e2c28));
  local_20 = (double)(longlong)iVar5;
  *param_1 = (short)iVar5;
  param_2[0xca] = (int)FLOAT_803e2c38;
  if ((param_2[0xb7] & 0x2000U) != 0) {
    fVar2 = *(float *)(iVar6 + 0x68) - *(float *)(param_1 + 0xc);
    fVar3 = *(float *)(iVar6 + 0x6c) - *(float *)(param_1 + 0xe);
    fVar4 = *(float *)(iVar6 + 0x70) - *(float *)(param_1 + 0x10);
    dVar7 = (double)FUN_802931a0((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
    param_2[0xcb] = (int)(float)dVar7;
    if (FLOAT_803e2c40 < (float)param_2[0xcb]) {
      param_2[0xb9] = param_2[0xb9] | 0x10000;
      param_2[0xcc] = (int)FLOAT_803e2c30;
    }
  }
  if ((float)param_2[0xc9] <= FLOAT_803e2c30) {
    FUN_8000b824(param_1,1000);
  }
  else {
    FUN_8000bb18(param_1,1000);
    iVar6 = (int)((FLOAT_803e2c6c * (float)param_2[0xc9]) / FLOAT_803e2c70);
    local_18 = (double)(longlong)iVar6;
    FUN_8000b99c((double)((float)param_2[0xc9] / FLOAT_803e2c70),param_1,1000,iVar6);
  }
  if ((param_2[0xd0] != 0) &&
     ((sVar1 = *(short *)(param_2[0xd0] + 0x46), sVar1 == 0x1f || (sVar1 == 0)))) {
    FUN_8000bb18(param_1,0x23d);
  }
  return;
}

