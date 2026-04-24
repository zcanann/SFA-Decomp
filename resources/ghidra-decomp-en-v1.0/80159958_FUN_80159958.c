// Function: FUN_80159958
// Entry: 80159958
// Size: 1652 bytes

/* WARNING: Removing unreachable block (ram,0x80159fa8) */

void FUN_80159958(short *param_1,int *param_2)

{
  float fVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined auStack92 [6];
  undefined2 local_56;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  double local_40;
  double local_38;
  double local_30;
  longlong local_28;
  undefined auStack8 [8];
  
  fVar1 = FLOAT_803e2c30;
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar7 = *param_2;
  if (((float)param_2[0xcc] != FLOAT_803e2c30) &&
     (param_2[0xcc] = (int)((float)param_2[0xcc] - FLOAT_803db414), (float)param_2[0xcc] <= fVar1))
  {
    param_2[0xcc] = (int)fVar1;
  }
  param_2[0xba] = param_2[0xba] | 0x100;
  local_50 = FLOAT_803e2c30;
  local_4c = FLOAT_803e2c34;
  local_48 = FLOAT_803e2c30;
  local_54 = FLOAT_803e2c24;
  local_56 = 0x605;
  if ((param_1[0x58] & 0x800U) != 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,1999,auStack92,2,0xffffffff,0);
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
    *(undefined *)((int)param_2 + 0x33a) =
         (&DAT_8031fb7a)[(uint)*(byte *)((int)param_2 + 0x33a) * 0xc];
    param_2[0xca] = (int)FLOAT_803e2c38;
    FUN_8000b824(param_1,1000);
  }
  if ((param_2[0xb7] & 0x2000U) != 0) {
    fVar1 = *(float *)(iVar7 + 0x68) - *(float *)(param_1 + 0xc);
    fVar3 = *(float *)(iVar7 + 0x6c) - *(float *)(param_1 + 0xe);
    fVar4 = *(float *)(iVar7 + 0x70) - *(float *)(param_1 + 0x10);
    dVar9 = (double)FUN_802931a0((double)(fVar4 * fVar4 + fVar1 * fVar1 + fVar3 * fVar3));
    param_2[0xcb] = (int)(float)dVar9;
    if (((float)param_2[0xcb] < FLOAT_803e2c10) && ((float)param_2[0xcc] == FLOAT_803e2c30)) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
    }
    fVar1 = FLOAT_803e2c3c - (float)param_2[0xcb] / FLOAT_803e2c40;
    fVar3 = FLOAT_803e2c30;
    if ((FLOAT_803e2c30 <= fVar1) && (fVar3 = fVar1, FLOAT_803e2c3c < fVar1)) {
      fVar3 = FLOAT_803e2c3c;
    }
    iVar5 = FUN_80010320((double)((float)param_2[0xbf] * fVar3),iVar7);
    if ((((iVar5 != 0) || (*(int *)(iVar7 + 0x10) != 0)) &&
        (cVar6 = (**(code **)(*DAT_803dca9c + 0x90))(iVar7), cVar6 != '\0')) &&
       (cVar6 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e2c44,*param_2,param_1,&DAT_803dbcf8,0xffffffff),
       cVar6 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    FUN_8014c920((double)*(float *)(iVar7 + 0x68),(double)*(float *)(iVar7 + 0x6c),
                 (double)*(float *)(iVar7 + 0x70),(double)FLOAT_803e2c48,(double)FLOAT_803e2c4c,
                 (double)FLOAT_803e2c50,(double)(float)param_2[0xc1],param_1);
  }
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    iVar7 = (uint)*(byte *)((int)param_2 + 0x33a) * 0xc;
    FUN_8014d08c((double)*(float *)(&DAT_8031fb70 + iVar7),param_1,param_2,(&DAT_8031fb78)[iVar7],0,
                 0);
    *(undefined *)((int)param_2 + 0x33a) =
         (&DAT_8031fb79)[(uint)*(byte *)((int)param_2 + 0x33a) * 0xc];
  }
  if ((float)param_2[0xc9] <= FLOAT_803e2c30) {
    param_2[0xc9] = (int)FLOAT_803e2c30;
    dVar10 = (double)FLOAT_803e2c3c;
    dVar11 = (double)(float)(dVar10 - (double)(((float)param_2[0xca] - FLOAT_803e2c58) /
                                              FLOAT_803e2c5c));
    dVar9 = (double)FLOAT_803e2c60;
    if ((dVar9 <= dVar11) && (dVar9 = dVar11, dVar10 < dVar11)) {
      dVar9 = dVar10;
    }
    if ((float)param_2[0xca] <= FLOAT_803e2c58) {
      param_2[0xca] = (int)FLOAT_803e2c58;
    }
    else {
      param_2[0xca] = (int)((float)param_2[0xca] - FLOAT_803db414);
    }
    dVar10 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                          *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
    fVar1 = (float)(dVar10 / (double)FLOAT_803e2c48);
    fVar3 = FLOAT_803e2c30;
    if ((FLOAT_803e2c30 <= fVar1) && (fVar3 = fVar1, FLOAT_803e2c3c < fVar1)) {
      fVar3 = FLOAT_803e2c3c;
    }
    local_38 = (double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000);
    iVar7 = (int)((float)(local_38 - DOUBLE_803e2c28) -
                 fVar3 * (float)((double)FLOAT_803e2c64 * dVar9) * FLOAT_803db414);
    local_40 = (double)(longlong)iVar7;
    param_1[1] = (short)iVar7;
    local_30 = (double)(longlong)(int)(float)param_2[0xca];
    FUN_8014cd1c((double)(float)((double)FLOAT_803e2c68 * dVar9),(double)FLOAT_803e2c30,param_1,
                 param_2,(int)(float)param_2[0xca],1);
  }
  else {
    param_2[0xc9] = (int)-(FLOAT_803e2c54 * FLOAT_803db414 - (float)param_2[0xc9]);
    local_40 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
    iVar7 = (int)((float)param_2[0xc9] * FLOAT_803db414 + (float)(local_40 - DOUBLE_803e2c28));
    local_38 = (double)(longlong)iVar7;
    *param_1 = (short)iVar7;
  }
  dVar9 = (double)FUN_80292b44((double)(float)param_2[0xc1],(double)FLOAT_803db414);
  local_30 = (double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000);
  iVar7 = (int)((double)(float)(local_30 - DOUBLE_803e2c28) * dVar9);
  local_38 = (double)(longlong)iVar7;
  param_1[1] = (short)iVar7;
  dVar9 = (double)FUN_80292b44((double)(float)param_2[0xc1],(double)FLOAT_803db414);
  local_40 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  iVar7 = (int)((double)(float)(local_40 - DOUBLE_803e2c28) * dVar9);
  local_28 = (longlong)iVar7;
  param_1[2] = (short)iVar7;
  iVar7 = FUN_800221a0(0,0x2ee);
  if (iVar7 == 0) {
    FUN_8000bb18(param_1,0x3e9);
  }
  if ((float)param_2[0xc9] <= FLOAT_803e2c30) {
    FUN_8000b824(param_1,1000);
  }
  else {
    FUN_8000bb18(param_1,1000);
    iVar7 = (int)((FLOAT_803e2c6c * (float)param_2[0xc9]) / FLOAT_803e2c70);
    local_28 = (longlong)iVar7;
    FUN_8000b99c((double)((float)param_2[0xc9] / FLOAT_803e2c70),param_1,1000,iVar7);
  }
  if ((param_2[0xd0] != 0) &&
     ((sVar2 = *(short *)(param_2[0xd0] + 0x46), sVar2 == 0x1f || (sVar2 == 0)))) {
    FUN_8000bb18(param_1,0x23d);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return;
}

