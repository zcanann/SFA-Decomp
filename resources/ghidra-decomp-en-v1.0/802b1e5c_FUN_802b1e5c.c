// Function: FUN_802b1e5c
// Entry: 802b1e5c
// Size: 1600 bytes

/* WARNING: Removing unreachable block (ram,0x802b2470) */
/* WARNING: Removing unreachable block (ram,0x802b2468) */
/* WARNING: Removing unreachable block (ram,0x802b2478) */

void FUN_802b1e5c(double param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f29;
  undefined8 in_f30;
  double in_f31;
  float local_78;
  float local_74;
  float **local_70;
  float local_6c [4];
  float local_5c;
  float local_58;
  float local_54;
  double local_50;
  double local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  fVar2 = FLOAT_803e7ee0;
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar9 = 0;
  *(float *)(param_3 + 0x82c) = FLOAT_803e7ee0;
  *(float *)(param_3 + 0x834) = fVar2;
  *(float *)(param_3 + 0x830) = FLOAT_803e8144;
  *(undefined *)(param_3 + 0x86c) = 0;
  bVar1 = (*(byte *)(param_3 + 0x3f0) >> 5 & 1) == 0;
  if ((bVar1) || ((!bVar1 && (FLOAT_803e80d0 != *(float *)(param_4 + 0x1c0))))) {
    *(undefined4 *)(param_3 + 0x83c) = *(undefined4 *)(param_4 + 0x1c0);
  }
  if (FLOAT_803e80d0 == *(float *)(param_3 + 0x83c)) {
    *(float *)(param_3 + 0x838) = FLOAT_803e7ea4;
  }
  else {
    *(float *)(param_3 + 0x838) = *(float *)(param_3 + 0x83c) - *(float *)(param_2 + 0x1c);
  }
  *(byte *)(param_3 + 0x3f1) = *(byte *)(param_3 + 0x3f1) & 0xfe;
  dVar12 = (double)FLOAT_803e7ea4;
  local_74 = FLOAT_803e7ea4;
  local_78 = FLOAT_803e7ea4;
  if ((*(byte *)(param_4 + 0x264) & 0x10) != 0) {
    *(byte *)(param_3 + 0x3f1) = *(byte *)(param_3 + 0x3f1) & 0xfe | 1;
    *(undefined *)(param_3 + 0x86c) = *(undefined *)(param_4 + 0xbc);
    fVar2 = FLOAT_803e7ee0;
    switch(*(undefined *)(param_3 + 0x86c)) {
    case 3:
      *(float *)(param_3 + 0x82c) = FLOAT_803e7ee0;
      *(float *)(param_3 + 0x834) = fVar2;
      *(float *)(param_3 + 0x830) = FLOAT_803e7f6c;
      break;
    default:
      *(undefined2 *)(param_3 + 0x808) = 0;
      if (*(float *)(param_3 + 0x7c8) < FLOAT_803e7ea4) {
        fVar2 = FLOAT_803e7efc * *(float *)(param_4 + 0x280) + *(float *)(param_3 + 0x7c8);
        fVar3 = FLOAT_803e7ea4;
        if (fVar2 < FLOAT_803e7ea4) {
          fVar3 = fVar2;
        }
        *(float *)(param_3 + 0x7c8) = fVar3;
        in_f31 = -(double)*(float *)(param_3 + 0x7c8);
      }
      break;
    case 6:
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x808) ^ 0x80000000);
      iVar6 = (int)((double)(float)(local_50 - DOUBLE_803e7ec0) - param_1);
      local_48 = (double)(longlong)iVar6;
      sVar4 = (short)iVar6;
      *(short *)(param_3 + 0x808) = sVar4;
      if (sVar4 < 1) {
        *(undefined2 *)(param_3 + 0x808) = 0x3c;
        FUN_80036450(param_2,0,0x14,2,0);
      }
      break;
    case 8:
      FUN_80036450(param_2,0,1,0,0);
      break;
    case 0xd:
      *(float *)(param_3 + 0x82c) = FLOAT_803e8148;
      *(float *)(param_3 + 0x834) = FLOAT_803e814c;
      *(float *)(param_3 + 0x830) = FLOAT_803e8118;
      break;
    case 0x1a:
      local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x808) ^ 0x80000000);
      iVar6 = (int)((double)(float)(local_48 - DOUBLE_803e7ec0) - param_1);
      local_50 = (double)(longlong)iVar6;
      sVar4 = (short)iVar6;
      *(short *)(param_3 + 0x808) = sVar4;
      if (sVar4 < 1) {
        *(undefined2 *)(param_3 + 0x808) = 0x3c;
        FUN_8003842c(param_2,0xb,&local_5c,&local_58,&local_54,0);
        FUN_800365b8((double)local_5c,(double)local_58,(double)local_54,param_2,0,0x14,2,0xffffffff)
        ;
      }
      break;
    case 0x1c:
      iVar6 = FUN_8001ffb4(0x21);
      if (iVar6 == 0) {
        local_48 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x8a0));
        iVar6 = (int)((double)(float)(local_48 - DOUBLE_803e7f38) + param_1);
        local_50 = (double)(longlong)iVar6;
        *(short *)(param_3 + 0x8a0) = (short)iVar6;
        if (0x78 < *(ushort *)(param_3 + 0x8a0)) {
          *(ushort *)(param_3 + 0x8a0) = *(ushort *)(param_3 + 0x8a0) - 0x78;
          FUN_8003842c(param_2,0xb,&local_5c,&local_58,&local_54,0);
          FUN_800365b8((double)local_5c,(double)local_58,(double)local_54,param_2,0,0x16,2,
                       0xffffffff);
        }
      }
      break;
    case 0x1d:
      local_6c[0] = FLOAT_803e8150;
      iVar9 = FUN_80036e58(0x16,param_2,local_6c);
      if (iVar9 != 0) {
        (**(code **)(**(int **)(iVar9 + 0x68) + 0x20))
                  ((double)FLOAT_803e7ee0,iVar9,param_2,&local_74,&local_78);
      }
      break;
    case 0x1f:
      FUN_800200e8(0x643,1);
      break;
    case 0x20:
      if (*(float *)(param_4 + 0x280) <= FLOAT_803e7e98) {
        *(float *)(param_3 + 0x7c8) =
             -(float)((double)FLOAT_803e7e90 * param_1 - (double)*(float *)(param_3 + 0x7c8));
        if ((double)FLOAT_803de440 <= dVar12) {
          FUN_8000bb18(param_2,0x208);
          uVar5 = FUN_800221a0(0x27,0x3c);
          local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          FLOAT_803de440 = (float)(local_48 - DOUBLE_803e7ec0);
        }
        else {
          FLOAT_803de440 = (float)((double)FLOAT_803de440 - param_1);
        }
      }
      else {
        dVar11 = (double)(FLOAT_803e7f6c + *(float *)(param_3 + 0x7c8));
        if (dVar11 < dVar12) {
          dVar12 = dVar11;
        }
        *(float *)(param_3 + 0x7c8) = (float)dVar12;
      }
      iVar6 = FUN_80065e50((double)*(float *)(param_2 + 0xc),(double)*(float *)(param_2 + 0x10),
                           (double)*(float *)(param_2 + 0x14),param_2,&local_70,0,0x20);
      in_f31 = -(double)*(float *)(param_3 + 0x7c8);
      if ((1 < iVar6) &&
         (in_f31 = (double)(float)(in_f31 + (double)(**local_70 - *local_70[iVar6 + -1])),
         (double)FLOAT_803e7fa0 < in_f31)) {
        iVar7 = *(int *)(param_2 + 0xb8);
        pcVar8 = *(char **)(iVar7 + 0x35c);
        iVar6 = *pcVar8 + -1;
        if (iVar6 < 0) {
          iVar6 = 0;
        }
        else if (pcVar8[1] < iVar6) {
          iVar6 = (int)pcVar8[1];
        }
        *pcVar8 = (char)iVar6;
        if (**(char **)(iVar7 + 0x35c) < '\x01') {
          FUN_802aaa80(param_2);
        }
      }
    }
    if (in_f31 != (double)FLOAT_803e7ea4) {
      dVar12 = -(double)(float)((double)FLOAT_803e7f6c * in_f31 - (double)FLOAT_803e7ee0);
      if (dVar12 < (double)FLOAT_803e7f14) {
        dVar12 = (double)FLOAT_803e7f14;
      }
      dVar11 = (double)FUN_80292b44(dVar12,param_1);
      *(float *)(param_2 + 0x24) = (float)((double)*(float *)(param_2 + 0x24) * dVar11);
      dVar12 = (double)FUN_80292b44(dVar12,param_1);
      *(float *)(param_2 + 0x2c) = (float)((double)*(float *)(param_2 + 0x2c) * dVar12);
    }
  }
  dVar12 = (double)FUN_80021370((double)(local_74 - *(float *)(param_3 + 0x890)),
                                (double)FLOAT_803e7fcc,(double)FLOAT_803db414);
  *(float *)(param_3 + 0x890) = (float)((double)*(float *)(param_3 + 0x890) + dVar12);
  dVar12 = (double)FUN_80021370((double)(local_78 - *(float *)(param_3 + 0x894)),
                                (double)FLOAT_803e7fcc,(double)FLOAT_803db414);
  *(float *)(param_3 + 0x894) = (float)((double)*(float *)(param_3 + 0x894) + dVar12);
  if (iVar9 == 0) {
    dVar12 = (double)FUN_80292b44((double)FLOAT_803e7ff4,(double)FLOAT_803db414);
    *(float *)(param_3 + 0x890) = (float)((double)*(float *)(param_3 + 0x890) * dVar12);
    dVar12 = (double)FUN_80292b44((double)FLOAT_803e7ff4,(double)FLOAT_803db414);
    *(float *)(param_3 + 0x894) = (float)((double)*(float *)(param_3 + 0x894) * dVar12);
  }
  if ((FLOAT_803e7fec < *(float *)(param_3 + 0x890)) &&
     (*(float *)(param_3 + 0x890) < FLOAT_803e7ef8)) {
    *(float *)(param_3 + 0x890) = FLOAT_803e7ea4;
  }
  if ((FLOAT_803e7fec < *(float *)(param_3 + 0x894)) &&
     (*(float *)(param_3 + 0x894) < FLOAT_803e7ef8)) {
    *(float *)(param_3 + 0x894) = FLOAT_803e7ea4;
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  return;
}

