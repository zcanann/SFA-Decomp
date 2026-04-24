// Function: FUN_80152b90
// Entry: 80152b90
// Size: 816 bytes

/* WARNING: Removing unreachable block (ram,0x80152ea0) */

void FUN_80152b90(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  char cVar5;
  int iVar3;
  uint uVar4;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  float local_38;
  float local_34;
  double local_30;
  double local_28;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x338));
  iVar3 = (int)(FLOAT_803e287c * FLOAT_803db414 + (float)(local_30 - DOUBLE_803e2898));
  local_28 = (double)(longlong)iVar3;
  *(short *)(param_2 + 0x338) = (short)iVar3;
  FUN_80293018(*(undefined2 *)(param_2 + 0x338),&local_34,&local_38);
  local_34 = local_34 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x324);
  local_38 = local_38 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x32c);
  if (*(char *)(param_2 + 0x33a) == '\0') {
    dVar8 = (double)*(float *)(param_1 + 0x10);
    fVar1 = *(float *)(param_2 + 0x324) - *(float *)(*(int *)(param_2 + 0x29c) + 0xc);
    fVar2 = *(float *)(param_2 + 0x32c) - *(float *)(*(int *)(param_2 + 0x29c) + 0x14);
    dVar7 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar7 <= (double)(FLOAT_803e2880 * *(float *)(param_2 + 0x2a8))) {
      *(undefined *)(param_2 + 0x33a) = 1;
      *(undefined *)(param_2 + 0x33b) = 0;
    }
  }
  else if (*(char *)(param_2 + 0x33a) == '\x01') {
    dVar8 = -(double)(FLOAT_803e2884 * FLOAT_803db414 - *(float *)(param_1 + 0x10));
    if ((double)(*(float *)(param_2 + 0x328) - FLOAT_803e2888) < dVar8) {
      local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x33b));
      iVar3 = (int)((float)(local_28 - DOUBLE_803e2898) + FLOAT_803db414);
      local_30 = (double)(longlong)iVar3;
      *(char *)(param_2 + 0x33b) = (char)iVar3;
      if (100 < *(byte *)(param_2 + 0x33b)) {
        *(undefined *)(param_2 + 0x33b) = 0;
        cVar5 = FUN_8002e04c();
        if (cVar5 != '\0') {
          iVar3 = FUN_8002bdf4(0x24,0x6b5);
          *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
          *(float *)(iVar3 + 0xc) = FLOAT_803e2878 + *(float *)(param_1 + 0x10);
          *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x14);
          *(undefined *)(iVar3 + 4) = 1;
          *(undefined *)(iVar3 + 5) = 1;
          *(undefined *)(iVar3 + 6) = 0xff;
          *(undefined *)(iVar3 + 7) = 0xff;
          iVar3 = FUN_8002b5a0(param_1);
          if (iVar3 != 0) {
            *(int *)(iVar3 + 0xc4) = param_1;
            FUN_8000bb18(param_1,0x249);
          }
        }
      }
    }
    else {
      *(undefined *)(param_2 + 0x33a) = 2;
    }
  }
  else {
    dVar8 = (double)(FLOAT_803e288c * FLOAT_803db414 + *(float *)(param_1 + 0x10));
    if ((double)*(float *)(param_2 + 0x328) <= dVar8) {
      *(undefined *)(param_2 + 0x33a) = 0;
    }
  }
  *(float *)(param_1 + 0x24) = FLOAT_803db418 * (local_34 - *(float *)(param_1 + 0xc));
  *(float *)(param_1 + 0x28) = FLOAT_803db418 * (float)(dVar8 - (double)*(float *)(param_1 + 0x10));
  *(float *)(param_1 + 0x2c) = FLOAT_803db418 * (local_38 - *(float *)(param_1 + 0x14));
  FUN_8014cd1c((double)FLOAT_803e2890,(double)FLOAT_803e2894,param_1,param_2,0xf,0);
  *(float *)(param_2 + 0x334) = *(float *)(param_2 + 0x334) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x334) <= FLOAT_803e2868) {
    uVar4 = FUN_800221a0(0x3c,0x78);
    local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    *(float *)(param_2 + 0x334) = (float)(local_28 - DOUBLE_803e2870);
    FUN_8000bb18(param_1,0x31);
  }
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x330) <= FLOAT_803e2868) {
    *(float *)(param_2 + 0x330) = FLOAT_803e286c;
    FUN_8000bb18(param_1,0x24a);
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

