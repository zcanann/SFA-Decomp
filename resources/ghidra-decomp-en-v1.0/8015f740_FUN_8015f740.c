// Function: FUN_8015f740
// Entry: 8015f740
// Size: 944 bytes

void FUN_8015f740(short *param_1)

{
  float fVar1;
  float fVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  double dVar8;
  undefined auStack56 [4];
  undefined auStack52 [4];
  undefined auStack48 [4];
  float local_2c;
  float local_28;
  float local_24;
  double local_20;
  
  pfVar7 = *(float **)(param_1 + 0x5c);
  if (pfVar7[1] != FLOAT_803e2e34) {
    pfVar7[1] = pfVar7[1] - FLOAT_803db414;
    FUN_80099d84((double)FLOAT_803e2e30,(double)(pfVar7[1] / FLOAT_803e2e38),param_1,1,0);
    if (pfVar7[1] <= FLOAT_803e2e34) {
      pfVar7[1] = FLOAT_803e2e34;
    }
  }
  if ((*(byte *)((int)pfVar7 + 0x12) & 2) == 0) {
    piVar3 = (int *)FUN_800394ac(param_1,0,0);
    fVar1 = *pfVar7;
    if (FLOAT_803e2e3c <= fVar1) {
      if (FLOAT_803e2e40 - fVar1 < FLOAT_803db414) {
        *pfVar7 = FLOAT_803e2e34;
      }
      else {
        *pfVar7 = fVar1 + FLOAT_803db414;
      }
      *piVar3 = 0;
    }
    else {
      if ((int)fVar1 == 10) {
        *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) | 1;
      }
      local_20 = (double)(longlong)(int)*pfVar7;
      *piVar3 = (uint)(byte)(&DAT_8031ff80)[(int)*pfVar7] << 8;
      fVar2 = FLOAT_803e2e3c;
      fVar1 = *pfVar7 + FLOAT_803e2e30;
      *pfVar7 = fVar1;
      if (fVar2 == fVar1) {
        uVar4 = FUN_800221a0(0x10,0xf5);
        local_20 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        *pfVar7 = (float)(local_20 - DOUBLE_803e2e48);
      }
    }
    iVar5 = FUN_8002b9ec();
    fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(param_1 + 6);
    fVar2 = *(float *)(iVar5 + 0x14) - *(float *)(param_1 + 10);
    dVar8 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
    uVar4 = (uint)dVar8;
    local_20 = (double)(longlong)(int)uVar4;
    if ((uVar4 & 0xffff) < (uint)*(ushort *)(pfVar7 + 3)) {
      if ((uint)*(ushort *)(pfVar7 + 3) <= (uint)*(ushort *)(pfVar7 + 4)) {
        *(undefined *)((int)pfVar7 + 0x12) = 5;
        *pfVar7 = FLOAT_803e2e34;
      }
      if ((*(byte *)((int)pfVar7 + 0x12) & 5) != 0) {
        local_2c = *(float *)(iVar5 + 0x18) - *(float *)(param_1 + 0xc);
        local_28 = *(float *)(iVar5 + 0x1c) - *(float *)(param_1 + 0xe);
        local_24 = *(float *)(iVar5 + 0x20) - *(float *)(param_1 + 0x10);
        uVar6 = FUN_800217c0();
        uVar6 = (uVar6 & 0xffff) - ((int)*param_1 & 0xffffU);
        if (0x8000 < (int)uVar6) {
          uVar6 = uVar6 - 0xffff;
        }
        if ((int)uVar6 < -0x8000) {
          uVar6 = uVar6 + 0xffff;
        }
        if (((uVar6 & 0xffff) < (uint)*(ushort *)((int)pfVar7 + 0xe)) ||
           ((0xffff - *(ushort *)((int)pfVar7 + 0xe) & 0xffff) < (uVar6 & 0xffff))) {
          iVar5 = FUN_800221a0(0,99);
          if ((iVar5 < (int)(uint)*(byte *)(pfVar7 + 5)) ||
             ((*(byte *)((int)pfVar7 + 0x12) & 4) != 0)) {
            FUN_8000bb18(param_1,0x268);
            FUN_8015f5b0(param_1);
          }
          else {
            FUN_8000bb18(param_1,0x269);
          }
        }
        else {
          FUN_8000bb18(param_1,0x269);
        }
      }
    }
    else if ((*(byte *)((int)pfVar7 + 0x12) & 1) != 0) {
      FUN_8000bb18(param_1,0x269);
    }
    *(short *)(pfVar7 + 4) = (short)uVar4;
    iVar5 = FUN_8003687c(param_1,auStack48,auStack52,auStack56);
    if ((iVar5 == 0xe) &&
       (*(char *)((int)pfVar7 + 0x13) = *(char *)((int)pfVar7 + 0x13) + -1,
       *(char *)((int)pfVar7 + 0x13) == '\0')) {
      FUN_80035f00(param_1);
      param_1[3] = param_1[3] | 0x4000;
      *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) | 2;
      FUN_8000bb18(param_1,0x26a);
      FUN_800200e8((int)*(short *)((int)pfVar7 + 10),1);
      pfVar7[1] = FLOAT_803e2e38;
      FUN_8000bb18(param_1,0x1ec);
    }
    *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) & 0xfa;
  }
  return;
}

