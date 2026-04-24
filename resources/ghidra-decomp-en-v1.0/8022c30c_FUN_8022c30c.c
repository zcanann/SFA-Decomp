// Function: FUN_8022c30c
// Entry: 8022c30c
// Size: 884 bytes

/* WARNING: Removing unreachable block (ram,0x8022c65c) */

void FUN_8022c30c(undefined4 param_1,int param_2)

{
  float fVar1;
  float fVar2;
  undefined2 uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_800395d8(*(undefined4 *)(param_2 + 4),0x14);
  if (((*(byte *)(param_2 + 0x478) < 4) && (iVar5 = FUN_8001ffb4(0x9d6), iVar5 == 0)) &&
     (iVar5 = FUN_8001ffb4(0x9d8), iVar5 == 0)) {
    dVar7 = (double)FUN_802945e0((double)(*(float *)(param_2 + 0x50) / *(float *)(param_2 + 0x5c)));
    dVar8 = (double)(float)((DOUBLE_803e6f48 + dVar7) * DOUBLE_803e6f50);
    FUN_8000da58(DOUBLE_803e6f48 + dVar7,param_1,0x29f);
    FUN_8000b888(dVar8,param_1,0x40,0xfe);
  }
  FUN_8022f270(*(undefined4 *)(param_2 + 4),*(undefined2 *)(param_2 + 0x44e));
  if (FLOAT_803e6ecc < *(float *)(param_2 + 0xb4)) {
    if ((*(ushort *)(param_2 + 0x3f4) & 0xc00) != 0) {
      FUN_8000bb18(param_1,0x381);
    }
    *(float *)(param_2 + 0xb4) = *(float *)(param_2 + 0xb4) - FLOAT_803db414;
    if (*(float *)(param_2 + 0xb4) <= FLOAT_803e6ecc) {
      *(float *)(param_2 + 0xb0) = FLOAT_803e6f5c;
    }
  }
  else {
    if ((*(byte *)(param_2 + 0x477) & 2) == 0) {
      if ((*(ushort *)(param_2 + 0x3f4) & 0x800) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfb;
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) | 2;
        *(float *)(param_2 + 0xb0) = FLOAT_803e6f58;
        FUN_8000b4d0(param_1,0x2b6,3);
      }
    }
    else {
      *(undefined4 *)(param_2 + 0x6c) = *(undefined4 *)(param_2 + 0x88);
      *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(param_2 + 0x90);
      if ((*(ushort *)(param_2 + 0x3f6) & 0x800) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfd;
        *(float *)(param_2 + 0xb0) = FLOAT_803e6f5c;
      }
    }
    if ((*(byte *)(param_2 + 0x477) & 4) == 0) {
      if ((*(ushort *)(param_2 + 0x3f4) & 0x400) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfd;
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) | 4;
        *(float *)(param_2 + 0xb0) = FLOAT_803e6f60;
        FUN_8000b4d0(param_1,0x2b7,3);
      }
    }
    else {
      *(undefined4 *)(param_2 + 0x6c) = *(undefined4 *)(param_2 + 0x8c);
      *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(param_2 + 0x94);
      if ((*(ushort *)(param_2 + 0x3f6) & 0x400) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfb;
        *(float *)(param_2 + 0xb0) = FLOAT_803e6f5c;
      }
    }
  }
  if ((*(byte *)(param_2 + 0x477) & 6) == 0) {
    *(float *)(param_2 + 0x6c) = FLOAT_803e6ed0;
    *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(param_2 + 0x98);
    if (FLOAT_803e6ecc < *(float *)(param_2 + 0xbc)) {
      *(float *)(param_2 + 0xbc) = *(float *)(param_2 + 0xbc) - FLOAT_803db414;
    }
    else {
      *(float *)(param_2 + 0x9c) = FLOAT_803e6f64 * FLOAT_803db414 + *(float *)(param_2 + 0x9c);
    }
  }
  else {
    *(float *)(param_2 + 0x9c) = *(float *)(param_2 + 0x9c) - FLOAT_803db414;
    *(float *)(param_2 + 0xbc) = FLOAT_803e6f38;
  }
  fVar1 = *(float *)(param_2 + 0x9c);
  fVar2 = FLOAT_803e6ecc;
  if ((FLOAT_803e6ecc <= fVar1) && (fVar2 = fVar1, *(float *)(param_2 + 0xa0) < fVar1)) {
    fVar2 = *(float *)(param_2 + 0xa0);
  }
  *(float *)(param_2 + 0x9c) = fVar2;
  fVar1 = FLOAT_803e6ecc;
  if (*(float *)(param_2 + 0x9c) <= FLOAT_803e6ecc) {
    *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xf9;
    *(undefined4 *)(param_2 + 0xb4) = *(undefined4 *)(param_2 + 0xb8);
    *(undefined4 *)(param_2 + 0x9c) = *(undefined4 *)(param_2 + 0xa0);
    *(float *)(param_2 + 0xb0) = FLOAT_803e6f68;
    *(float *)(param_2 + 0xbc) = fVar1;
  }
  if (iVar4 != 0) {
    *(float *)(param_2 + 0xac) =
         FLOAT_803e6ef8 * (*(float *)(param_2 + 0xb0) - *(float *)(param_2 + 0xac)) +
         *(float *)(param_2 + 0xac);
    uVar3 = (undefined2)(int)*(float *)(param_2 + 0xac);
    *(undefined2 *)(iVar4 + 10) = uVar3;
    *(undefined2 *)(iVar4 + 8) = uVar3;
    *(undefined2 *)(iVar4 + 6) = uVar3;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

