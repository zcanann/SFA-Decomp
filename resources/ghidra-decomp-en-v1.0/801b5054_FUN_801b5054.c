// Function: FUN_801b5054
// Entry: 801b5054
// Size: 1532 bytes

/* WARNING: Removing unreachable block (ram,0x801b5630) */

void FUN_801b5054(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined2 uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  float local_b8;
  float local_b4;
  float local_b0;
  undefined auStack172 [48];
  undefined auStack124 [52];
  double local_48;
  undefined4 local_40;
  uint uStack60;
  double local_38;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar14 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar14 >> 0x20);
  iVar2 = (int)uVar14;
  iVar9 = *(int *)(iVar3 + 0xb8);
  *(undefined *)(iVar9 + 0xa58) = 0;
  if ((int)*(short *)(iVar2 + 0x1a) == 0) {
    dVar13 = (double)FLOAT_803e49a8;
  }
  else {
    local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 0x1a) ^ 0x80000000);
    dVar13 = (double)((float)(local_48 - DOUBLE_803e4948) * FLOAT_803e4974);
    if ((double)FLOAT_803e49a8 < dVar13) {
      dVar13 = (double)FLOAT_803e49a8;
    }
  }
  FUN_801b3de4((double)(float)((double)FLOAT_803e49ac * dVar13),(double)*(float *)(iVar3 + 0xc),
               (double)*(float *)(iVar3 + 0x10),(double)*(float *)(iVar3 + 0x14),iVar3,0);
  *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x2000;
  *(byte *)(iVar9 + 0xa5d) = (byte)*(undefined2 *)(iVar2 + 0x1c) & 3;
  FUN_8002b884(iVar3,*(undefined *)(iVar9 + 0xa5d));
  if ((*(ushort *)(iVar2 + 0x1c) & 4) == 0) {
    *(float *)(iVar9 + 0xa3c) = FLOAT_803e4960;
  }
  else {
    *(float *)(iVar9 + 0xa3c) = FLOAT_803e49a4;
  }
  *(undefined *)(iVar9 + 0xa5c) = 0;
  iVar4 = FUN_800658a4((double)*(float *)(iVar3 + 0xc),
                       (double)(FLOAT_803e49b0 + *(float *)(iVar3 + 0x10)),
                       (double)*(float *)(iVar3 + 0x14),iVar3,iVar9 + 0x960,0);
  if (iVar4 == 0) {
    if (*(float *)(iVar9 + 0x960) < FLOAT_803e49b4) {
      *(undefined *)(iVar9 + 0xa5c) = 1;
    }
    *(float *)(iVar9 + 0x960) = *(float *)(iVar3 + 0x10) - *(float *)(iVar9 + 0x960);
  }
  else {
    *(undefined4 *)(iVar9 + 0x960) = *(undefined4 *)(iVar3 + 0x10);
  }
  if ((*(ushort *)(iVar2 + 0x1c) & 0x10) == 0) {
    *(undefined *)(iVar9 + 0xa5a) = 0;
  }
  else {
    iVar4 = (int)((float)((double)FLOAT_803e49b8 * dVar13) / FLOAT_803e49a8);
    local_48 = (double)(longlong)iVar4;
    iVar10 = iVar9;
    for (iVar8 = 0; iVar8 < iVar4; iVar8 = iVar8 + 1) {
      if (*(char *)(iVar9 + 0xa5c) == '\0') {
        uVar5 = FUN_800221a0(0x14,0x28);
        local_38 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_b0 = FLOAT_803e49bc * FLOAT_803e49c0 * (float)(local_38 - DOUBLE_803e4948) +
                   FLOAT_803e49bc;
        iVar1 = iVar8 >> 0x1f;
        uVar5 = (iVar1 * 4 | (uint)(iVar8 * 0x40000000 + iVar1) >> 0x1e) - iVar1 & 0xff;
        local_b8 = local_b0 * (float)(&DAT_80325528)[uVar5 * 3];
        local_b4 = local_b0 * (float)(&DAT_8032552c)[uVar5 * 3];
        local_b0 = local_b0 * (float)(&DAT_80325530)[uVar5 * 3];
        uStack60 = FUN_800221a0(0,0x8000);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_802470c8((double)(float)(DOUBLE_803e4968 *
                                    (double)(((float)((double)CONCAT44(0x43300000,uStack60) -
                                                     DOUBLE_803e4948) - FLOAT_803e49c8) /
                                            FLOAT_803e49c4)),auStack124,0x7a);
        uVar5 = FUN_800221a0(0,0x8000);
        local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        FUN_802470c8((double)(float)(DOUBLE_803e4968 *
                                    (double)(((float)(local_48 - DOUBLE_803e4948) - FLOAT_803e49c8)
                                            / FLOAT_803e49c4)),auStack172,0x78);
        FUN_80246eb4(auStack172,auStack124,auStack124);
        FUN_80247574(auStack124,&local_b8,&local_b8);
      }
      else {
        uVar5 = FUN_800221a0(0x14,0x28);
        local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_b8 = FLOAT_803e49bc * FLOAT_803e49c0 * (float)(local_48 - DOUBLE_803e4948) +
                   FLOAT_803e49bc;
        local_b4 = FLOAT_803e4960;
        local_b0 = FLOAT_803e4960;
        uStack60 = FUN_800221a0(0x2000,0x6000);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_802470c8((double)(float)(DOUBLE_803e4968 *
                                    (double)((float)((double)CONCAT44(0x43300000,uStack60) -
                                                    DOUBLE_803e4948) / FLOAT_803e49c4)),auStack124,
                     0x7a);
        uVar5 = FUN_800221a0(0,0xffff);
        local_38 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        FUN_802470c8((double)(float)(DOUBLE_803e4968 *
                                    (double)((float)(local_38 - DOUBLE_803e4948) / FLOAT_803e4970)),
                     auStack172,0x79);
        FUN_80246eb4(auStack172,auStack124,auStack124);
        FUN_80247574(auStack124,&local_b8,&local_b8);
      }
      *(undefined4 *)(iVar10 + 0x964) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(iVar10 + 0x968) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(iVar10 + 0x96c) = *(undefined4 *)(iVar3 + 0x14);
      *(float *)(iVar10 + 0x970) = local_b8;
      *(float *)(iVar10 + 0x974) = local_b4;
      *(float *)(iVar10 + 0x978) = local_b0;
      *(undefined4 *)(iVar10 + 0x97c) = 0;
      uVar6 = FUN_800221a0(0x28,0x32);
      *(undefined4 *)(iVar10 + 0x980) = uVar6;
      *(undefined *)(iVar10 + 0x984) = 1;
      iVar10 = iVar10 + 0x24;
    }
    *(char *)(iVar9 + 0xa5a) = (char)iVar8;
  }
  *(undefined4 *)(iVar9 + 0xa40) = 0;
  if ((*(ushort *)(iVar2 + 0x1c) & 0x20) != 0) {
    uVar6 = FUN_8001f4c8(0,1);
    *(undefined4 *)(iVar9 + 0xa40) = uVar6;
    if (*(int *)(iVar9 + 0xa40) != 0) {
      FUN_8001db2c(*(int *)(iVar9 + 0xa40),2);
      FUN_8001dd88((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                   (double)*(float *)(iVar3 + 0x20),*(undefined4 *)(iVar9 + 0xa40));
      FUN_8001dd40(*(undefined4 *)(iVar9 + 0xa40),1);
      FUN_8001db6c((double)FLOAT_803e4960,*(undefined4 *)(iVar9 + 0xa40),1);
      FUN_8001dc38((double)(float)((double)FLOAT_803e49cc * dVar13),
                   (double)(float)((double)FLOAT_803e4958 * dVar13),*(undefined4 *)(iVar9 + 0xa40));
      FUN_8001daf0(*(undefined4 *)(iVar9 + 0xa40),0xff,0xeb,0xa0,0xff);
    }
  }
  *(undefined *)(iVar3 + 0x36) = 0xff;
  if ((*(ushort *)(iVar2 + 0x1c) & 8) == 0) {
    *(undefined *)(iVar9 + 0xa59) = 0;
  }
  else if (*(char *)(iVar9 + 0xa5c) == '\0') {
    *(undefined *)(iVar9 + 0xa59) = 2;
    uVar7 = FUN_800221a0(0,0x4000);
    *(undefined2 *)(iVar9 + 0xa44) = uVar7;
    uVar7 = FUN_800221a0(0,0x8000);
    *(undefined2 *)(iVar9 + 0xa46) = uVar7;
    *(short *)(iVar9 + 0xa48) = *(short *)(iVar9 + 0xa44) + 0x4000;
    *(undefined2 *)(iVar9 + 0xa4a) = *(undefined2 *)(iVar9 + 0xa46);
  }
  else {
    *(undefined *)(iVar9 + 0xa59) = 1;
    *(undefined2 *)(iVar9 + 0xa44) = 0;
    *(undefined2 *)(iVar9 + 0xa46) = 0;
  }
  *(undefined *)(iVar9 + 0xa5b) = 0;
  *(undefined4 *)(iVar9 + 0xa4c) = 0;
  dVar12 = (double)FUN_802931a0(dVar13);
  local_38 = (double)(longlong)(int)((double)FLOAT_803e4930 * dVar12);
  *(int *)(iVar9 + 0xa50) = (int)((double)FLOAT_803e4930 * dVar12);
  iVar2 = *(int *)(iVar9 + 0xa50);
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (0x3c < iVar2) {
    iVar2 = 0x3c;
  }
  *(int *)(iVar9 + 0xa50) = iVar2;
  *(float *)(iVar9 + 0xa54) = (float)dVar13;
  *(float *)(iVar3 + 8) = FLOAT_803e4960;
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286124();
  return;
}

