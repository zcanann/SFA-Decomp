// Function: FUN_8018c140
// Entry: 8018c140
// Size: 1040 bytes

/* WARNING: Removing unreachable block (ram,0x8018c528) */
/* WARNING: Removing unreachable block (ram,0x8018c530) */

void FUN_8018c140(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  float fVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  byte bVar13;
  undefined4 uVar14;
  int iVar15;
  undefined4 uVar16;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  int local_98;
  float local_94;
  float local_90;
  float local_8c;
  int local_88 [10];
  double local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar19 = FUN_802860cc();
  iVar4 = (int)((ulonglong)uVar19 >> 0x20);
  iVar15 = *(int *)(iVar4 + 0xb8);
  dVar18 = (double)FLOAT_803e3cc8;
  local_98 = 0;
  uVar14 = 0x40;
  uVar10 = 0;
  bVar3 = false;
  if ((char)*(byte *)(iVar15 + 0x5c) < '\0') {
    if ((*(byte *)(iVar15 + 0x5c) >> 5 & 1) == 0) {
      FUN_800972dc((double)FLOAT_803e3ccc,(double)FLOAT_803e3cd4,iVar4,5,1,1,0x14,0,0);
    }
    else {
      FUN_800972dc((double)FLOAT_803e3ccc,(double)FLOAT_803e3cd0,iVar4,5,1,1,0x14,0,0);
    }
    puVar5 = (undefined4 *)FUN_8002b588(iVar4);
    iVar6 = FUN_80028424(*puVar5,0);
    *(undefined *)(iVar6 + 0x43) = 0x7f;
    FUN_8003b8f4((double)FLOAT_803e3ccc,iVar4,(int)uVar19,param_3,param_4,param_5);
    for (bVar13 = 0; bVar13 < 10; bVar13 = bVar13 + 1) {
      iVar6 = iVar15 + (uint)bVar13 * 4;
      if (*(int *)(iVar6 + 8) == 0) {
        if ((!bVar3) && (iVar7 = FUN_8002073c(), iVar7 == 0)) {
          iVar7 = FUN_800221a0(0,9);
          if ((iVar7 == 0) && ((*(byte *)(iVar15 + 0x5c) >> 5 & 1) == 0)) {
            iVar7 = FUN_80036f50(0x4f,&local_98);
            for (uVar12 = 0; (int)(uVar12 & 0xff) < local_98; uVar12 = uVar12 + 1) {
              iVar2 = (uVar12 & 0xff) * 4;
              iVar9 = *(int *)(iVar7 + iVar2);
              uVar11 = uVar10;
              if (iVar9 != iVar4) {
                if ((*(int *)(iVar9 + 0xb8) == 0) ||
                   ((*(byte *)(*(int *)(iVar9 + 0xb8) + 0x5c) >> 5 & 1) == 0)) {
                  bVar3 = true;
                }
                else {
                  bVar3 = false;
                }
                if ((bVar3) &&
                   (dVar17 = (double)FUN_800216d0(iVar9 + 0x18,iVar4 + 0x18),
                   dVar17 < (double)FLOAT_803e3cdc)) {
                  uVar11 = uVar10 + 1;
                  local_88[uVar10 & 0xff] = *(int *)(iVar7 + iVar2);
                }
              }
              uVar10 = uVar11;
            }
          }
          if ((uVar10 & 0xff) == 0) {
            local_88[0] = iVar4;
          }
          else {
            uVar10 = FUN_800221a0(0,uVar10 - 1 & 0xff);
            uVar10 = uVar10 & 0xff;
            dVar18 = (double)FUN_80021704(local_88[uVar10] + 0x18,iVar4 + 0x18);
            dVar18 = -(double)(FLOAT_803e3ce8 * (float)(dVar18 / (double)FLOAT_803e3ce0) -
                              FLOAT_803e3ce4);
            uVar14 = 0xff;
          }
          iVar7 = local_88[uVar10 & 0xff];
          local_94 = *(float *)(iVar7 + 0xc);
          local_90 = *(float *)(iVar7 + 0x10);
          local_8c = *(float *)(iVar7 + 0x14);
          if (iVar7 == iVar4) {
            fVar1 = FLOAT_803e3cf0;
            if ((*(byte *)(iVar15 + 0x5c) >> 5 & 1) != 0) {
              fVar1 = FLOAT_803e3cec;
            }
            dVar17 = (double)fVar1;
            iVar7 = FUN_800221a0(0,2000);
            local_60 = (double)CONCAT44(0x43300000,iVar7 - 1000U ^ 0x80000000);
            local_94 = (float)(dVar17 * (double)(float)(local_60 - DOUBLE_803e3d00) +
                              (double)local_94);
            iVar7 = FUN_800221a0(0,2000);
            uStack84 = iVar7 - 1000U ^ 0x80000000;
            local_58 = 0x43300000;
            local_90 = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack84) -
                                                       DOUBLE_803e3d00) + (double)local_90);
            iVar7 = FUN_800221a0(0,2000);
            uStack76 = iVar7 - 1000U ^ 0x80000000;
            local_50 = 0x43300000;
            local_8c = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack76) -
                                                       DOUBLE_803e3d00) + (double)local_8c);
          }
          uVar8 = FUN_8008fb20(dVar18,(double)FLOAT_803e3cf4,iVar4 + 0xc,&local_94,0x14,uVar14,0);
          *(undefined4 *)(iVar6 + 8) = uVar8;
          *(float *)(iVar6 + 0x34) = FLOAT_803e3cf8;
          bVar3 = true;
        }
      }
      else {
        FUN_8008f904();
        iVar7 = FUN_8002073c();
        if (iVar7 == 0) {
          *(float *)(iVar6 + 0x34) = *(float *)(iVar6 + 0x34) + FLOAT_803db414;
          iVar7 = (int)(FLOAT_803e3cd8 + *(float *)(iVar6 + 0x34));
          local_60 = (double)(longlong)iVar7;
          *(short *)(*(int *)(iVar6 + 8) + 0x20) = (short)iVar7;
          if (0x14 < *(ushort *)(*(int *)(iVar6 + 8) + 0x20)) {
            FUN_8008fc7c();
            *(undefined4 *)(iVar6 + 8) = 0;
          }
        }
      }
    }
  }
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  FUN_80286118();
  return;
}

