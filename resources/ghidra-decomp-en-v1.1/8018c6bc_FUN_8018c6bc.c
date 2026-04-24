// Function: FUN_8018c6bc
// Entry: 8018c6bc
// Size: 1040 bytes

/* WARNING: Removing unreachable block (ram,0x8018caac) */
/* WARNING: Removing unreachable block (ram,0x8018caa4) */
/* WARNING: Removing unreachable block (ram,0x8018c6d4) */
/* WARNING: Removing unreachable block (ram,0x8018c6cc) */

void FUN_8018c6bc(void)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  byte bVar12;
  undefined uVar13;
  int iVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps30_1;
  double in_ps31_1;
  int local_98;
  float local_94;
  float local_90;
  float local_8c;
  int local_88 [10];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  iVar3 = FUN_80286830();
  iVar14 = *(int *)(iVar3 + 0xb8);
  dVar16 = (double)FLOAT_803e4960;
  local_98 = 0;
  uVar13 = 0x40;
  uVar10 = 0;
  bVar2 = false;
  if ((char)*(byte *)(iVar14 + 0x5c) < '\0') {
    if ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) == 0) {
      FUN_80097568((double)FLOAT_803e4964,(double)FLOAT_803e496c,iVar3,5,1,1,0x14,0,0);
    }
    else {
      FUN_80097568((double)FLOAT_803e4964,(double)FLOAT_803e4968,iVar3,5,1,1,0x14,0,0);
    }
    piVar4 = (int *)FUN_8002b660(iVar3);
    iVar5 = FUN_800284e8(*piVar4,0);
    *(undefined *)(iVar5 + 0x43) = 0x7f;
    FUN_8003b9ec(iVar3);
    for (bVar12 = 0; bVar12 < 10; bVar12 = bVar12 + 1) {
      iVar5 = iVar14 + (uint)bVar12 * 4;
      if (*(float **)(iVar5 + 8) == (float *)0x0) {
        if ((!bVar2) && (iVar6 = FUN_80020800(), iVar6 == 0)) {
          uVar7 = FUN_80022264(0,9);
          if ((uVar7 == 0) && ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) == 0)) {
            puVar8 = FUN_80037048(0x4f,&local_98);
            for (uVar7 = 0; (int)(uVar7 & 0xff) < local_98; uVar7 = uVar7 + 1) {
              iVar6 = puVar8[uVar7 & 0xff];
              uVar11 = uVar10;
              if (iVar6 != iVar3) {
                if ((*(int *)(iVar6 + 0xb8) == 0) ||
                   ((*(byte *)(*(int *)(iVar6 + 0xb8) + 0x5c) >> 5 & 1) == 0)) {
                  bVar2 = true;
                }
                else {
                  bVar2 = false;
                }
                if ((bVar2) &&
                   (dVar15 = FUN_80021794((float *)(iVar6 + 0x18),(float *)(iVar3 + 0x18)),
                   dVar15 < (double)FLOAT_803e4974)) {
                  uVar11 = uVar10 + 1;
                  local_88[uVar10 & 0xff] = puVar8[uVar7 & 0xff];
                }
              }
              uVar10 = uVar11;
            }
          }
          if ((uVar10 & 0xff) == 0) {
            local_88[0] = iVar3;
          }
          else {
            uVar10 = FUN_80022264(0,uVar10 - 1 & 0xff);
            uVar10 = uVar10 & 0xff;
            dVar16 = (double)FUN_800217c8((float *)(local_88[uVar10] + 0x18),(float *)(iVar3 + 0x18)
                                         );
            dVar16 = -(double)(FLOAT_803e4980 * (float)(dVar16 / (double)FLOAT_803e4978) -
                              FLOAT_803e497c);
            uVar13 = 0xff;
          }
          iVar6 = local_88[uVar10 & 0xff];
          local_94 = *(float *)(iVar6 + 0xc);
          local_90 = *(float *)(iVar6 + 0x10);
          local_8c = *(float *)(iVar6 + 0x14);
          if (iVar6 == iVar3) {
            fVar1 = FLOAT_803e4988;
            if ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) != 0) {
              fVar1 = FLOAT_803e4984;
            }
            dVar15 = (double)fVar1;
            uVar7 = FUN_80022264(0,2000);
            local_60 = (double)CONCAT44(0x43300000,uVar7 - 1000 ^ 0x80000000);
            local_94 = (float)(dVar15 * (double)(float)(local_60 - DOUBLE_803e4998) +
                              (double)local_94);
            uVar7 = FUN_80022264(0,2000);
            uStack_54 = uVar7 - 1000 ^ 0x80000000;
            local_58 = 0x43300000;
            local_90 = (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) -
                                                       DOUBLE_803e4998) + (double)local_90);
            uVar7 = FUN_80022264(0,2000);
            uStack_4c = uVar7 - 1000 ^ 0x80000000;
            local_50 = 0x43300000;
            local_8c = (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) -
                                                       DOUBLE_803e4998) + (double)local_8c);
          }
          uVar9 = FUN_8008fdac(dVar16,(double)FLOAT_803e498c,iVar3 + 0xc,&local_94,0x14,uVar13,0);
          *(undefined4 *)(iVar5 + 8) = uVar9;
          *(float *)(iVar5 + 0x34) = FLOAT_803e4990;
          bVar2 = true;
        }
      }
      else {
        FUN_8008fb90(*(float **)(iVar5 + 8));
        iVar6 = FUN_80020800();
        if (iVar6 == 0) {
          *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x34) + FLOAT_803dc074;
          iVar6 = (int)(FLOAT_803e4970 + *(float *)(iVar5 + 0x34));
          local_60 = (double)(longlong)iVar6;
          *(short *)(*(int *)(iVar5 + 8) + 0x20) = (short)iVar6;
          if (0x14 < *(ushort *)(*(uint *)(iVar5 + 8) + 0x20)) {
            FUN_8008ff08(*(uint *)(iVar5 + 8));
            *(undefined4 *)(iVar5 + 8) = 0;
          }
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

