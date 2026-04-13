// Function: FUN_8012cd38
// Entry: 8012cd38
// Size: 3456 bytes

/* WARNING: Removing unreachable block (ram,0x8012da98) */
/* WARNING: Removing unreachable block (ram,0x8012da90) */
/* WARNING: Removing unreachable block (ram,0x8012da88) */
/* WARNING: Removing unreachable block (ram,0x8012da80) */
/* WARNING: Removing unreachable block (ram,0x8012da78) */
/* WARNING: Removing unreachable block (ram,0x8012cd68) */
/* WARNING: Removing unreachable block (ram,0x8012cd60) */
/* WARNING: Removing unreachable block (ram,0x8012cd58) */
/* WARNING: Removing unreachable block (ram,0x8012cd50) */
/* WARNING: Removing unreachable block (ram,0x8012cd48) */

void FUN_8012cd38(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  byte bVar2;
  ushort uVar4;
  char cVar5;
  char cVar6;
  ushort *puVar3;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  byte *pbVar12;
  uint uVar13;
  uint uVar14;
  int iVar15;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  double dVar16;
  undefined8 uVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  undefined8 local_b0;
  undefined8 local_98;
  
  FUN_80286824();
  if (DAT_803de400 == '\0') {
    if (DAT_803de3f6 == 0) {
      FUN_80019940(0xff,0xff,0xff,0xff);
      FUN_80077318((double)FLOAT_803e2e30,(double)FLOAT_803e2e34,DAT_803a9638,0xff,0x100);
      FUN_80076998((double)FLOAT_803e2c1c,(double)FLOAT_803e2e34,DAT_803a9644,0xff,0x100,0xa8,5,0);
      FUN_80076998((double)FLOAT_803e2e30,(double)FLOAT_803e2b5c,DAT_803a963c,0xff,0x100,5,0x30,0);
      FUN_80076998((double)FLOAT_803e2c1c,(double)FLOAT_803e2b5c,DAT_803a9640,0xff,0x100,0xa8,0x30,0
                  );
      FUN_80076998((double)FLOAT_803e2c1c,(double)FLOAT_803e2e38,DAT_803a9644,0xff,0x100,0xa8,5,2);
      FUN_80076998((double)FLOAT_803e2e3c,(double)FLOAT_803e2b5c,DAT_803a963c,0xff,0x100,5,0x30,1);
      FUN_80076998((double)FLOAT_803e2e3c,(double)FLOAT_803e2e38,DAT_803a9638,0xff,0x100,5,5,3);
      FUN_80076998((double)FLOAT_803e2e3c,(double)FLOAT_803e2e34,DAT_803a9638,0xff,0x100,5,5,1);
      FUN_80076998((double)FLOAT_803e2e30,(double)FLOAT_803e2e38,DAT_803a9638,0xff,0x100,5,5,2);
      dVar18 = (double)FLOAT_803e2e40;
      uVar17 = FUN_80077318((double)FLOAT_803e2c70,dVar18,DAT_803a970c,0xff,0x100);
      puVar3 = FUN_800195a8(uVar17,dVar18,param_3,param_4,param_5,param_6,param_7,param_8,0x2ac);
      if (1 < puVar3[1]) {
        FUN_80015e00(*(undefined4 *)(*(int *)(puVar3 + 4) + 4),0x93,0x69,0x17f);
      }
      FUN_80077318((double)FLOAT_803e2b1c,(double)FLOAT_803e2e44,DAT_803a971c,0xff,0x100);
      if (2 < puVar3[1]) {
        FUN_80015e00(*(undefined4 *)(*(int *)(puVar3 + 4) + 8),0x93,0x51,0x194);
      }
      FUN_80077318((double)FLOAT_803e2e48,(double)FLOAT_803e2e34,DAT_803a9638,0xff,0x100);
      FUN_80076998((double)FLOAT_803e2e4c,(double)FLOAT_803e2e34,DAT_803a9644,0xff,0x100,0xa8,5,0);
      FUN_80076998((double)FLOAT_803e2e48,(double)FLOAT_803e2b5c,DAT_803a963c,0xff,0x100,5,0x30,0);
      FUN_80076998((double)FLOAT_803e2e4c,(double)FLOAT_803e2b5c,DAT_803a9640,0xff,0x100,0xa8,0x30,0
                  );
      FUN_80076998((double)FLOAT_803e2e4c,(double)FLOAT_803e2e38,DAT_803a9644,0xff,0x100,0xa8,5,2);
      FUN_80076998((double)FLOAT_803e2e50,(double)FLOAT_803e2b5c,DAT_803a963c,0xff,0x100,5,0x30,1);
      FUN_80076998((double)FLOAT_803e2e50,(double)FLOAT_803e2e38,DAT_803a9638,0xff,0x100,5,5,3);
      FUN_80076998((double)FLOAT_803e2e50,(double)FLOAT_803e2e34,DAT_803a9638,0xff,0x100,5,5,1);
      FUN_80076998((double)FLOAT_803e2e48,(double)FLOAT_803e2e38,DAT_803a9638,0xff,0x100,5,5,2);
      FUN_80077318((double)FLOAT_803e2e54,(double)FLOAT_803e2e58,DAT_803a9710,0xff,0x100);
      if (4 < puVar3[1]) {
        FUN_80015e00(*(undefined4 *)(*(int *)(puVar3 + 4) + 0x10),0x93,0x20c,0x17f);
      }
      FUN_80077318((double)FLOAT_803e2e5c,(double)FLOAT_803e2c38,DAT_803a9714,0xff,0x100);
      if (5 < puVar3[1]) {
        FUN_80015e00(*(undefined4 *)(*(int *)(puVar3 + 4) + 0x14),0x93,0x1f6,0x195);
      }
    }
    else {
      uVar9 = (uint)(short)(DAT_803de3f6 * 0xf);
      if (0xff < (int)uVar9) {
        uVar9 = 0xff;
      }
      iVar10 = DAT_803de3f6 + -0x14;
      if ((short)iVar10 < 0) {
        iVar10 = 0;
      }
      uVar4 = (ushort)(iVar10 << 4);
      if ((int)(uint)DAT_802c7d06 < (int)(short)uVar4) {
        uVar4 = DAT_802c7d06;
      }
      uVar8 = (uint)DAT_802c7d14;
      uVar7 = (uint)DAT_802c7d16;
      iVar10 = (int)(short)uVar4;
      iVar15 = (int)DAT_802c7d02;
      uVar13 = uVar8 - 5;
      uVar14 = uVar7 - 5;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uVar13 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,uVar14 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a9638,uVar9 & 0xff,0x100);
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),
                   (double)(float)((double)CONCAT44(0x43300000,uVar14 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a9644,uVar9 & 0xff,0x100,iVar15,5,0);
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar13 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),DAT_803a963c,uVar9 & 0xff,0x100,5,iVar10,0);
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),
                   (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),DAT_803a9640,uVar9 & 0xff,0x100,iVar15,iVar10,0);
      uVar11 = uVar7 + iVar10;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),
                   (double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a9644,uVar9 & 0xff,0x100,iVar15,5,2);
      uVar8 = uVar8 + iVar15;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),
                   (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),DAT_803a963c,uVar9 & 0xff,0x100,5,iVar10,1);
      local_b0 = (double)CONCAT44(0x43300000,uVar11 ^ 0x80000000);
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),(double)(float)(local_b0 - DOUBLE_803e2af8),DAT_803a9638,
                   uVar9 & 0xff,0x100,5,5,3);
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e2af8
                                  ),
                   (double)(float)((double)CONCAT44(0x43300000,uVar14 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a9638,uVar9 & 0xff,0x100,5,5,1);
      local_98 = (double)CONCAT44(0x43300000,uVar13 ^ 0x80000000);
      dVar18 = (double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - DOUBLE_803e2af8);
      FUN_80076998((double)(float)(local_98 - DOUBLE_803e2af8),dVar18,DAT_803a9638,uVar9 & 0xff,
                   0x100,5,5,2);
      iVar10 = 0;
      pbVar12 = &DAT_803dc6fc;
      DAT_802c7d0a = uVar4;
      do {
        uVar7 = FUN_80020078((uint)*(ushort *)(&DAT_8031bcda + (uint)*pbVar12 * 0x1c));
        if (uVar7 != 0) {
          cVar6 = (&DAT_803dc6fc)[iVar10];
          goto LAB_8012d128;
        }
        pbVar12 = pbVar12 + 1;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 5);
      cVar6 = -1;
LAB_8012d128:
      uVar7 = FUN_80020078(0x63c);
      uVar8 = FUN_80020078(0x4e9);
      uVar11 = FUN_80020078(0x5f3);
      uVar13 = FUN_80020078(0x5f4);
      iVar10 = uVar8 + uVar7 + uVar11 + uVar13;
      uVar7 = FUN_80020078(0x123);
      if (uVar7 != 0) {
        iVar10 = iVar10 + 1;
      }
      uVar7 = FUN_80020078(0x2e8);
      if (uVar7 != 0) {
        iVar10 = iVar10 + 1;
      }
      uVar7 = FUN_80020078(0x83b);
      if (uVar7 != 0) {
        iVar10 = iVar10 + 1;
      }
      uVar7 = FUN_80020078(0x83c);
      if (uVar7 != 0) {
        iVar10 = iVar10 + 1;
      }
      bVar2 = DAT_803dc6fc;
      if ((((iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)DAT_803dc6fc * 0x1c]) &&
           (bVar2 = bRam803dc6fd,
           iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc6fd * 0x1c])) &&
          (bVar2 = bRam803dc6fe,
          iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc6fe * 0x1c])) &&
         ((bVar2 = bRam803dc6ff,
          iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc6ff * 0x1c] &&
          (bVar2 = bRam803dc700,
          iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc700 * 0x1c])))) {
        bVar2 = 0xff;
      }
      uVar8 = (uint)(char)bVar2;
      uVar4 = FUN_800ea540();
      bVar1 = 0xad < uVar4;
      uVar7 = (uint)DAT_803de3fa;
      uVar17 = extraout_f1;
      if ((uVar7 == 2) && (bVar1)) {
        uVar7 = 0x574;
      }
      else if (((int)cVar6 == uVar7) && (uVar8 != uVar7)) {
        uVar7 = (uint)*(ushort *)(&DAT_8031bcc4 + uVar7 * 0x1c);
      }
      else if (uVar7 == 2) {
        cVar5 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
        uVar17 = extraout_f1_00;
        if ((cVar5 != '\x02') || (bVar1)) {
          if ((int)cVar6 == uVar8) {
            uVar7 = FUN_80020078((uint)*(ushort *)(&DAT_8031bcde + uVar8 * 0x1c));
            if (uVar7 == 0) {
              uVar7 = (uint)*(ushort *)(&DAT_8031bcc8 + uVar8 * 0x1c);
            }
            else {
              uVar7 = 0x578;
            }
          }
          else {
            uVar7 = (uint)*(ushort *)(&DAT_8031bcc6 + (uint)DAT_803de3fa * 0x1c);
          }
        }
        else {
          uVar7 = 0x577;
        }
      }
      else if (((uVar7 != 0) ||
               (cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(0xd), uVar17 = extraout_f1_01,
               cVar6 != '\x02')) || (bVar1)) {
        uVar7 = (uint)*(ushort *)(&DAT_8031bcc6 + (uint)DAT_803de3fa * 0x1c);
      }
      else {
        uVar7 = 0x568;
      }
      FUN_800168a8(uVar17,dVar18,param_3,param_4,param_5,param_6,param_7,param_8,uVar7);
      DAT_803de3fc = DAT_803de3fc + 1;
      FUN_80077318((double)FLOAT_803e2e28,(double)FLOAT_803e2e2c,DAT_803a9638,uVar9 & 0xff,0x100);
      FUN_80076998((double)FLOAT_803e2bc8,(double)FLOAT_803e2e2c,DAT_803a9644,uVar9 & 0xff,0x100,
                   0x82,5,0);
      FUN_80076998((double)FLOAT_803e2e28,(double)FLOAT_803e2b1c,DAT_803a963c,uVar9 & 0xff,0x100,5,
                   0x96,0);
      FUN_80076998((double)FLOAT_803e2bc8,(double)FLOAT_803e2b4c,DAT_803a9644,uVar9 & 0xff,0x100,
                   0x82,5,2);
      FUN_80076998((double)FLOAT_803e2cd8,(double)FLOAT_803e2b1c,DAT_803a963c,uVar9 & 0xff,0x100,5,
                   0x96,1);
      FUN_80076998((double)FLOAT_803e2cd8,(double)FLOAT_803e2b4c,DAT_803a9638,uVar9 & 0xff,0x100,5,5
                   ,3);
      FUN_80076998((double)FLOAT_803e2cd8,(double)FLOAT_803e2e2c,DAT_803a9638,uVar9 & 0xff,0x100,5,5
                   ,1);
      FUN_80076998((double)FLOAT_803e2e28,(double)FLOAT_803e2b4c,DAT_803a9638,uVar9 & 0xff,0x100,5,5
                   ,2);
      iVar10 = 0;
      dVar19 = (double)FLOAT_803e2ccc;
      uVar9 = (int)(short)uVar9 ^ 0x80000000;
      dVar21 = (double)FLOAT_803e2cd0;
      dVar22 = (double)FLOAT_803e2c90;
      dVar18 = DOUBLE_803e2af8;
      do {
        dVar16 = (double)FUN_80293994();
        dVar20 = (double)(float)(dVar19 * dVar16);
        dVar16 = (double)FUN_80293994();
        dVar16 = (double)(float)(dVar19 * dVar16 + dVar20);
        uVar7 = (uint)((float)((double)CONCAT44(0x43300000,uVar9) - dVar18) *
                      (float)(dVar21 + dVar16));
        if ((int)uVar7 < 0) {
          uVar7 = 0;
        }
        uVar8 = FUN_80022264(0,0x1e);
        uVar11 = FUN_80022264(0,0x1e);
        if (0xff < (int)uVar7) {
          uVar7 = 0xff;
        }
        FUN_80076144((double)FLOAT_803e2bc8,
                     (double)(float)((double)CONCAT44(0x43300000,iVar10 + 0x32U ^ 0x80000000) -
                                    dVar18),DAT_803a9760,uVar7 & 0xff,0x100,0x82,2,uVar11 << 1,
                     uVar8 << 1);
        uVar7 = (uint)((float)((double)CONCAT44(0x43300000,uVar9) - dVar18) *
                      (float)(dVar22 + dVar16));
        if ((int)uVar7 < 0) {
          uVar7 = 0;
        }
        uVar8 = FUN_80022264(0,0x1e);
        uVar11 = FUN_80022264(0,0x1e);
        dVar16 = (double)(float)((double)CONCAT44(0x43300000,iVar10 + 0x34U ^ 0x80000000) - dVar18);
        if (0xff < (int)uVar7) {
          uVar7 = 0xff;
        }
        uVar17 = FUN_80076144((double)FLOAT_803e2bc8,dVar16,DAT_803a9760,uVar7 & 0xff,0x100,0x82,2,
                              uVar11 << 1,uVar8 << 1);
        iVar10 = iVar10 + 4;
      } while (iVar10 < 0x96);
      FUN_80016848(uVar17,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,0x3dd,100,0x15e);
    }
  }
  FUN_80286870();
  return;
}

