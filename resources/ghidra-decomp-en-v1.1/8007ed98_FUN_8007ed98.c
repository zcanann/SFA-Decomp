// Function: FUN_8007ed98
// Entry: 8007ed98
// Size: 1956 bytes

void FUN_8007ed98(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined *param_14,uint param_15,uint param_16)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  ushort uVar8;
  undefined4 uVar7;
  uint *puVar9;
  uint uVar10;
  int iVar11;
  code *pcVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint unaff_r23;
  uint unaff_r24;
  bool bVar28;
  undefined8 extraout_f1;
  undefined8 uVar29;
  undefined8 extraout_f1_00;
  ulonglong uVar30;
  
  uVar30 = FUN_80286830();
  uVar3 = 0xffffffff;
  uVar6 = 0;
  uVar5 = param_12;
  uVar7 = param_13;
  pcVar12 = (code *)param_14;
  uVar29 = extraout_f1;
  DAT_803ddcc4 = FUN_80023d8c(0x2000,-1);
  if (DAT_803ddcc4 == 0) {
    DAT_803dc360 = 8;
  }
  else {
    iVar2 = FUN_8007fac8(uVar29,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (char)(uVar30 >> 0x20),uVar3,uVar6,uVar5,uVar7,pcVar12,param_15,param_16);
    if (iVar2 == 0) {
      FUN_800238c4(DAT_803ddcc4);
    }
    else {
      FUN_802420b0(DAT_803ddcc4,0x2000);
      iVar2 = FUN_802640ac((int *)&DAT_80397560,DAT_803ddcc4,0x2000,0x2000);
      if (iVar2 == 0) {
        uVar4 = 0;
        uVar1 = 0;
        uVar13 = 1;
        iVar11 = 0;
        for (uVar8 = 0; uVar8 < 0x3f7; uVar8 = uVar8 + 8) {
          puVar9 = (uint *)(DAT_803ddcc4 + (uint)uVar8 * 8);
          uVar21 = puVar9[1];
          bVar28 = CARRY4(uVar13,uVar21);
          uVar10 = uVar13 + uVar21;
          uVar22 = puVar9[3];
          uVar15 = uVar10 + uVar22;
          uVar23 = puVar9[5];
          uVar16 = uVar15 + uVar23;
          uVar24 = puVar9[7];
          uVar17 = uVar16 + uVar24;
          uVar25 = puVar9[9];
          uVar18 = uVar17 + uVar25;
          uVar26 = puVar9[0xb];
          uVar19 = uVar18 + uVar26;
          param_16 = puVar9[0xd];
          uVar20 = uVar19 + param_16;
          param_15 = puVar9[0xe];
          uVar14 = puVar9[0xf];
          uVar4 = uVar4 ^ uVar21 ^ uVar22 ^ uVar23 ^ uVar24 ^ uVar25 ^ uVar26 ^ param_16 ^ uVar14;
          uVar1 = uVar1 ^ *puVar9 ^ puVar9[2] ^ puVar9[4] ^ puVar9[6] ^ puVar9[8] ^ puVar9[10] ^
                  puVar9[0xc] ^ param_15;
          uVar13 = uVar20 + uVar14;
          iVar11 = iVar11 + *puVar9 + (uint)bVar28 + puVar9[2] + (uint)CARRY4(uVar10,uVar22) +
                   puVar9[4] + (uint)CARRY4(uVar15,uVar23) + puVar9[6] + (uint)CARRY4(uVar16,uVar24)
                   + puVar9[8] + (uint)CARRY4(uVar17,uVar25) +
                   puVar9[10] + (uint)CARRY4(uVar18,uVar26) +
                   puVar9[0xc] + (uint)CARRY4(uVar19,param_16) + param_15 + CARRY4(uVar20,uVar14);
        }
        for (; uVar8 < 0x3ff; uVar8 = uVar8 + 1) {
          puVar9 = (uint *)(DAT_803ddcc4 + (uint)uVar8 * 8);
          uVar14 = *puVar9;
          param_15 = puVar9[1];
          uVar4 = uVar4 ^ param_15;
          uVar1 = uVar1 ^ uVar14;
          bVar28 = CARRY4(uVar13,param_15);
          uVar13 = uVar13 + param_15;
          iVar11 = iVar11 + uVar14 + bVar28;
        }
        unaff_r23 = uVar4 ^ uVar13 + 0xd;
        unaff_r24 = uVar1 ^ iVar11 + (uint)(0xfffffff2 < uVar13);
        if (unaff_r23 != *(uint *)(DAT_803ddcc4 + 0x1ffc) ||
            unaff_r24 != *(uint *)(DAT_803ddcc4 + 0x1ff8)) {
          FUN_802420b0(DAT_803ddcc4,0x2000);
          iVar2 = FUN_802640ac((int *)&DAT_80397560,DAT_803ddcc4,0x2000,0x4000);
          if (iVar2 == 0) {
            uVar4 = 0;
            uVar1 = 0;
            uVar13 = 1;
            iVar2 = 0;
            for (uVar8 = 0; uVar8 < 0x3f7; uVar8 = uVar8 + 8) {
              puVar9 = (uint *)(DAT_803ddcc4 + (uint)uVar8 * 8);
              uVar21 = puVar9[1];
              bVar28 = CARRY4(uVar13,uVar21);
              uVar10 = uVar13 + uVar21;
              uVar22 = puVar9[3];
              uVar15 = uVar10 + uVar22;
              uVar23 = puVar9[5];
              uVar16 = uVar15 + uVar23;
              uVar24 = puVar9[7];
              uVar17 = uVar16 + uVar24;
              uVar25 = puVar9[9];
              uVar18 = uVar17 + uVar25;
              uVar26 = puVar9[0xb];
              uVar19 = uVar18 + uVar26;
              param_16 = puVar9[0xd];
              uVar20 = uVar19 + param_16;
              param_15 = puVar9[0xe];
              uVar14 = puVar9[0xf];
              uVar4 = uVar4 ^ uVar21 ^ uVar22 ^ uVar23 ^ uVar24 ^ uVar25 ^ uVar26 ^ param_16 ^
                      uVar14;
              uVar1 = uVar1 ^ *puVar9 ^ puVar9[2] ^ puVar9[4] ^ puVar9[6] ^ puVar9[8] ^ puVar9[10] ^
                      puVar9[0xc] ^ param_15;
              uVar13 = uVar20 + uVar14;
              iVar2 = iVar2 + *puVar9 + (uint)bVar28 + puVar9[2] + (uint)CARRY4(uVar10,uVar22) +
                      puVar9[4] + (uint)CARRY4(uVar15,uVar23) +
                      puVar9[6] + (uint)CARRY4(uVar16,uVar24) +
                      puVar9[8] + (uint)CARRY4(uVar17,uVar25) +
                      puVar9[10] + (uint)CARRY4(uVar18,uVar26) +
                      puVar9[0xc] + (uint)CARRY4(uVar19,param_16) + param_15 + CARRY4(uVar20,uVar14)
              ;
            }
            for (; uVar8 < 0x3ff; uVar8 = uVar8 + 1) {
              puVar9 = (uint *)(DAT_803ddcc4 + (uint)uVar8 * 8);
              uVar14 = *puVar9;
              param_15 = puVar9[1];
              uVar4 = uVar4 ^ param_15;
              uVar1 = uVar1 ^ uVar14;
              bVar28 = CARRY4(uVar13,param_15);
              uVar13 = uVar13 + param_15;
              iVar2 = iVar2 + uVar14 + bVar28;
            }
            unaff_r23 = uVar4 ^ uVar13 + 0xd;
            unaff_r24 = uVar1 ^ iVar2 + (uint)(0xfffffff2 < uVar13);
            if (unaff_r23 == *(uint *)(DAT_803ddcc4 + 0x1ffc) &&
                unaff_r24 == *(uint *)(DAT_803ddcc4 + 0x1ff8)) {
              iVar2 = FUN_8007ea14(1);
            }
            else {
              iVar2 = -0x55;
              DAT_803dc360 = 10;
            }
          }
        }
      }
      uVar1 = DAT_803ddcd0;
      uVar4 = DAT_803ddcd4;
      if ((((iVar2 == 0) && (uVar1 = unaff_r24, uVar4 = unaff_r23, DAT_803ddcd9 != '\0')) &&
          (uVar1 = unaff_r24, uVar4 = unaff_r23, DAT_803ddcd4 != 0 || DAT_803ddcd0 != 0)) &&
         (uVar1 = DAT_803ddcd0, uVar4 = DAT_803ddcd4,
         unaff_r23 != DAT_803ddcd4 || unaff_r24 != DAT_803ddcd0)) {
        iVar2 = -0x55;
        DAT_803dc360 = 0xb;
      }
      DAT_803ddcd4 = uVar4;
      DAT_803ddcd0 = uVar1;
      if (iVar2 == 0) {
        DAT_803ddcdc = FUN_80023d8c(0x4000,-1);
        if (DAT_803ddcdc == 0) {
          if (DAT_803ddcda != '\0') {
            DAT_803ddcda = '\0';
            FUN_80263888((int *)&DAT_80397560);
          }
          FUN_80262bf4(0);
          FUN_800238c4(DAT_803ddcc0);
          DAT_803ddcc0 = 0;
          FUN_800238c4(DAT_803ddcc4);
          DAT_803dc360 = 8;
          goto LAB_8007f524;
        }
        iVar2 = FUN_802640ac((int *)&DAT_80397560,DAT_803ddcdc,0x2000,0);
        if (iVar2 == 0) {
          uVar4 = 0;
          uVar1 = 0;
          uVar14 = 1;
          iVar11 = 0;
          for (uVar13 = 0; (uVar13 & 0xffff) < 0x400; uVar13 = uVar13 + 8) {
            puVar9 = (uint *)(DAT_803ddcdc + (uVar13 & 0xffff) * 8);
            uVar22 = puVar9[1];
            bVar28 = CARRY4(uVar14,uVar22);
            uVar15 = uVar14 + uVar22;
            uVar23 = puVar9[3];
            uVar16 = uVar15 + uVar23;
            uVar24 = puVar9[5];
            uVar17 = uVar16 + uVar24;
            uVar25 = puVar9[7];
            uVar18 = uVar17 + uVar25;
            uVar26 = puVar9[9];
            uVar19 = uVar18 + uVar26;
            uVar27 = puVar9[0xb];
            uVar20 = uVar19 + uVar27;
            param_16 = puVar9[0xd];
            uVar21 = uVar20 + param_16;
            param_15 = puVar9[0xe];
            uVar10 = puVar9[0xf];
            uVar4 = uVar4 ^ uVar22 ^ uVar23 ^ uVar24 ^ uVar25 ^ uVar26 ^ uVar27 ^ param_16 ^ uVar10;
            uVar1 = uVar1 ^ *puVar9 ^ puVar9[2] ^ puVar9[4] ^ puVar9[6] ^ puVar9[8] ^ puVar9[10] ^
                    puVar9[0xc] ^ param_15;
            uVar14 = uVar21 + uVar10;
            iVar11 = iVar11 + *puVar9 + (uint)bVar28 + puVar9[2] + (uint)CARRY4(uVar15,uVar23) +
                     puVar9[4] + (uint)CARRY4(uVar16,uVar24) +
                     puVar9[6] + (uint)CARRY4(uVar17,uVar25) +
                     puVar9[8] + (uint)CARRY4(uVar18,uVar26) +
                     puVar9[10] + (uint)CARRY4(uVar19,uVar27) +
                     puVar9[0xc] + (uint)CARRY4(uVar20,param_16) + param_15 + CARRY4(uVar21,uVar10);
          }
          uVar4 = uVar4 ^ uVar14 + 0xd;
          if (uVar4 != *(uint *)(DAT_803ddcc4 + 0xa44) ||
              (uVar1 ^ iVar11 + (uint)(0xfffffff2 < uVar14)) != *(uint *)(DAT_803ddcc4 + 0xa40)) {
            if ((uVar30 & 0xff00000000) == 0) {
              uVar5 = 0;
              uVar7 = 0x4000;
              uVar29 = extraout_f1_00;
              iVar2 = FUN_800033a8(DAT_803ddcdc,0,0x4000);
              FUN_8007f53c(uVar29,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                           uVar5,uVar7,uVar4,iVar11,uVar14,param_15,param_16);
              iVar2 = FUN_80264428((int *)&DAT_80397560,DAT_803ddcdc,0x2000,0);
              if (iVar2 == -5) {
                FUN_80264624(0,DAT_803dc364);
              }
              uVar1 = DAT_803ddcc4;
              if (iVar2 == 0) {
                iVar11 = *(int *)(DAT_803ddcdc + 0x2a40);
                if (*(int *)(DAT_803ddcdc + 0x2a44) != *(int *)(DAT_803ddcc4 + 0xa44) ||
                    iVar11 != *(int *)(DAT_803ddcc4 + 0xa40)) {
                  *(int *)(DAT_803ddcc4 + 0xa44) = *(int *)(DAT_803ddcdc + 0x2a44);
                  *(int *)(uVar1 + 0xa40) = iVar11;
                  if (((code *)param_14 == (code *)0x0) && (iVar2 = FUN_8007ea14(2), iVar2 == 0)) {
                    iVar2 = FUN_8007ea14(1);
                  }
                }
              }
            }
            else {
              iVar2 = -4;
              DAT_803dc360 = 0xc;
            }
          }
        }
        FUN_800238c4(DAT_803ddcdc);
      }
      if ((iVar2 == 0) && ((code *)param_14 != (code *)0x0)) {
        iVar2 = (*(code *)param_14)((int)uVar30,param_11,param_12,param_13);
      }
      if (DAT_803ddcda != '\0') {
        DAT_803ddcda = '\0';
        FUN_80263888((int *)&DAT_80397560);
      }
      FUN_80262bf4(0);
      FUN_800238c4(DAT_803ddcc0);
      DAT_803ddcc0 = 0;
      FUN_800238c4(DAT_803ddcc4);
      if (iVar2 != -4) {
        if (iVar2 < -4) {
          if (-6 < iVar2) {
            DAT_803dc360 = 4;
          }
        }
        else if (iVar2 == 0) {
          DAT_803dc360 = 0xd;
        }
      }
    }
  }
LAB_8007f524:
  DAT_803ddcc4 = 0;
  FUN_8028687c();
  return;
}

