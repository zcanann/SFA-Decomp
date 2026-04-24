// Function: FUN_8007eb44
// Entry: 8007eb44
// Size: 1948 bytes

void FUN_8007eb44(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,code *param_6)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  ushort uVar5;
  uint *puVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
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
  uint unaff_r23;
  uint unaff_r24;
  bool bVar25;
  ulonglong uVar26;
  
  uVar26 = FUN_802860cc();
  DAT_803dd044 = FUN_80023cc8(0x2000,0xffffffff,0);
  if (DAT_803dd044 == 0) {
    DAT_803db700 = 8;
    uVar2 = 0;
  }
  else {
    iVar3 = FUN_8007f83c((int)(uVar26 >> 0x20));
    if (iVar3 == 0) {
      FUN_80023800(DAT_803dd044);
      DAT_803dd044 = 0;
      uVar2 = 0;
    }
    else {
      FUN_802419b8(DAT_803dd044,0x2000);
      iVar3 = FUN_80263948(&DAT_80396900,DAT_803dd044,0x2000,0x2000);
      if (iVar3 == 0) {
        uVar4 = 0;
        uVar1 = 0;
        uVar9 = 1;
        iVar8 = 0;
        for (uVar5 = 0; uVar5 < 0x3f7; uVar5 = uVar5 + 8) {
          puVar6 = (uint *)(DAT_803dd044 + (uint)uVar5 * 8);
          uVar17 = puVar6[1];
          bVar25 = CARRY4(uVar9,uVar17);
          uVar7 = uVar9 + uVar17;
          uVar18 = puVar6[3];
          uVar11 = uVar7 + uVar18;
          uVar19 = puVar6[5];
          uVar12 = uVar11 + uVar19;
          uVar20 = puVar6[7];
          uVar13 = uVar12 + uVar20;
          uVar21 = puVar6[9];
          uVar14 = uVar13 + uVar21;
          uVar22 = puVar6[0xb];
          uVar15 = uVar14 + uVar22;
          uVar23 = puVar6[0xd];
          uVar16 = uVar15 + uVar23;
          uVar10 = puVar6[0xf];
          uVar4 = uVar4 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar22 ^ uVar23 ^ uVar10;
          uVar1 = uVar1 ^ *puVar6 ^ puVar6[2] ^ puVar6[4] ^ puVar6[6] ^ puVar6[8] ^ puVar6[10] ^
                  puVar6[0xc] ^ puVar6[0xe];
          uVar9 = uVar16 + uVar10;
          iVar8 = iVar8 + *puVar6 + (uint)bVar25 + puVar6[2] + (uint)CARRY4(uVar7,uVar18) +
                  puVar6[4] + (uint)CARRY4(uVar11,uVar19) + puVar6[6] + (uint)CARRY4(uVar12,uVar20)
                  + puVar6[8] + (uint)CARRY4(uVar13,uVar21) +
                  puVar6[10] + (uint)CARRY4(uVar14,uVar22) +
                  puVar6[0xc] + (uint)CARRY4(uVar15,uVar23) +
                  puVar6[0xe] + (uint)CARRY4(uVar16,uVar10);
        }
        for (; uVar5 < 0x3ff; uVar5 = uVar5 + 1) {
          puVar6 = (uint *)(DAT_803dd044 + (uint)uVar5 * 8);
          uVar10 = *puVar6;
          uVar7 = puVar6[1];
          uVar4 = uVar4 ^ uVar7;
          uVar1 = uVar1 ^ uVar10;
          bVar25 = CARRY4(uVar9,uVar7);
          uVar9 = uVar9 + uVar7;
          iVar8 = iVar8 + uVar10 + bVar25;
        }
        unaff_r23 = uVar4 ^ uVar9 + 0xd;
        unaff_r24 = uVar1 ^ iVar8 + (uint)(0xfffffff2 < uVar9);
        if ((unaff_r23 ^ *(uint *)(DAT_803dd044 + 0x1ffc) |
            unaff_r24 ^ *(uint *)(DAT_803dd044 + 0x1ff8)) != 0) {
          FUN_802419b8(DAT_803dd044,0x2000);
          iVar3 = FUN_80263948(&DAT_80396900,DAT_803dd044,0x2000,0x4000);
          if (iVar3 == 0) {
            uVar4 = 0;
            uVar1 = 0;
            uVar9 = 1;
            iVar3 = 0;
            for (uVar5 = 0; uVar5 < 0x3f7; uVar5 = uVar5 + 8) {
              puVar6 = (uint *)(DAT_803dd044 + (uint)uVar5 * 8);
              uVar17 = puVar6[1];
              bVar25 = CARRY4(uVar9,uVar17);
              uVar7 = uVar9 + uVar17;
              uVar18 = puVar6[3];
              uVar11 = uVar7 + uVar18;
              uVar19 = puVar6[5];
              uVar12 = uVar11 + uVar19;
              uVar20 = puVar6[7];
              uVar13 = uVar12 + uVar20;
              uVar21 = puVar6[9];
              uVar14 = uVar13 + uVar21;
              uVar22 = puVar6[0xb];
              uVar15 = uVar14 + uVar22;
              uVar23 = puVar6[0xd];
              uVar16 = uVar15 + uVar23;
              uVar10 = puVar6[0xf];
              uVar4 = uVar4 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar22 ^ uVar23 ^ uVar10;
              uVar1 = uVar1 ^ *puVar6 ^ puVar6[2] ^ puVar6[4] ^ puVar6[6] ^ puVar6[8] ^ puVar6[10] ^
                      puVar6[0xc] ^ puVar6[0xe];
              uVar9 = uVar16 + uVar10;
              iVar3 = iVar3 + *puVar6 + (uint)bVar25 + puVar6[2] + (uint)CARRY4(uVar7,uVar18) +
                      puVar6[4] + (uint)CARRY4(uVar11,uVar19) +
                      puVar6[6] + (uint)CARRY4(uVar12,uVar20) +
                      puVar6[8] + (uint)CARRY4(uVar13,uVar21) +
                      puVar6[10] + (uint)CARRY4(uVar14,uVar22) +
                      puVar6[0xc] + (uint)CARRY4(uVar15,uVar23) +
                      puVar6[0xe] + (uint)CARRY4(uVar16,uVar10);
            }
            for (; uVar5 < 0x3ff; uVar5 = uVar5 + 1) {
              puVar6 = (uint *)(DAT_803dd044 + (uint)uVar5 * 8);
              uVar10 = *puVar6;
              uVar7 = puVar6[1];
              uVar4 = uVar4 ^ uVar7;
              uVar1 = uVar1 ^ uVar10;
              bVar25 = CARRY4(uVar9,uVar7);
              uVar9 = uVar9 + uVar7;
              iVar3 = iVar3 + uVar10 + bVar25;
            }
            unaff_r23 = uVar4 ^ uVar9 + 0xd;
            unaff_r24 = uVar1 ^ iVar3 + (uint)(0xfffffff2 < uVar9);
            if ((unaff_r23 ^ *(uint *)(DAT_803dd044 + 0x1ffc) |
                unaff_r24 ^ *(uint *)(DAT_803dd044 + 0x1ff8)) == 0) {
              iVar3 = FUN_8007e7c0(1);
            }
            else {
              iVar3 = -0x55;
              DAT_803db700 = 10;
            }
          }
        }
      }
      uVar1 = DAT_803dd050;
      uVar4 = DAT_803dd054;
      if ((((iVar3 == 0) && (uVar1 = unaff_r24, uVar4 = unaff_r23, DAT_803dd059 != '\0')) &&
          (uVar1 = unaff_r24, uVar4 = unaff_r23, (DAT_803dd054 | DAT_803dd050) != 0)) &&
         (uVar1 = DAT_803dd050, uVar4 = DAT_803dd054,
         (unaff_r23 ^ DAT_803dd054 | unaff_r24 ^ DAT_803dd050) != 0)) {
        iVar3 = -0x55;
        DAT_803db700 = 0xb;
      }
      DAT_803dd054 = uVar4;
      DAT_803dd050 = uVar1;
      if (iVar3 == 0) {
        DAT_803dd05c = FUN_80023cc8(0x4000,0xffffffff,0);
        if (DAT_803dd05c == 0) {
          if (DAT_803dd05a != '\0') {
            DAT_803dd05a = '\0';
            FUN_80263124(&DAT_80396900);
          }
          FUN_80262490(0);
          FUN_80023800(DAT_803dd040);
          DAT_803dd040 = 0;
          FUN_80023800(DAT_803dd044);
          DAT_803dd044 = 0;
          DAT_803db700 = 8;
          uVar2 = 0;
          goto LAB_8007f2c8;
        }
        iVar3 = FUN_80263948(&DAT_80396900,DAT_803dd05c,0x2000,0);
        if (iVar3 == 0) {
          uVar4 = 0;
          uVar1 = 0;
          uVar10 = 1;
          iVar8 = 0;
          for (uVar9 = 0; (uVar9 & 0xffff) < 0x400; uVar9 = uVar9 + 8) {
            puVar6 = (uint *)(DAT_803dd05c + (uVar9 & 0xffff) * 8);
            uVar18 = puVar6[1];
            bVar25 = CARRY4(uVar10,uVar18);
            uVar11 = uVar10 + uVar18;
            uVar19 = puVar6[3];
            uVar12 = uVar11 + uVar19;
            uVar20 = puVar6[5];
            uVar13 = uVar12 + uVar20;
            uVar21 = puVar6[7];
            uVar14 = uVar13 + uVar21;
            uVar22 = puVar6[9];
            uVar15 = uVar14 + uVar22;
            uVar23 = puVar6[0xb];
            uVar16 = uVar15 + uVar23;
            uVar24 = puVar6[0xd];
            uVar17 = uVar16 + uVar24;
            uVar7 = puVar6[0xf];
            uVar4 = uVar4 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar22 ^ uVar23 ^ uVar24 ^ uVar7;
            uVar1 = uVar1 ^ *puVar6 ^ puVar6[2] ^ puVar6[4] ^ puVar6[6] ^ puVar6[8] ^ puVar6[10] ^
                    puVar6[0xc] ^ puVar6[0xe];
            uVar10 = uVar17 + uVar7;
            iVar8 = iVar8 + *puVar6 + (uint)bVar25 + puVar6[2] + (uint)CARRY4(uVar11,uVar19) +
                    puVar6[4] + (uint)CARRY4(uVar12,uVar20) +
                    puVar6[6] + (uint)CARRY4(uVar13,uVar21) +
                    puVar6[8] + (uint)CARRY4(uVar14,uVar22) +
                    puVar6[10] + (uint)CARRY4(uVar15,uVar23) +
                    puVar6[0xc] + (uint)CARRY4(uVar16,uVar24) +
                    puVar6[0xe] + (uint)CARRY4(uVar17,uVar7);
          }
          if ((uVar4 ^ uVar10 + 0xd ^ *(uint *)(DAT_803dd044 + 0xa44) |
              uVar1 ^ iVar8 + (uint)(0xfffffff2 < uVar10) ^ *(uint *)(DAT_803dd044 + 0xa40)) != 0) {
            if ((uVar26 & 0xff00000000) == 0) {
              FUN_800033a8(DAT_803dd05c,0,0x4000);
              FUN_8007f2e0();
              iVar3 = FUN_80263cc4(&DAT_80396900,DAT_803dd05c,0x2000,0);
              if (iVar3 == -5) {
                FUN_80263ec0(0,DAT_803db704);
              }
              iVar8 = DAT_803dd044;
              if (iVar3 == 0) {
                uVar1 = *(uint *)(DAT_803dd05c + 0x2a40);
                if ((*(uint *)(DAT_803dd05c + 0x2a44) ^ *(uint *)(DAT_803dd044 + 0xa44) |
                    uVar1 ^ *(uint *)(DAT_803dd044 + 0xa40)) != 0) {
                  *(uint *)(DAT_803dd044 + 0xa44) = *(uint *)(DAT_803dd05c + 0x2a44);
                  *(uint *)(iVar8 + 0xa40) = uVar1;
                  iVar3 = FUN_8007e7c0(2);
                  if (iVar3 == 0) {
                    iVar3 = FUN_8007e7c0(1);
                  }
                }
              }
            }
            else {
              iVar3 = -4;
              DAT_803db700 = 0xc;
            }
          }
        }
        FUN_80023800(DAT_803dd05c);
      }
      if ((iVar3 == 0) && (param_6 != (code *)0x0)) {
        iVar3 = (*param_6)((int)uVar26,param_3,param_4,param_5);
      }
      if (DAT_803dd05a != '\0') {
        DAT_803dd05a = '\0';
        FUN_80263124(&DAT_80396900);
      }
      FUN_80262490(0);
      FUN_80023800(DAT_803dd040);
      DAT_803dd040 = 0;
      FUN_80023800(DAT_803dd044);
      DAT_803dd044 = 0;
      if (iVar3 != -4) {
        if (iVar3 < -4) {
          if (-6 < iVar3) {
            DAT_803db700 = 4;
          }
        }
        else if (iVar3 == 0) {
          DAT_803db700 = 0xd;
          uVar2 = 1;
          goto LAB_8007f2c8;
        }
      }
      uVar2 = 0;
    }
  }
LAB_8007f2c8:
  FUN_80286118(uVar2);
  return;
}

