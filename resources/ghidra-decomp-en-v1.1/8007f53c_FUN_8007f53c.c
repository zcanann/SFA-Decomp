// Function: FUN_8007f53c
// Entry: 8007f53c
// Size: 988 bytes

void FUN_8007f53c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
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
  uint *puVar22;
  uint uVar23;
  bool bVar24;
  undefined8 uVar25;
  int aiStack_48 [17];
  
  uVar25 = FUN_8007f918(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                        &PTR_LAB_80310000,param_10,param_11,param_12,param_13,param_14,param_15,
                        param_16);
  iVar2 = FUN_80249300(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_opening_bnr_8030f718,(int)aiStack_48);
  if (iVar2 != 0) {
    uVar25 = FUN_80015888(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_48,
                          DAT_803ddcdc + 0x40,0x1800,0x20,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_48);
  }
  iVar2 = FUN_80249300(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_card_memcardicon0_img_8030f724,(int)aiStack_48);
  if (iVar2 != 0) {
    uVar25 = FUN_80015888(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_48,
                          DAT_803ddcdc + 0x1840,0x400,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_48);
  }
  iVar2 = FUN_80249300(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_card_memcardicon1_img_8030f73c,(int)aiStack_48);
  if (iVar2 != 0) {
    uVar25 = FUN_80015888(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_48,
                          DAT_803ddcdc + 0x1c40,0x400,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_48);
  }
  iVar2 = FUN_80249300(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_card_memcardicon2_img_8030f754,(int)aiStack_48);
  if (iVar2 != 0) {
    uVar25 = FUN_80015888(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_48,
                          DAT_803ddcdc + 0x2040,0x400,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_48);
  }
  iVar2 = FUN_80249300(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_card_memcardicon3_img_8030f76c,(int)aiStack_48);
  if (iVar2 != 0) {
    uVar25 = FUN_80015888(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_48,
                          DAT_803ddcdc + 0x2440,0x400,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_48);
  }
  iVar2 = FUN_80249300(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_card_memcardicon0_pal_8030f784,(int)aiStack_48);
  if (iVar2 != 0) {
    FUN_80015888(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_48,
                 DAT_803ddcdc + 0x2840,0x200,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_48);
  }
  uVar1 = DAT_803ddcdc;
  uVar7 = 0;
  uVar6 = 0;
  uVar3 = 1;
  iVar2 = 0;
  for (uVar13 = 0; (uVar13 & 0xffff) < 0x400; uVar13 = uVar13 + 8) {
    puVar22 = (uint *)(DAT_803ddcdc + (uVar13 & 0xffff) * 8);
    uVar23 = puVar22[1];
    bVar24 = CARRY4(uVar3,uVar23);
    uVar8 = uVar3 + uVar23;
    uVar17 = puVar22[3];
    uVar9 = uVar8 + uVar17;
    uVar18 = puVar22[5];
    uVar10 = uVar9 + uVar18;
    uVar19 = puVar22[7];
    uVar11 = uVar10 + uVar19;
    uVar20 = puVar22[9];
    uVar12 = uVar11 + uVar20;
    uVar21 = puVar22[0xb];
    uVar14 = uVar12 + uVar21;
    uVar5 = puVar22[0xd];
    uVar15 = uVar14 + uVar5;
    uVar16 = puVar22[0xf];
    uVar7 = uVar7 ^ uVar23 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar5 ^ uVar16;
    uVar6 = uVar6 ^ *puVar22 ^ puVar22[2] ^ puVar22[4] ^ puVar22[6] ^ puVar22[8] ^ puVar22[10] ^
            puVar22[0xc] ^ puVar22[0xe];
    uVar3 = uVar15 + uVar16;
    iVar2 = iVar2 + *puVar22 + (uint)bVar24 + puVar22[2] + (uint)CARRY4(uVar8,uVar17) +
            puVar22[4] + (uint)CARRY4(uVar9,uVar18) + puVar22[6] + (uint)CARRY4(uVar10,uVar19) +
            puVar22[8] + (uint)CARRY4(uVar11,uVar20) + puVar22[10] + (uint)CARRY4(uVar12,uVar21) +
            puVar22[0xc] + (uint)CARRY4(uVar14,uVar5) + puVar22[0xe] + (uint)CARRY4(uVar15,uVar16);
  }
  uVar13 = 0;
  *(uint *)(DAT_803ddcdc + 0x2a44) = uVar7 ^ uVar3 + 0xd;
  *(uint *)(uVar1 + 0x2a40) = uVar6 ^ iVar2 + (uint)(0xfffffff2 < uVar3);
  uVar1 = DAT_803ddcdc;
  uVar3 = 0;
  uVar6 = 1;
  iVar2 = 0;
  for (uVar4 = 0; uVar4 < 0x3f7; uVar4 = uVar4 + 8) {
    puVar22 = (uint *)(DAT_803ddcdc + 0x2000 + (uint)uVar4 * 8);
    uVar14 = puVar22[1];
    bVar24 = CARRY4(uVar6,uVar14);
    uVar7 = uVar6 + uVar14;
    uVar15 = puVar22[3];
    uVar23 = uVar7 + uVar15;
    uVar16 = puVar22[5];
    uVar8 = uVar23 + uVar16;
    uVar17 = puVar22[7];
    uVar9 = uVar8 + uVar17;
    uVar18 = puVar22[9];
    uVar10 = uVar9 + uVar18;
    uVar19 = puVar22[0xb];
    uVar11 = uVar10 + uVar19;
    uVar20 = puVar22[0xd];
    uVar12 = uVar11 + uVar20;
    uVar21 = puVar22[0xf];
    uVar13 = uVar13 ^ uVar14 ^ uVar15 ^ uVar16 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21;
    uVar3 = uVar3 ^ *puVar22 ^ puVar22[2] ^ puVar22[4] ^ puVar22[6] ^ puVar22[8] ^ puVar22[10] ^
            puVar22[0xc] ^ puVar22[0xe];
    uVar6 = uVar12 + uVar21;
    iVar2 = iVar2 + *puVar22 + (uint)bVar24 + puVar22[2] + (uint)CARRY4(uVar7,uVar15) +
            puVar22[4] + (uint)CARRY4(uVar23,uVar16) + puVar22[6] + (uint)CARRY4(uVar8,uVar17) +
            puVar22[8] + (uint)CARRY4(uVar9,uVar18) + puVar22[10] + (uint)CARRY4(uVar10,uVar19) +
            puVar22[0xc] + (uint)CARRY4(uVar11,uVar20) + puVar22[0xe] + (uint)CARRY4(uVar12,uVar21);
  }
  for (; uVar4 < 0x3ff; uVar4 = uVar4 + 1) {
    puVar22 = (uint *)(DAT_803ddcdc + 0x2000 + (uint)uVar4 * 8);
    uVar7 = *puVar22;
    uVar23 = puVar22[1];
    uVar13 = uVar13 ^ uVar23;
    uVar3 = uVar3 ^ uVar7;
    bVar24 = CARRY4(uVar6,uVar23);
    uVar6 = uVar6 + uVar23;
    iVar2 = iVar2 + uVar7 + bVar24;
  }
  *(uint *)(DAT_803ddcdc + 0x3ffc) = uVar13 ^ uVar6 + 0xd;
  *(uint *)(uVar1 + 0x3ff8) = uVar3 ^ iVar2 + (uint)(0xfffffff2 < uVar6);
  FUN_802420e0(DAT_803ddcdc,0x4000);
  return;
}

