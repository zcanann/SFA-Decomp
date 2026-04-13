// Function: FUN_8028d5ec
// Entry: 8028d5ec
// Size: 696 bytes

undefined4
FUN_8028d5ec(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 extraout_r4;
  uint uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  uint uVar12;
  uint uVar13;
  undefined4 in_r11;
  undefined4 in_r12;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined4 uVar26;
  undefined4 uVar27;
  undefined4 uVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  undefined4 uVar31;
  undefined4 uVar32;
  uint uVar33;
  uint in_MSR;
  undefined4 uVar34;
  
  uVar2 = *param_1;
  puVar3 = (undefined *)param_1[1];
  uVar4 = param_1[2];
  uVar1 = *(ushort *)((int)param_1 + 0x1a2);
  uVar12 = (uint)uVar1;
  uVar13 = uVar1 & 2;
  if ((uVar1 & 2) == 0) {
    uVar14 = param_1[0xd];
    uVar15 = param_1[0xe];
    uVar16 = param_1[0xf];
    uVar17 = param_1[0x10];
    uVar18 = param_1[0x11];
    uVar19 = param_1[0x12];
    uVar20 = param_1[0x13];
    uVar21 = param_1[0x14];
    uVar22 = param_1[0x15];
    uVar23 = param_1[0x16];
    uVar24 = param_1[0x17];
    uVar25 = param_1[0x18];
    uVar26 = param_1[0x19];
    uVar27 = param_1[0x1a];
    uVar28 = param_1[0x1b];
    uVar29 = param_1[0x1c];
    uVar30 = param_1[0x1d];
    uVar31 = param_1[0x1e];
  }
  else {
    *(ushort *)((int)param_1 + 0x1a2) = uVar1 & 0xfffd;
    uVar12 = param_1[5];
    uVar13 = param_1[6];
    param_5 = param_1[7];
    param_6 = param_1[8];
    param_7 = param_1[9];
    param_8 = param_1[10];
    in_r11 = param_1[0xb];
    in_r12 = param_1[0xc];
    uVar14 = param_1[0xd];
    uVar15 = param_1[0xe];
    uVar16 = param_1[0xf];
    uVar17 = param_1[0x10];
    uVar18 = param_1[0x11];
    uVar19 = param_1[0x12];
    uVar20 = param_1[0x13];
    uVar21 = param_1[0x14];
    uVar22 = param_1[0x15];
    uVar23 = param_1[0x16];
    uVar24 = param_1[0x17];
    uVar25 = param_1[0x18];
    uVar26 = param_1[0x19];
    uVar27 = param_1[0x1a];
    uVar28 = param_1[0x1b];
    uVar29 = param_1[0x1c];
    uVar30 = param_1[0x1d];
    uVar31 = param_1[0x1e];
  }
  uVar6 = param_1[0x20];
  uVar7 = param_1[0x22];
  uVar8 = param_1[0x23];
  uVar33 = in_MSR & 0x9000;
  uVar9 = param_1[3];
  uVar10 = param_1[4];
  uVar5 = param_1[0x66];
  uVar11 = param_1[0x67];
  uVar32 = param_1[0x1f];
  uVar6 = uVar6 & 0xf0000000 | (uint)((byte)(uVar6 >> 0x18) & 0xf) << 0x18 |
          (uint)((byte)(uVar6 >> 0x14) & 0xf) << 0x14 | (uint)((byte)(uVar6 >> 0x10) & 0xf) << 0x10
          | (uint)((byte)(uVar6 >> 0xc) & 0xf) << 0xc | (uint)((byte)(uVar6 >> 8) & 0xf) << 8 |
          (uint)((byte)(uVar6 >> 4) & 0xf) << 4 | (uint)((byte)uVar6 & 0xf);
  sync(0);
  sync(0);
  DAT_803d8f58 = (undefined2)param_2;
  uVar34 = param_1[0x21];
  if (param_2 == 0x500) {
    DAT_803d942c = param_1[0x21];
    FUN_8028d674();
    if ((*DAT_803d8ffc == '\0') || (DAT_80332f68._0_1_ == '\x01')) {
      returnFromInterrupt(uVar33,uVar11);
      return DAT_803d943c;
    }
    DAT_803d8ff8._0_1_ = 1;
    uVar10 = extraout_r4;
    uVar34 = DAT_803d942c;
  }
  if (DAT_80332f68._0_1_ != '\0') {
    DAT_80332f64._0_2_ = DAT_803d8f58;
    DAT_80332f5c = uVar5;
    DAT_80332f68._1_1_ = 1;
    returnFromInterrupt(uVar33,uVar11);
    return uVar9;
  }
  DAT_803d92f8._0_2_ = DAT_803d8f58;
  DAT_803d92f8._2_2_ = DAT_803d8f58;
  DAT_803d9000 = uVar2;
  DAT_803d9004 = puVar3;
  DAT_803d9008 = uVar4;
  DAT_803d900c = uVar9;
  DAT_803d9010 = uVar10;
  DAT_803d9014 = uVar12;
  DAT_803d9018 = uVar13;
  DAT_803d901c = param_5;
  DAT_803d9020 = param_6;
  DAT_803d9024 = param_7;
  DAT_803d9028 = param_8;
  DAT_803d902c = in_r11;
  DAT_803d9030 = in_r12;
  DAT_803d9034 = uVar14;
  DAT_803d9038 = uVar15;
  DAT_803d903c = uVar16;
  DAT_803d9040 = uVar17;
  DAT_803d9044 = uVar18;
  DAT_803d9048 = uVar19;
  DAT_803d904c = uVar20;
  DAT_803d9050 = uVar21;
  DAT_803d9054 = uVar22;
  DAT_803d9058 = uVar23;
  DAT_803d905c = uVar24;
  DAT_803d9060 = uVar25;
  DAT_803d9064 = uVar26;
  DAT_803d9068 = uVar27;
  DAT_803d906c = uVar28;
  DAT_803d9070 = uVar29;
  DAT_803d9074 = uVar30;
  DAT_803d9078 = uVar31;
  DAT_803d907c = uVar32;
  DAT_803d9080 = uVar5;
  DAT_803d9084 = uVar34;
  DAT_803d9088 = uVar6;
  DAT_803d908c = uVar7;
  DAT_803d9090 = uVar8;
  FUN_8028d230();
  DAT_80332f68._0_1_ = 1;
  sync(0);
  sync(0);
  uVar2 = FUN_8028c494();
  return uVar2;
}

