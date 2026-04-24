// Function: FUN_8028ce8c
// Entry: 8028ce8c
// Size: 696 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 *
FUN_8028ce8c(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 extraout_r4;
  uint uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 *puVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  uint uVar13;
  uint uVar14;
  undefined4 in_r11;
  undefined4 in_r12;
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
  undefined4 uVar33;
  uint uVar34;
  uint in_MSR;
  undefined4 uVar35;
  
  uVar3 = *param_1;
  puVar4 = (undefined *)param_1[1];
  uVar5 = param_1[2];
  uVar1 = *(ushort *)((int)param_1 + 0x1a2);
  uVar13 = (uint)uVar1;
  uVar14 = uVar1 & 2;
  if ((uVar1 & 2) == 0) {
    uVar15 = param_1[0xd];
    uVar16 = param_1[0xe];
    uVar17 = param_1[0xf];
    uVar18 = param_1[0x10];
    uVar19 = param_1[0x11];
    uVar20 = param_1[0x12];
    uVar21 = param_1[0x13];
    uVar22 = param_1[0x14];
    uVar23 = param_1[0x15];
    uVar24 = param_1[0x16];
    uVar25 = param_1[0x17];
    uVar26 = param_1[0x18];
    uVar27 = param_1[0x19];
    uVar28 = param_1[0x1a];
    uVar29 = param_1[0x1b];
    uVar30 = param_1[0x1c];
    uVar31 = param_1[0x1d];
    uVar32 = param_1[0x1e];
  }
  else {
    *(ushort *)((int)param_1 + 0x1a2) = uVar1 & 0xfffd;
    uVar13 = param_1[5];
    uVar14 = param_1[6];
    param_5 = param_1[7];
    param_6 = param_1[8];
    param_7 = param_1[9];
    param_8 = param_1[10];
    in_r11 = param_1[0xb];
    in_r12 = param_1[0xc];
    uVar15 = param_1[0xd];
    uVar16 = param_1[0xe];
    uVar17 = param_1[0xf];
    uVar18 = param_1[0x10];
    uVar19 = param_1[0x11];
    uVar20 = param_1[0x12];
    uVar21 = param_1[0x13];
    uVar22 = param_1[0x14];
    uVar23 = param_1[0x15];
    uVar24 = param_1[0x16];
    uVar25 = param_1[0x17];
    uVar26 = param_1[0x18];
    uVar27 = param_1[0x19];
    uVar28 = param_1[0x1a];
    uVar29 = param_1[0x1b];
    uVar30 = param_1[0x1c];
    uVar31 = param_1[0x1d];
    uVar32 = param_1[0x1e];
  }
  uVar7 = param_1[0x20];
  uVar8 = param_1[0x22];
  uVar9 = param_1[0x23];
  uVar34 = in_MSR & 0x9000;
  puVar10 = (undefined4 *)param_1[3];
  uVar11 = param_1[4];
  uVar6 = param_1[0x66];
  uVar12 = param_1[0x67];
  uVar33 = param_1[0x1f];
  uVar7 = uVar7 & 0xf0000000 | (uint)((byte)(uVar7 >> 0x18) & 0xf) << 0x18 |
          (uint)((byte)(uVar7 >> 0x14) & 0xf) << 0x14 | (uint)((byte)(uVar7 >> 0x10) & 0xf) << 0x10
          | (uint)((byte)(uVar7 >> 0xc) & 0xf) << 0xc | (uint)((byte)(uVar7 >> 8) & 0xf) << 8 |
          (uint)((byte)(uVar7 >> 4) & 0xf) << 4 | (uint)((byte)uVar7 & 0xf);
  sync(0);
  sync(0);
  DAT_803d82f8 = (undefined2)param_2;
  uVar35 = param_1[0x21];
  if (param_2 == 0x500) {
    DAT_803d87cc = param_1[0x21];
    FUN_8028cf14();
    if ((*DAT_803d839c == '\0') || (DAT_80332308._0_1_ == '\x01')) {
      returnFromInterrupt(uVar34,uVar12);
      return DAT_803d87dc;
    }
    _DAT_803d8398 = CONCAT13(1,DAT_803d8398_1);
    uVar11 = extraout_r4;
    uVar35 = DAT_803d87cc;
  }
  if (DAT_80332308._0_1_ == '\0') {
    DAT_803d8698 = CONCAT22(DAT_803d82f8,DAT_803d82f8);
    DAT_803d83a0 = uVar3;
    DAT_803d83a4 = puVar4;
    DAT_803d83a8 = uVar5;
    DAT_803d83ac = puVar10;
    DAT_803d83b0 = uVar11;
    DAT_803d83b4 = uVar13;
    DAT_803d83b8 = uVar14;
    DAT_803d83bc = param_5;
    DAT_803d83c0 = param_6;
    DAT_803d83c4 = param_7;
    DAT_803d83c8 = param_8;
    DAT_803d83cc = in_r11;
    DAT_803d83d0 = in_r12;
    DAT_803d83d4 = uVar15;
    DAT_803d83d8 = uVar16;
    DAT_803d83dc = uVar17;
    DAT_803d83e0 = uVar18;
    DAT_803d83e4 = uVar19;
    DAT_803d83e8 = uVar20;
    DAT_803d83ec = uVar21;
    DAT_803d83f0 = uVar22;
    DAT_803d83f4 = uVar23;
    DAT_803d83f8 = uVar24;
    DAT_803d83fc = uVar25;
    DAT_803d8400 = uVar26;
    DAT_803d8404 = uVar27;
    DAT_803d8408 = uVar28;
    DAT_803d840c = uVar29;
    DAT_803d8410 = uVar30;
    DAT_803d8414 = uVar31;
    DAT_803d8418 = uVar32;
    DAT_803d841c = uVar33;
    DAT_803d8420 = uVar6;
    DAT_803d8424 = uVar35;
    DAT_803d8428 = uVar7;
    DAT_803d842c = uVar8;
    DAT_803d8430 = uVar9;
    FUN_8028cad0();
    uVar16 = DAT_803d837c;
    uVar15 = DAT_803d8324;
    uVar5 = DAT_803d8320;
    uVar3 = DAT_803d831c;
    iVar2 = DAT_803d8300;
    DAT_80332308._0_1_ = 1;
    sync(0);
    sync(0);
    *(int *)(DAT_803d8300 + -0x20) = DAT_803d8300;
    *(undefined4 *)(iVar2 + 4) = uVar16;
    puVar10 = &DAT_803d82fc;
    if (_DAT_803d8398 == 0) {
      uVar13 = DAT_803d8698 & 0xffff;
      if ((uVar13 == 0xd00) || ((uVar13 < 0xd00 && (uVar13 == 0x700)))) {
        *(undefined4 *)(iVar2 + -0x18) = 4;
        FUN_8028c6f4(iVar2 + -0x14,DAT_803d8420,iVar2 + -0x18,0,1,uVar3,uVar5,uVar15);
        if (*(int *)(iVar2 + -0x14) == 0xfe00000) {
          uVar3 = 5;
        }
        else {
          uVar3 = 3;
        }
      }
      else {
        uVar3 = 4;
      }
      FUN_80286978(iVar2 + -0x10,uVar3);
      puVar10 = (undefined4 *)FUN_80286990(iVar2 + -0x10);
    }
    else {
      _DAT_803d8398 = 0;
    }
    return puVar10;
  }
  returnFromInterrupt(uVar34,uVar12);
  DAT_803322fc = uVar6;
  DAT_80332304 = DAT_803d82f8;
  DAT_80332308._1_1_ = 1;
  return puVar10;
}

