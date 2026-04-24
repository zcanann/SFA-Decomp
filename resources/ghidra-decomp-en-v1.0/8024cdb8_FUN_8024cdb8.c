// Function: FUN_8024cdb8
// Entry: 8024cdb8
// Size: 1948 bytes

void FUN_8024cdb8(uint *param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  ushort uVar9;
  uint uVar8;
  int iVar10;
  short sVar11;
  short sVar12;
  int iVar13;
  
  uVar2 = FUN_8024377c();
  uVar6 = DAT_800000cc;
  if (DAT_803ae17c != (*param_1 & 3)) {
    DAT_803ddf80 = 1;
    DAT_803ae17c = *param_1 & 3;
  }
  uVar4 = *param_1 >> 2;
  if ((uVar4 == 4) && (DAT_803ddfac == 0)) {
    DAT_803ddfac = 1;
    FUN_8007d6dc(s__________________________________8032dfac);
    FUN_8007d6dc(s________C_A_U_T_I_O_N_______8032dfd8);
    FUN_8007d6dc(s_This_TV_format__DEBUG_PAL__is_on_8032e004);
    FUN_8007d6dc(s_temporary_solution_until_PAL_DAC_8032e030);
    FUN_8007d6dc(s_is_available__Please_do_NOT_use_t_8032e05c);
    FUN_8007d6dc(s_mode_in_real_games____8032e088);
    FUN_8007d6dc(s__________________________________8032dfac);
  }
  if ((uVar4 == 0) || (DAT_803ae180 = uVar4, uVar4 == 2)) {
    DAT_803ae180 = uVar6;
  }
  DAT_803ae158 = *(short *)((int)param_1 + 10);
  if (DAT_803ae17c == 1) {
    DAT_803ae15a = *(short *)(param_1 + 3) << 1;
  }
  else {
    DAT_803ae15a = *(ushort *)(param_1 + 3);
  }
  DAT_803ae15c = *(ushort *)((int)param_1 + 0xe);
  DAT_803ae16a = *(ushort *)(param_1 + 1);
  DAT_803ae16c = *(short *)(param_1 + 2);
  DAT_803ae178 = param_1[5];
  DAT_803ae16e = 0;
  DAT_803ae170 = 0;
  DAT_803ae15e = DAT_803ae16c;
  if (((DAT_803ae17c != 2) && (DAT_803ae17c != 3)) && (DAT_803ae178 == 0)) {
    DAT_803ae15e = DAT_803ae16c << 1;
  }
  DAT_803ae19c = (uint)(DAT_803ae17c == 3);
  DAT_803ae172 = DAT_803ae16a;
  DAT_803ae174 = DAT_803ae16c;
  puVar3 = (undefined *)FUN_8024c1f0(DAT_803ae180 * 4 + DAT_803ae17c);
  uVar6 = 0x2d0 - DAT_803ae15c;
  uVar4 = (int)DAT_803ae158 + (int)DAT_803ddf7c;
  if (((int)uVar4 <= (int)uVar6) && (uVar6 = uVar4, (int)uVar4 < 0)) {
    uVar6 = 0;
  }
  DAT_803ae160 = (undefined2)uVar6;
  if (DAT_803ae178 == 0) {
    iVar5 = 2;
  }
  else {
    iVar5 = 1;
  }
  iVar10 = (int)DAT_803ddf7e;
  uVar7 = DAT_803ae15a & 1;
  uVar4 = uVar7;
  if ((int)uVar7 < (short)DAT_803ae15a + iVar10) {
    uVar4 = (short)DAT_803ae15a + iVar10;
  }
  DAT_803ae162 = (undefined2)uVar4;
  iVar1 = *(short *)(puVar3 + 2) * 2 - uVar7;
  iVar13 = (int)(short)DAT_803ae15a + DAT_803ae15e + iVar10;
  if (iVar13 - iVar1 < 1) {
    sVar12 = 0;
  }
  else {
    sVar12 = (short)iVar13 - (short)iVar1;
  }
  iVar13 = (short)DAT_803ae15a + iVar10;
  if ((int)(iVar13 - uVar7) < 0) {
    sVar11 = (short)iVar13 - (short)uVar7;
  }
  else {
    sVar11 = 0;
  }
  DAT_803ae164 = (DAT_803ae15e + sVar11) - sVar12;
  if ((int)(((short)DAT_803ae15a + iVar10) - uVar7) < 0) {
    iVar13 = ((short)DAT_803ae15a + iVar10) - uVar7;
  }
  else {
    iVar13 = 0;
  }
  DAT_803ae166 = DAT_803ae170 - (short)(iVar13 / iVar5);
  iVar13 = (int)(short)DAT_803ae15a + DAT_803ae15e + iVar10;
  if (iVar13 - iVar1 < 1) {
    iVar13 = 0;
  }
  else {
    iVar13 = iVar13 - iVar1;
  }
  iVar10 = (short)DAT_803ae15a + iVar10;
  if ((int)(iVar10 - uVar7) < 0) {
    iVar10 = iVar10 - uVar7;
  }
  else {
    iVar10 = 0;
  }
  DAT_803ae168 = (DAT_803ae174 + (short)(iVar10 / iVar5)) - (short)(iVar13 / iVar5);
  if (DAT_803ddf78 == 0) {
    DAT_803ae180 = 3;
  }
  iVar5 = (int)(uint)*(ushort *)(puVar3 + 0x18) >> 1;
  if (((uint)*(ushort *)(puVar3 + 0x18) + iVar5 * -2 & 0xffff) == 0) {
    sVar12 = 0;
  }
  else {
    sVar12 = *(short *)(puVar3 + 0x1a);
  }
  DAT_803ae09a = sVar12 + 1;
  DAT_803ae098 = (short)iVar5 + 1U | 0x1000;
  if ((DAT_803ae17c == 2) || (DAT_803ae17c == 3)) {
    uVar9 = DAT_803ae06a & 0xfffb | 4;
  }
  else {
    uVar9 = (ushort)((DAT_803ae17c & 1) << 2) | DAT_803ae06a & 0xfffb;
  }
  uVar9 = uVar9 & 0xfff7 | (ushort)(DAT_803ae19c << 3);
  if ((DAT_803ae180 == 4) || (DAT_803ae180 == 5)) {
    DAT_803ae06a = uVar9 & 0xfcff;
  }
  else {
    DAT_803ae06a = uVar9 & 0xfcff | (ushort)(DAT_803ae180 << 8);
  }
  if ((*param_1 == 2) || (*param_1 == 3)) {
    DAT_803ae0d4 = DAT_803ae0d4 & 0xfffe | 1;
  }
  else {
    DAT_803ae0d4 = DAT_803ae0d4 & 0xfffe;
  }
  uVar7 = (uint)DAT_803ae15c;
  uVar8 = (uint)DAT_803ae172;
  uVar4 = uVar8;
  if (DAT_803ae19c != 0) {
    uVar4 = uVar8 << 1;
  }
  uVar4 = uVar4 & 0xffff;
  if (uVar4 < uVar7) {
    DAT_803ae0b2 = (ushort)((uVar7 + uVar4 * 0x100 + -1) / uVar7) | 0x1000;
    DAT_803ae0d8 = (undefined2)uVar4;
    DAT_803ddf8c = DAT_803ddf8c | 0x4000280;
  }
  else {
    DAT_803ae0b2 = 0x100;
    DAT_803ddf8c = DAT_803ddf8c | 0x4000200;
  }
  DAT_803ae06e = *(undefined2 *)(puVar3 + 0x1a);
  DAT_803ae06c = *(undefined2 *)(puVar3 + 0x1d);
  uVar4 = ((uint)(byte)puVar3[0x1f] + (uVar6 & 0xffff)) - 0x28;
  DAT_803ae072 = (ushort)(byte)puVar3[0x1c] | (short)uVar4 * 0x80;
  DAT_803ae070 = (ushort)(uVar4 >> 9) |
                 ((*(short *)(puVar3 + 0x20) + (short)(uVar6 & 0xffff) + 0x28) -
                 (0x2d0 - DAT_803ae15c)) * 2;
  DAT_803ae07e = (ushort)(byte)puVar3[0xc] | *(short *)(puVar3 + 0x10) << 5;
  DAT_803ae07c = (ushort)(byte)puVar3[0xe] | *(short *)(puVar3 + 0x14) << 5;
  DAT_803ae082 = (ushort)(byte)puVar3[0xd] | *(short *)(puVar3 + 0x12) << 5;
  DAT_803ae080 = (ushort)(byte)puVar3[0xf] | *(short *)(puVar3 + 0x16) << 5;
  DAT_803ddf88 = DAT_803ddf88 | 0x7c3c00c0;
  DAT_803ae184 = (char)((int)(DAT_803ae16a + 0xf) >> 4);
  DAT_803ae185 = DAT_803ae184;
  if (DAT_803ae178 != 0) {
    DAT_803ae185 = DAT_803ae184 << 1;
  }
  DAT_803ae194 = (char)DAT_803ae16e + (char)((int)(uint)DAT_803ae16e >> 4) * -0x10;
  DAT_803ae186 = (undefined)((int)((uint)DAT_803ae194 + uVar8 + 0xf) >> 4);
  DAT_803ae0b0 = CONCAT11(DAT_803ae186,DAT_803ae185);
  DAT_803ddf8c = DAT_803ddf8c | 0x8000000;
  DAT_803ae1ac = puVar3;
  if (DAT_803ddfa8 != 0) {
    FUN_8024c944(&DAT_803ae158,&DAT_803ae18c,&DAT_803ae190,&DAT_803ae1a4,&DAT_803ae1a8);
  }
  FUN_8024cc18(DAT_803ae162,DAT_803ae164,*puVar3,*(undefined2 *)(puVar3 + 2),
               *(undefined2 *)(puVar3 + 4),*(undefined2 *)(puVar3 + 6),*(undefined2 *)(puVar3 + 8),
               *(undefined2 *)(puVar3 + 10),DAT_803ae198);
  FUN_802437a4(uVar2);
  return;
}

