// Function: FUN_8024d51c
// Entry: 8024d51c
// Size: 1948 bytes

void FUN_8024d51c(uint *param_1)

{
  int iVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  ushort uVar8;
  uint uVar7;
  int iVar9;
  short sVar10;
  short sVar11;
  int iVar12;
  
  FUN_80243e74();
  uVar5 = DAT_800000cc;
  if (DAT_803aeddc != (*param_1 & 3)) {
    DAT_803dec00 = 1;
    DAT_803aeddc = *param_1 & 3;
  }
  uVar3 = *param_1 >> 2;
  if ((uVar3 == 4) && (DAT_803dec2c == 0)) {
    DAT_803dec2c = 1;
    FUN_8007d858();
    FUN_8007d858();
    FUN_8007d858();
    FUN_8007d858();
    FUN_8007d858();
    FUN_8007d858();
    FUN_8007d858();
  }
  if ((uVar3 == 0) || (DAT_803aede0 = uVar3, uVar3 == 2)) {
    DAT_803aede0 = uVar5;
  }
  DAT_803aedb8 = *(short *)((int)param_1 + 10);
  if (DAT_803aeddc == 1) {
    DAT_803aedba = *(short *)(param_1 + 3) << 1;
  }
  else {
    DAT_803aedba = *(ushort *)(param_1 + 3);
  }
  DAT_803aedbc = *(ushort *)((int)param_1 + 0xe);
  DAT_803aedca = *(ushort *)(param_1 + 1);
  DAT_803aedcc = *(short *)(param_1 + 2);
  DAT_803aedd8 = param_1[5];
  DAT_803aedce = 0;
  DAT_803aedd0 = 0;
  DAT_803aedbe = DAT_803aedcc;
  if (((DAT_803aeddc != 2) && (DAT_803aeddc != 3)) && (DAT_803aedd8 == 0)) {
    DAT_803aedbe = DAT_803aedcc << 1;
  }
  DAT_803aedfc = (uint)(DAT_803aeddc == 3);
  DAT_803aedd2 = DAT_803aedca;
  DAT_803aedd4 = DAT_803aedcc;
  pbVar2 = FUN_8024c954(DAT_803aede0 * 4 + DAT_803aeddc);
  uVar5 = 0x2d0 - DAT_803aedbc;
  uVar3 = (int)DAT_803aedb8 + (int)DAT_803debfc;
  if (((int)uVar3 <= (int)uVar5) && (uVar5 = uVar3, (int)uVar3 < 0)) {
    uVar5 = 0;
  }
  DAT_803aedc0 = (undefined2)uVar5;
  if (DAT_803aedd8 == 0) {
    iVar4 = 2;
  }
  else {
    iVar4 = 1;
  }
  iVar9 = (int)DAT_803debfe;
  uVar6 = DAT_803aedba & 1;
  uVar3 = uVar6;
  if ((int)uVar6 < (short)DAT_803aedba + iVar9) {
    uVar3 = (short)DAT_803aedba + iVar9;
  }
  DAT_803aedc2 = (ushort)uVar3;
  iVar1 = *(short *)(pbVar2 + 2) * 2 - uVar6;
  iVar12 = (int)(short)DAT_803aedba + DAT_803aedbe + iVar9;
  if (iVar12 - iVar1 < 1) {
    sVar11 = 0;
  }
  else {
    sVar11 = (short)iVar12 - (short)iVar1;
  }
  iVar12 = (short)DAT_803aedba + iVar9;
  if ((int)(iVar12 - uVar6) < 0) {
    sVar10 = (short)iVar12 - (short)uVar6;
  }
  else {
    sVar10 = 0;
  }
  DAT_803aedc4 = (DAT_803aedbe + sVar10) - sVar11;
  if ((int)(((short)DAT_803aedba + iVar9) - uVar6) < 0) {
    iVar12 = ((short)DAT_803aedba + iVar9) - uVar6;
  }
  else {
    iVar12 = 0;
  }
  DAT_803aedc6 = DAT_803aedd0 - (short)(iVar12 / iVar4);
  iVar12 = (int)(short)DAT_803aedba + DAT_803aedbe + iVar9;
  if (iVar12 - iVar1 < 1) {
    iVar12 = 0;
  }
  else {
    iVar12 = iVar12 - iVar1;
  }
  iVar9 = (short)DAT_803aedba + iVar9;
  if ((int)(iVar9 - uVar6) < 0) {
    iVar9 = iVar9 - uVar6;
  }
  else {
    iVar9 = 0;
  }
  DAT_803aedc8 = (DAT_803aedd4 + (short)(iVar9 / iVar4)) - (short)(iVar12 / iVar4);
  if (DAT_803debf8 == 0) {
    DAT_803aede0 = 3;
  }
  iVar4 = (int)(uint)*(ushort *)(pbVar2 + 0x18) >> 1;
  if (((uint)*(ushort *)(pbVar2 + 0x18) + iVar4 * -2 & 0xffff) == 0) {
    sVar11 = 0;
  }
  else {
    sVar11 = *(short *)(pbVar2 + 0x1a);
  }
  DAT_803aecfa = sVar11 + 1;
  DAT_803aecf8 = (short)iVar4 + 1U | 0x1000;
  if ((DAT_803aeddc == 2) || (DAT_803aeddc == 3)) {
    uVar8 = DAT_803aecca & 0xfffb | 4;
  }
  else {
    uVar8 = (ushort)((DAT_803aeddc & 1) << 2) | DAT_803aecca & 0xfffb;
  }
  uVar8 = uVar8 & 0xfff7 | (ushort)(DAT_803aedfc << 3);
  if ((DAT_803aede0 == 4) || (DAT_803aede0 == 5)) {
    DAT_803aecca = uVar8 & 0xfcff;
  }
  else {
    DAT_803aecca = uVar8 & 0xfcff | (ushort)(DAT_803aede0 << 8);
  }
  if ((*param_1 == 2) || (*param_1 == 3)) {
    DAT_803aed34 = DAT_803aed34 & 0xfffe | 1;
  }
  else {
    DAT_803aed34 = DAT_803aed34 & 0xfffe;
  }
  uVar6 = (uint)DAT_803aedbc;
  uVar7 = (uint)DAT_803aedd2;
  uVar3 = uVar7;
  if (DAT_803aedfc != 0) {
    uVar3 = uVar7 << 1;
  }
  if ((uVar3 & 0xffff) < uVar6) {
    DAT_803aed12 = (ushort)((uVar6 + (uVar3 & 0xffff) * 0x100 + -1) / uVar6) | 0x1000;
    DAT_803aed38 = (undefined2)uVar3;
    DAT_803dec0c = DAT_803dec0c | 0x4000280;
  }
  else {
    DAT_803aed12 = 0x100;
    DAT_803dec0c = DAT_803dec0c | 0x4000200;
  }
  DAT_803aecce = *(undefined2 *)(pbVar2 + 0x1a);
  DAT_803aeccc = *(undefined2 *)(pbVar2 + 0x1d);
  uVar3 = ((uint)pbVar2[0x1f] + (uVar5 & 0xffff)) - 0x28;
  DAT_803aecd2 = (ushort)pbVar2[0x1c] | (short)uVar3 * 0x80;
  DAT_803aecd0 = (ushort)(uVar3 >> 9) |
                 (short)(((uint)*(ushort *)(pbVar2 + 0x20) + (uVar5 & 0xffff) + 0x28) -
                        (0x2d0 - uVar6)) * 2;
  DAT_803aecde = (ushort)pbVar2[0xc] | *(short *)(pbVar2 + 0x10) << 5;
  DAT_803aecdc = (ushort)pbVar2[0xe] | *(short *)(pbVar2 + 0x14) << 5;
  DAT_803aece2 = (ushort)pbVar2[0xd] | *(short *)(pbVar2 + 0x12) << 5;
  DAT_803aece0 = (ushort)pbVar2[0xf] | *(short *)(pbVar2 + 0x16) << 5;
  DAT_803dec08 = DAT_803dec08 | 0x7c3c00c0;
  DAT_803aede4 = (char)((int)(DAT_803aedca + 0xf) >> 4);
  DAT_803aede5 = DAT_803aede4;
  if (DAT_803aedd8 != 0) {
    DAT_803aede5 = DAT_803aede4 << 1;
  }
  DAT_803aedf4 = (char)DAT_803aedce + (char)((int)(uint)DAT_803aedce >> 4) * -0x10;
  DAT_803aede6 = (undefined)((int)((uint)DAT_803aedf4 + uVar7 + 0xf) >> 4);
  DAT_803aed10 = CONCAT11(DAT_803aede6,DAT_803aede5);
  DAT_803dec0c = DAT_803dec0c | 0x8000000;
  DAT_803aee0c = pbVar2;
  if (DAT_803dec28 != 0) {
    FUN_8024d0a8(-0x7fc51248,(uint *)&DAT_803aedec,(uint *)&DAT_803aedf0,(uint *)&DAT_803aee04,
                 (uint *)&DAT_803aee08);
  }
  FUN_8024d37c(DAT_803aedc2,DAT_803aedc4,*pbVar2,*(short *)(pbVar2 + 2),*(short *)(pbVar2 + 4),
               *(short *)(pbVar2 + 6),*(short *)(pbVar2 + 8),*(short *)(pbVar2 + 10),DAT_803aedf8);
  FUN_80243e9c();
  return;
}

