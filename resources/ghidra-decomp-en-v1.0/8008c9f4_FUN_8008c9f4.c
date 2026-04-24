// Function: FUN_8008c9f4
// Entry: 8008c9f4
// Size: 1684 bytes

void FUN_8008c9f4(int param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  double dVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  bVar1 = (*(byte *)(param_1 + 0x58) & 0x80) != 0;
  *(undefined4 *)(&DAT_803dd184)[bVar1] = 0;
  *(undefined *)((&DAT_803dd184)[bVar1] + 0x317) = 1;
  fVar2 = FLOAT_803df108;
  iVar8 = 0;
  iVar7 = 0;
  iVar9 = 2;
  do {
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x178) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x17c) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x180) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x184) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x188) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x18c) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 400) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x194) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x198) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x19c) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x1a0) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x1a4) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x1a8) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x1ac) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x1b0) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x1b4) = fVar2;
    fVar3 = FLOAT_803df108;
    iVar7 = iVar7 + 0x40;
    iVar8 = iVar8 + 0x10;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar7 = iVar8 * 4;
  iVar9 = 0x21 - iVar8;
  if (iVar8 < 0x21) {
    do {
      *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x178) = fVar3;
      iVar7 = iVar7 + 4;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  fVar2 = FLOAT_803df108;
  iVar8 = 0;
  iVar7 = 0;
  iVar9 = 2;
  do {
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x70) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x74) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x78) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x7c) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x80) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x84) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x88) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x8c) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x90) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x94) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x98) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x9c) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0xa0) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0xa4) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0xa8) = fVar2;
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0xac) = fVar2;
    fVar3 = FLOAT_803df108;
    iVar7 = iVar7 + 0x40;
    iVar8 = iVar8 + 0x10;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar7 = iVar8 * 4;
  iVar9 = 0x21 - iVar8;
  if (iVar8 < 0x21) {
    do {
      *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x70) = fVar3;
      iVar7 = iVar7 + 4;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  fVar2 = FLOAT_803df108;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2ac) = FLOAT_803df108;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2b0) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2b4) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2b8) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 700) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2c0) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2c4) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2c8) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2cc) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2d0) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2d4) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2d8) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2dc) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2e0) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2e4) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2e8) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2ec) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2f0) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2f4) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2f8) = fVar2;
  *(float *)((&DAT_803dd184)[bVar1] + 0x2fc) = fVar2;
  iVar8 = 0x54;
  iVar7 = 1;
  do {
    *(float *)((&DAT_803dd184)[bVar1] + iVar8 + 0x2ac) = fVar2;
    fVar4 = FLOAT_803df110;
    fVar3 = FLOAT_803df10c;
    iVar8 = iVar8 + 4;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  *(float *)((&DAT_803dd184)[bVar1] + 0x1fc) = FLOAT_803df10c;
  *(float *)((&DAT_803dd184)[bVar1] + 0x228) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x200) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x22c) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x204) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x230) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x208) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x234) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x20c) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x238) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x210) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x23c) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x214) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x240) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x218) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x244) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x21c) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x248) = fVar4;
  *(float *)((&DAT_803dd184)[bVar1] + 0x220) = fVar3;
  *(float *)((&DAT_803dd184)[bVar1] + 0x24c) = fVar4;
  iVar8 = 0x28;
  iVar7 = 1;
  do {
    *(float *)((&DAT_803dd184)[bVar1] + iVar8 + 0x1fc) = fVar3;
    *(float *)((&DAT_803dd184)[bVar1] + iVar8 + 0x228) = fVar4;
    dVar5 = DOUBLE_803df128;
    iVar8 = iVar8 + 4;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  pbVar6 = &DAT_8030f4a0;
  iVar7 = 0;
  iVar8 = 0xb;
  do {
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0xf4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + *pbVar6 + 0xc)) - dVar5);
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x120) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + *pbVar6 + 0x14)) - dVar5);
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x14c) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + *pbVar6 + 0x1c)) - dVar5);
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x254) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_1 + (uint)*pbVar6 * 2 + 0x3e))
                - dVar5);
    *(float *)((&DAT_803dd184)[bVar1] + iVar7 + 0x280) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_1 + (uint)*pbVar6 * 2 + 0x2e))
                - dVar5);
    pbVar6 = pbVar6 + 1;
    iVar7 = iVar7 + 4;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  *(ushort *)((&DAT_803dd184)[bVar1] + 4) = (ushort)*(byte *)(param_1 + 0x58);
  *(ushort *)((&DAT_803dd184)[bVar1] + 6) = (ushort)*(byte *)(param_1 + 0x59);
  fVar2 = FLOAT_803df108;
  *(float *)((&DAT_803dd184)[bVar1] + 100) = FLOAT_803df108;
  *(float *)((&DAT_803dd184)[bVar1] + 0x68) = fVar2;
  *(undefined *)((&DAT_803dd184)[bVar1] + 0x314) = 0xff;
  *(float *)((&DAT_803dd184)[bVar1] + 0x6c) = fVar2;
  if (*(short *)(param_1 + 0x2a) == 0) {
    *(undefined2 *)(param_1 + 0x2a) = 1;
  }
  if (*(ushort *)(param_1 + 0x2a) == 0) {
    *(undefined4 *)((&DAT_803dd184)[bVar1] + 0x3c) = 0;
    *(float *)((&DAT_803dd184)[bVar1] + 0x5c) = FLOAT_803df114;
  }
  else {
    *(uint *)((&DAT_803dd184)[bVar1] + 0x3c) = (uint)*(ushort *)(param_1 + 0x2a);
    *(undefined4 *)((&DAT_803dd184)[bVar1] + 0x48) = 1;
    *(uint *)((&DAT_803dd184)[bVar1] + 8) = (uint)*(ushort *)(param_1 + 0x2e);
    *(float *)((&DAT_803dd184)[bVar1] + 0x5c) =
         FLOAT_803df114 /
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_1 + 0x2a)) - DOUBLE_803df128);
  }
  if (*(short *)(param_1 + 0x2c) == 0) {
    *(undefined2 *)(param_1 + 0x2c) = 1;
  }
  if (*(ushort *)(param_1 + 0x2c) == 0) {
    *(undefined4 *)((&DAT_803dd184)[bVar1] + 0x40) = 0;
    *(float *)((&DAT_803dd184)[bVar1] + 0x60) = FLOAT_803df114;
  }
  else {
    *(uint *)((&DAT_803dd184)[bVar1] + 0x40) = (uint)*(ushort *)(param_1 + 0x2c);
    dVar5 = DOUBLE_803df128;
    *(float *)((&DAT_803dd184)[bVar1] + 0x58) =
         FLOAT_803df118 /
         (FLOAT_803df11c *
         ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_1 + 0x2c)) - DOUBLE_803df128)
         / FLOAT_803df120));
    *(undefined4 *)((&DAT_803dd184)[bVar1] + 0xc) = 0x5dc;
    *(float *)((&DAT_803dd184)[bVar1] + 0x60) =
         FLOAT_803df114 /
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_1 + 0x2c)) - dVar5);
  }
  *(undefined4 *)((&DAT_803dd184)[bVar1] + 0x44) = 0;
  return;
}

