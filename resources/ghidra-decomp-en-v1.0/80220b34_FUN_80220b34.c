// Function: FUN_80220b34
// Entry: 80220b34
// Size: 1220 bytes

void FUN_80220b34(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  int iVar10;
  float local_28;
  float local_24;
  float local_20;
  
  iVar3 = FUN_802860dc();
  iVar10 = *(int *)(iVar3 + 0xb8);
  FUN_80094378((double)FLOAT_803e6bcc,(double)FLOAT_803e6bd0,(double)FLOAT_803e6bd4);
  if (*(int *)(iVar3 + 0xf4) == 0) {
    iVar4 = FUN_8001ffb4(0xe7b);
    if (iVar4 == 0) {
      FUN_80008b74(iVar3,iVar3,0x210,0);
      FUN_80008b74(iVar3,iVar3,0x20f,0);
      FUN_80008b74(iVar3,iVar3,0x212,0);
      FUN_80008b74(iVar3,iVar3,0x1ea,0);
      FUN_80088e54((double)FLOAT_803e6bd8,0);
      FUN_800200e8(0xe7b,1);
    }
    *(undefined4 *)(iVar3 + 0xf4) = 1;
  }
  FUN_801d7ed4(iVar10,2,0x1a7,0x64b,0xf0e,0xe5);
  FUN_801d8060(iVar10,1,0xffffffff,0xffffffff,0xe26,0xb8);
  FUN_801d7ed4(iVar10,4,0xffffffff,0xffffffff,0xcbb,0xc4);
  uVar5 = FUN_8001ffb4(0xe30);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_8001ffb4(0xe31);
  uVar6 = uVar6 & 0xff;
  uVar7 = FUN_8001ffb4(0xe32);
  uVar7 = uVar7 & 0xff;
  uVar8 = FUN_8001ffb4(0xe33);
  uVar8 = uVar8 & 0xff;
  if (((((*(byte *)(iVar10 + 8) >> 1 & 1) == 0) && (uVar5 != 0)) && (uVar6 != 0)) &&
     ((uVar7 != 0 && (uVar8 != 0)))) {
    *(byte *)(iVar10 + 8) = *(byte *)(iVar10 + 8) & 0xfd | 2;
    FUN_800200e8(0xe9c,1);
    FUN_8000bb18(0,0x7e);
  }
  else {
    bVar9 = *(byte *)(iVar10 + 8);
    if (((uVar5 != (bVar9 >> 5 & 1)) || ((uVar6 != (bVar9 >> 4 & 1) || (uVar7 != (bVar9 >> 3 & 1))))
        ) || (uVar8 != (bVar9 >> 2 & 1))) {
      FUN_8000bb18(0,0x109);
    }
  }
  *(byte *)(iVar10 + 8) = (byte)(uVar5 << 5) & 0x20 | *(byte *)(iVar10 + 8) & 0xdf;
  *(byte *)(iVar10 + 8) = (byte)(uVar6 << 4) & 0x10 | *(byte *)(iVar10 + 8) & 0xef;
  *(byte *)(iVar10 + 8) = (byte)(uVar7 << 3) & 8 | *(byte *)(iVar10 + 8) & 0xf7;
  *(byte *)(iVar10 + 8) = (byte)(uVar8 << 2) & 4 | *(byte *)(iVar10 + 8) & 0xfb;
  bVar9 = FUN_8001ffb4(0xe38);
  uVar5 = FUN_8001ffb4(0xe3c);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_8001ffb4(0xe3d);
  uVar6 = uVar6 & 0xff;
  uVar7 = FUN_8001ffb4(0xe3e);
  uVar7 = uVar7 & 0xff;
  if (((((*(byte *)(iVar10 + 9) >> 4 & 1) == 0) && (bVar9 != 0)) && (uVar5 != 0)) &&
     ((uVar6 != 0 && (uVar7 != 0)))) {
    *(byte *)(iVar10 + 9) = *(byte *)(iVar10 + 9) & 0xef | 0x10;
    FUN_8000bb18(0,0x7e);
  }
  else {
    if (bVar9 == (*(byte *)(iVar10 + 8) & 1)) {
      bVar1 = *(byte *)(iVar10 + 9);
      if (((uVar5 == bVar1 >> 7) && (uVar6 == (bVar1 >> 6 & 1))) && (uVar7 == (bVar1 >> 5 & 1)))
      goto LAB_80220df8;
    }
    FUN_8000bb18(0,0x109);
  }
LAB_80220df8:
  *(byte *)(iVar10 + 8) = bVar9 & 1 | *(byte *)(iVar10 + 8) & 0xfe;
  *(byte *)(iVar10 + 9) = (byte)(uVar5 << 7) | *(byte *)(iVar10 + 9) & 0x7f;
  *(byte *)(iVar10 + 9) = (byte)(uVar6 << 6) & 0x40 | *(byte *)(iVar10 + 9) & 0xbf;
  *(byte *)(iVar10 + 9) = (byte)(uVar7 << 5) & 0x20 | *(byte *)(iVar10 + 9) & 0xdf;
  uVar5 = FUN_8001ffb4(0x9e0);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_8001ffb4(0x9e1);
  uVar6 = uVar6 & 0xff;
  uVar7 = FUN_8001ffb4(0x9e2);
  uVar7 = uVar7 & 0xff;
  bVar9 = FUN_8001ffb4(0x9e7);
  if ((((uVar5 == 0) || (uVar6 == 0)) || (uVar7 == 0)) || (bVar9 == 0)) {
    bVar1 = *(byte *)(iVar10 + 9);
    if (((uVar5 != (bVar1 >> 3 & 1)) || (uVar6 != (bVar1 >> 2 & 1))) ||
       ((uVar7 != (bVar1 >> 1 & 1) || (bVar9 != (bVar1 & 1))))) {
      *(float *)(iVar10 + 4) = FLOAT_803e6bdc;
    }
  }
  fVar2 = FLOAT_803e6bd8;
  if ((FLOAT_803e6bd8 < *(float *)(iVar10 + 4)) &&
     (*(float *)(iVar10 + 4) = *(float *)(iVar10 + 4) - FLOAT_803db414,
     *(float *)(iVar10 + 4) <= fVar2)) {
    FUN_8000bb18(0,0x4bd);
  }
  *(byte *)(iVar10 + 9) = (byte)(uVar5 << 3) & 8 | *(byte *)(iVar10 + 9) & 0xf7;
  *(byte *)(iVar10 + 9) = (byte)(uVar6 << 2) & 4 | *(byte *)(iVar10 + 9) & 0xfb;
  *(byte *)(iVar10 + 9) = (byte)(uVar7 << 1) & 2 | *(byte *)(iVar10 + 9) & 0xfd;
  *(byte *)(iVar10 + 9) = bVar9 & 1 | *(byte *)(iVar10 + 9) & 0xfe;
  if (*(char *)(iVar10 + 8) < '\0') {
    iVar3 = FUN_8001ffb4(0x9f0);
    if ((iVar3 == 0) || (iVar3 = FUN_8001ffb4(0x632), iVar3 != 0)) {
      (**(code **)(*DAT_803dcaac + 0x2c))();
      *(byte *)(iVar10 + 8) = *(byte *)(iVar10 + 8) & 0x7f;
    }
  }
  else {
    iVar3 = FUN_8001ffb4(0x9f0);
    if ((iVar3 != 0) && (iVar3 = FUN_8001ffb4(0x632), iVar3 == 0)) {
      local_28 = FLOAT_803e6be0;
      local_24 = FLOAT_803e6be4;
      local_20 = FLOAT_803e6be8;
      (**(code **)(*DAT_803dcaac + 0x24))(&local_28,0x7fff,0,0);
      *(byte *)(iVar10 + 8) = *(byte *)(iVar10 + 8) & 0x7f | 0x80;
    }
  }
  FUN_80286128();
  return;
}

