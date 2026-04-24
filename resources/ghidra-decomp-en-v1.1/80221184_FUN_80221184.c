// Function: FUN_80221184
// Entry: 80221184
// Size: 1220 bytes

void FUN_80221184(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_28;
  float local_24;
  float local_20;
  
  iVar3 = FUN_80286840();
  iVar8 = *(int *)(iVar3 + 0xb8);
  dVar10 = (double)FLOAT_803e7868;
  dVar11 = (double)FLOAT_803e786c;
  uVar9 = FUN_80094604((double)FLOAT_803e7864,dVar10,dVar11);
  if (*(int *)(iVar3 + 0xf4) == 0) {
    uVar4 = FUN_80020078(0xe7b);
    if (uVar4 == 0) {
      uVar9 = FUN_80008b74(uVar9,dVar10,dVar11,in_f4,in_f5,in_f6,in_f7,in_f8,iVar3,iVar3,0x210,0,
                           in_r7,in_r8,in_r9,in_r10);
      uVar9 = FUN_80008b74(uVar9,dVar10,dVar11,in_f4,in_f5,in_f6,in_f7,in_f8,iVar3,iVar3,0x20f,0,
                           in_r7,in_r8,in_r9,in_r10);
      uVar9 = FUN_80008b74(uVar9,dVar10,dVar11,in_f4,in_f5,in_f6,in_f7,in_f8,iVar3,iVar3,0x212,0,
                           in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar9,dVar10,dVar11,in_f4,in_f5,in_f6,in_f7,in_f8,iVar3,iVar3,0x1ea,0,in_r7,in_r8
                   ,in_r9,in_r10);
      FUN_800890e0((double)FLOAT_803e7870,0);
      FUN_800201ac(0xe7b,1);
    }
    *(undefined4 *)(iVar3 + 0xf4) = 1;
  }
  FUN_801d84c4(iVar8,2,0x1a7,0x64b,0xf0e,(int *)0xe5);
  FUN_801d8650(iVar8,1,-1,-1,0xe26,(int *)0xb8);
  FUN_801d84c4(iVar8,4,-1,-1,0xcbb,(int *)0xc4);
  uVar4 = FUN_80020078(0xe30);
  uVar4 = uVar4 & 0xff;
  uVar5 = FUN_80020078(0xe31);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_80020078(0xe32);
  uVar6 = uVar6 & 0xff;
  uVar7 = FUN_80020078(0xe33);
  uVar7 = uVar7 & 0xff;
  if (((((*(byte *)(iVar8 + 8) >> 1 & 1) == 0) && (uVar4 != 0)) && (uVar5 != 0)) &&
     ((uVar6 != 0 && (uVar7 != 0)))) {
    *(byte *)(iVar8 + 8) = *(byte *)(iVar8 + 8) & 0xfd | 2;
    FUN_800201ac(0xe9c,1);
    FUN_8000bb38(0,0x7e);
  }
  else {
    bVar1 = *(byte *)(iVar8 + 8);
    if (((uVar4 != (bVar1 >> 5 & 1)) || ((uVar5 != (bVar1 >> 4 & 1) || (uVar6 != (bVar1 >> 3 & 1))))
        ) || (uVar7 != (bVar1 >> 2 & 1))) {
      FUN_8000bb38(0,0x109);
    }
  }
  *(byte *)(iVar8 + 8) = (byte)(uVar4 << 5) & 0x20 | *(byte *)(iVar8 + 8) & 0xdf;
  *(byte *)(iVar8 + 8) = (byte)(uVar5 << 4) & 0x10 | *(byte *)(iVar8 + 8) & 0xef;
  *(byte *)(iVar8 + 8) = (byte)(uVar6 << 3) & 8 | *(byte *)(iVar8 + 8) & 0xf7;
  *(byte *)(iVar8 + 8) = (byte)(uVar7 << 2) & 4 | *(byte *)(iVar8 + 8) & 0xfb;
  uVar7 = FUN_80020078(0xe38);
  uVar4 = FUN_80020078(0xe3c);
  uVar4 = uVar4 & 0xff;
  uVar5 = FUN_80020078(0xe3d);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_80020078(0xe3e);
  uVar6 = uVar6 & 0xff;
  if (((((*(byte *)(iVar8 + 9) >> 4 & 1) == 0) && ((uVar7 & 0xff) != 0)) && (uVar4 != 0)) &&
     ((uVar5 != 0 && (uVar6 != 0)))) {
    *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) & 0xef | 0x10;
    FUN_8000bb38(0,0x7e);
  }
  else {
    if ((uVar7 & 0xff) == (*(byte *)(iVar8 + 8) & 1)) {
      bVar1 = *(byte *)(iVar8 + 9);
      if (((uVar4 == bVar1 >> 7) && (uVar5 == (bVar1 >> 6 & 1))) && (uVar6 == (bVar1 >> 5 & 1)))
      goto LAB_80221448;
    }
    FUN_8000bb38(0,0x109);
  }
LAB_80221448:
  *(byte *)(iVar8 + 8) = (byte)uVar7 & 1 | *(byte *)(iVar8 + 8) & 0xfe;
  *(byte *)(iVar8 + 9) = (byte)(uVar4 << 7) | *(byte *)(iVar8 + 9) & 0x7f;
  *(byte *)(iVar8 + 9) = (byte)(uVar5 << 6) & 0x40 | *(byte *)(iVar8 + 9) & 0xbf;
  *(byte *)(iVar8 + 9) = (byte)(uVar6 << 5) & 0x20 | *(byte *)(iVar8 + 9) & 0xdf;
  uVar4 = FUN_80020078(0x9e0);
  uVar4 = uVar4 & 0xff;
  uVar5 = FUN_80020078(0x9e1);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_80020078(0x9e2);
  uVar6 = uVar6 & 0xff;
  uVar7 = FUN_80020078(0x9e7);
  if ((((uVar4 == 0) || (uVar5 == 0)) || (uVar6 == 0)) || ((uVar7 & 0xff) == 0)) {
    bVar1 = *(byte *)(iVar8 + 9);
    if (((uVar4 != (bVar1 >> 3 & 1)) || (uVar5 != (bVar1 >> 2 & 1))) ||
       ((uVar6 != (bVar1 >> 1 & 1) || ((uVar7 & 0xff) != (bVar1 & 1))))) {
      *(float *)(iVar8 + 4) = FLOAT_803e7874;
    }
  }
  fVar2 = FLOAT_803e7870;
  if (FLOAT_803e7870 < *(float *)(iVar8 + 4)) {
    *(float *)(iVar8 + 4) = *(float *)(iVar8 + 4) - FLOAT_803dc074;
    if (*(float *)(iVar8 + 4) <= fVar2) {
      FUN_8000bb38(0,0x4bd);
    }
  }
  *(byte *)(iVar8 + 9) = (byte)(uVar4 << 3) & 8 | *(byte *)(iVar8 + 9) & 0xf7;
  *(byte *)(iVar8 + 9) = (byte)(uVar5 << 2) & 4 | *(byte *)(iVar8 + 9) & 0xfb;
  *(byte *)(iVar8 + 9) = (byte)(uVar6 << 1) & 2 | *(byte *)(iVar8 + 9) & 0xfd;
  *(byte *)(iVar8 + 9) = (byte)uVar7 & 1 | *(byte *)(iVar8 + 9) & 0xfe;
  if (*(char *)(iVar8 + 8) < '\0') {
    uVar4 = FUN_80020078(0x9f0);
    if ((uVar4 == 0) || (uVar4 = FUN_80020078(0x632), uVar4 != 0)) {
      (**(code **)(*DAT_803dd72c + 0x2c))();
      *(byte *)(iVar8 + 8) = *(byte *)(iVar8 + 8) & 0x7f;
    }
  }
  else {
    uVar4 = FUN_80020078(0x9f0);
    if ((uVar4 != 0) && (uVar4 = FUN_80020078(0x632), uVar4 == 0)) {
      local_28 = FLOAT_803e7878;
      local_24 = FLOAT_803e787c;
      local_20 = FLOAT_803e7880;
      (**(code **)(*DAT_803dd72c + 0x24))(&local_28,0x7fff,0,0);
      *(byte *)(iVar8 + 8) = *(byte *)(iVar8 + 8) & 0x7f | 0x80;
    }
  }
  FUN_8028688c();
  return;
}

