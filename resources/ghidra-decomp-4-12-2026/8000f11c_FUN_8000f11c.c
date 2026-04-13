// Function: FUN_8000f11c
// Entry: 8000f11c
// Size: 732 bytes

void FUN_8000f11c(void)

{
  undefined2 uVar1;
  undefined2 uVar2;
  byte bVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  double dVar8;
  
  bVar3 = DAT_803dd50d;
  uVar7 = (uint)DAT_803dd50d;
  uVar6 = FUN_80070050();
  bVar4 = DAT_803dd50d;
  if ((*(uint *)(&DAT_802c65b0 + uVar7 * 0x34) & 1) == 0) {
    uVar7 = (uint)DAT_803dd50d;
    if ((*(uint *)(&DAT_802c65b0 + uVar7 * 0x34) & 1) == 0) {
      uVar1 = (undefined2)(((uVar6 & 0xffff) >> 1) << 2);
      (&DAT_802c6658)[uVar7 * 8] = uVar1;
      uVar2 = (undefined2)((uVar6 >> 0x11) << 2);
      (&DAT_802c665a)[uVar7 * 8] = uVar2;
      (&DAT_802c6650)[uVar7 * 8] = uVar1;
      (&DAT_802c6652)[uVar7 * 8] = uVar2;
    }
    if (DAT_803dd510 == 1) {
      FUN_80247dfc((double)FLOAT_803dd520,(double)FLOAT_803dd51c,(double)FLOAT_803dd518,
                   (double)FLOAT_803dd514,(double)FLOAT_803dbec0,(double)FLOAT_803dbec4,
                   (float *)&DAT_803393b0);
    }
    else {
      FUN_80247d2c((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803dbec0,
                   (double)FLOAT_803dbec4,(float *)&DAT_803393b0);
      FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803df2a8,
                   (double)FLOAT_803df2a8,(double)FLOAT_803df2ac,(double)FLOAT_803df2ac,
                   (float *)&DAT_803974b0);
      dVar8 = (double)FLOAT_803df2ac;
      FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar8,dVar8,dVar8,dVar8,
                   (float *)&DAT_80397450);
      dVar8 = (double)FLOAT_803df2ac;
      FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar8,(double)FLOAT_803df2b0,dVar8,
                   dVar8,(float *)&DAT_80397480);
    }
    FUN_8025d6ac(&DAT_803393b0,DAT_803dd510);
    FUN_8000f0d8();
  }
  else {
    iVar5 = (uint)bVar3 * 0x34;
    DAT_803dd50d = bVar3;
    FUN_8005524c(0,0,*(int *)(&DAT_802c65a0 + iVar5),*(int *)(&DAT_802c65a4 + iVar5),
                 *(int *)(&DAT_802c65a8 + iVar5),*(int *)(&DAT_802c65ac + iVar5));
    uVar6 = (uint)DAT_803dd50d;
    if ((*(uint *)(&DAT_802c65b0 + uVar6 * 0x34) & 1) == 0) {
      (&DAT_802c6658)[uVar6 * 8] = 0;
      (&DAT_802c665a)[uVar6 * 8] = 0;
      (&DAT_802c6650)[uVar6 * 8] = 0;
      (&DAT_802c6652)[uVar6 * 8] = 0;
    }
    DAT_803dd50d = bVar4;
    if (DAT_803dd510 == 1) {
      FUN_80247dfc((double)FLOAT_803dd520,(double)FLOAT_803dd51c,(double)FLOAT_803dd518,
                   (double)FLOAT_803dd514,(double)FLOAT_803dbec0,(double)FLOAT_803dbec4,
                   (float *)&DAT_803393b0);
    }
    else {
      FUN_80247d2c((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803dbec0,
                   (double)FLOAT_803dbec4,(float *)&DAT_803393b0);
      FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803df2a8,
                   (double)FLOAT_803df2a8,(double)FLOAT_803df2ac,(double)FLOAT_803df2ac,
                   (float *)&DAT_803974b0);
      dVar8 = (double)FLOAT_803df2ac;
      FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar8,dVar8,dVar8,dVar8,
                   (float *)&DAT_80397450);
      dVar8 = (double)FLOAT_803df2ac;
      FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar8,(double)FLOAT_803df2b0,dVar8,
                   dVar8,(float *)&DAT_80397480);
    }
    FUN_8025d6ac(&DAT_803393b0,DAT_803dd510);
  }
  DAT_803dd50d = bVar3;
  return;
}

