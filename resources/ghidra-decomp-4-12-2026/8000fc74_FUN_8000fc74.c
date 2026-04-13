// Function: FUN_8000fc74
// Entry: 8000fc74
// Size: 568 bytes

/* WARNING: Removing unreachable block (ram,0x8000fdc0) */

void FUN_8000fc74(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  
  fVar4 = FLOAT_803df2d0;
  fVar3 = FLOAT_803df290;
  fVar2 = FLOAT_803df28c;
  uVar5 = 0;
  iVar6 = 4;
  do {
    uVar1 = uVar5 & 0xff;
    (&DAT_80338e34)[uVar1 * 0x30] = 0;
    (&DAT_80338e32)[uVar1 * 0x30] = 0;
    (&DAT_80338e30)[uVar1 * 0x30] = 0x7ff8;
    (&DAT_80338e3c)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e40)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e44)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e50)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e54)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e58)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e5c)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e70)[uVar1 * 0x18] = 0;
    (&DAT_80338e8a)[uVar1 * 0x30] = 0;
    (&DAT_80338e48)[uVar1 * 0x18] = fVar3;
    uVar1 = uVar5 + 1 & 0xff;
    (&DAT_80338e34)[uVar1 * 0x30] = 0;
    (&DAT_80338e32)[uVar1 * 0x30] = 0;
    (&DAT_80338e30)[uVar1 * 0x30] = 0x7ff8;
    (&DAT_80338e3c)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e40)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e44)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e50)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e54)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e58)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e5c)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e70)[uVar1 * 0x18] = 0;
    (&DAT_80338e8a)[uVar1 * 0x30] = 0;
    (&DAT_80338e48)[uVar1 * 0x18] = fVar3;
    uVar1 = uVar5 + 2 & 0xff;
    (&DAT_80338e34)[uVar1 * 0x30] = 0;
    (&DAT_80338e32)[uVar1 * 0x30] = 0;
    (&DAT_80338e30)[uVar1 * 0x30] = 0x7ff8;
    (&DAT_80338e3c)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e40)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e44)[uVar1 * 0x18] = fVar4;
    (&DAT_80338e50)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e54)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e58)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e5c)[uVar1 * 0x18] = fVar2;
    (&DAT_80338e70)[uVar1 * 0x18] = 0;
    (&DAT_80338e8a)[uVar1 * 0x30] = 0;
    (&DAT_80338e48)[uVar1 * 0x18] = fVar3;
    uVar5 = uVar5 + 3;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  DAT_803dd50d = 0;
  DAT_803dd50c = 0;
  DAT_803dd508 = 0;
  DAT_803dd504 = 0;
  DAT_803dd506 = 0;
  FLOAT_803dbec4 = FLOAT_803df2cc;
  DAT_803dd500 = 0;
  FLOAT_803dd524 = FLOAT_803df290;
  DAT_803dd510 = 0;
  FUN_80247d2c((double)FLOAT_803df290,(double)FLOAT_803dbec8,(double)FLOAT_803dbec0,
               (double)FLOAT_803df2cc,(float *)&DAT_803393b0);
  FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803df2a8,
               (double)FLOAT_803df2a8,(double)FLOAT_803df2ac,(double)FLOAT_803df2ac,
               (float *)&DAT_803974b0);
  dVar7 = (double)FLOAT_803df2ac;
  FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar7,dVar7,dVar7,dVar7,
               (float *)&DAT_80397450);
  dVar7 = (double)FLOAT_803df2ac;
  FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar7,(double)FLOAT_803df2b0,dVar7,
               dVar7,(float *)&DAT_80397480);
  FUN_8025d6ac(&DAT_803393b0,DAT_803dd510);
  FUN_80070088((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803dbec0,
               (double)FLOAT_803dbec4,(double)FLOAT_803df270,(float *)&DAT_80338d70,
               (short *)&DAT_803dd50a);
  FUN_80022324((undefined4 *)&DAT_80338d70,(undefined4 *)&DAT_80338cb0);
  return;
}

