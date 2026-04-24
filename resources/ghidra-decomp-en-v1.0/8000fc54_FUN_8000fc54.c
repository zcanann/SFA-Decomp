// Function: FUN_8000fc54
// Entry: 8000fc54
// Size: 568 bytes

/* WARNING: Removing unreachable block (ram,0x8000fda0) */

void FUN_8000fc54(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  
  fVar4 = FLOAT_803de650;
  fVar3 = FLOAT_803de610;
  fVar2 = FLOAT_803de60c;
  uVar5 = 0;
  iVar6 = 4;
  do {
    uVar1 = uVar5 & 0xff;
    (&DAT_803381d4)[uVar1 * 0x30] = 0;
    (&DAT_803381d2)[uVar1 * 0x30] = 0;
    (&DAT_803381d0)[uVar1 * 0x30] = 0x7ff8;
    (&DAT_803381dc)[uVar1 * 0x18] = fVar4;
    (&DAT_803381e0)[uVar1 * 0x18] = fVar4;
    (&DAT_803381e4)[uVar1 * 0x18] = fVar4;
    (&DAT_803381f0)[uVar1 * 0x18] = fVar2;
    (&DAT_803381f4)[uVar1 * 0x18] = fVar2;
    (&DAT_803381f8)[uVar1 * 0x18] = fVar2;
    (&DAT_803381fc)[uVar1 * 0x18] = fVar2;
    (&DAT_80338210)[uVar1 * 0x18] = 0;
    (&DAT_8033822a)[uVar1 * 0x30] = 0;
    (&DAT_803381e8)[uVar1 * 0x18] = fVar3;
    uVar1 = uVar5 + 1 & 0xff;
    (&DAT_803381d4)[uVar1 * 0x30] = 0;
    (&DAT_803381d2)[uVar1 * 0x30] = 0;
    (&DAT_803381d0)[uVar1 * 0x30] = 0x7ff8;
    (&DAT_803381dc)[uVar1 * 0x18] = fVar4;
    (&DAT_803381e0)[uVar1 * 0x18] = fVar4;
    (&DAT_803381e4)[uVar1 * 0x18] = fVar4;
    (&DAT_803381f0)[uVar1 * 0x18] = fVar2;
    (&DAT_803381f4)[uVar1 * 0x18] = fVar2;
    (&DAT_803381f8)[uVar1 * 0x18] = fVar2;
    (&DAT_803381fc)[uVar1 * 0x18] = fVar2;
    (&DAT_80338210)[uVar1 * 0x18] = 0;
    (&DAT_8033822a)[uVar1 * 0x30] = 0;
    (&DAT_803381e8)[uVar1 * 0x18] = fVar3;
    uVar1 = uVar5 + 2 & 0xff;
    (&DAT_803381d4)[uVar1 * 0x30] = 0;
    (&DAT_803381d2)[uVar1 * 0x30] = 0;
    (&DAT_803381d0)[uVar1 * 0x30] = 0x7ff8;
    (&DAT_803381dc)[uVar1 * 0x18] = fVar4;
    (&DAT_803381e0)[uVar1 * 0x18] = fVar4;
    (&DAT_803381e4)[uVar1 * 0x18] = fVar4;
    (&DAT_803381f0)[uVar1 * 0x18] = fVar2;
    (&DAT_803381f4)[uVar1 * 0x18] = fVar2;
    (&DAT_803381f8)[uVar1 * 0x18] = fVar2;
    (&DAT_803381fc)[uVar1 * 0x18] = fVar2;
    (&DAT_80338210)[uVar1 * 0x18] = 0;
    (&DAT_8033822a)[uVar1 * 0x30] = 0;
    (&DAT_803381e8)[uVar1 * 0x18] = fVar3;
    uVar5 = uVar5 + 3;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  DAT_803dc88d = 0;
  DAT_803dc88c = 0;
  DAT_803dc888 = 0;
  DAT_803dc884 = 0;
  DAT_803dc886 = 0;
  FLOAT_803db264 = FLOAT_803de64c;
  DAT_803dc880 = 0;
  FLOAT_803dc8a4 = FLOAT_803de610;
  DAT_803dc890 = 0;
  FUN_802475c8((double)FLOAT_803de610,(double)FLOAT_803db268,(double)FLOAT_803db260,
               (double)FLOAT_803de64c,&DAT_80338750);
  FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803de628,
               (double)FLOAT_803de628,(double)FLOAT_803de62c,(double)FLOAT_803de62c,&DAT_80396850);
  dVar7 = (double)FLOAT_803de62c;
  FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar7,dVar7,dVar7,dVar7,&DAT_803967f0);
  dVar7 = (double)FLOAT_803de62c;
  FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar7,(double)FLOAT_803de630,dVar7,
               dVar7,&DAT_80396820);
  FUN_8025cf48(&DAT_80338750,DAT_803dc890);
  FUN_8006ff0c((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803db260,
               (double)FLOAT_803db264,(double)FLOAT_803de5f0,&DAT_80338110,&DAT_803dc88a);
  FUN_80022260(&DAT_80338110,&DAT_80338050);
  return;
}

