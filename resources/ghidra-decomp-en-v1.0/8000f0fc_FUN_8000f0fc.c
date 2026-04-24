// Function: FUN_8000f0fc
// Entry: 8000f0fc
// Size: 732 bytes

void FUN_8000f0fc(undefined4 param_1)

{
  undefined2 uVar1;
  undefined2 uVar2;
  byte bVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  double dVar8;
  
  bVar3 = DAT_803dc88d;
  uVar7 = (uint)DAT_803dc88d;
  uVar6 = FUN_8006fed4();
  bVar4 = DAT_803dc88d;
  if ((*(uint *)(&DAT_802c5e30 + uVar7 * 0x34) & 1) == 0) {
    uVar7 = (uint)DAT_803dc88d;
    if ((*(uint *)(&DAT_802c5e30 + uVar7 * 0x34) & 1) == 0) {
      uVar1 = (undefined2)(((uVar6 & 0xffff) >> 1) << 2);
      (&DAT_802c5ed8)[uVar7 * 8] = uVar1;
      uVar2 = (undefined2)((uVar6 >> 0x11) << 2);
      (&DAT_802c5eda)[uVar7 * 8] = uVar2;
      (&DAT_802c5ed0)[uVar7 * 8] = uVar1;
      (&DAT_802c5ed2)[uVar7 * 8] = uVar2;
    }
    if (DAT_803dc890 == 1) {
      FUN_80247698((double)FLOAT_803dc8a0,(double)FLOAT_803dc89c,(double)FLOAT_803dc898,
                   (double)FLOAT_803dc894,(double)FLOAT_803db260,(double)FLOAT_803db264,
                   &DAT_80338750);
    }
    else {
      FUN_802475c8((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803db260,
                   (double)FLOAT_803db264,&DAT_80338750);
      FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803de628,
                   (double)FLOAT_803de628,(double)FLOAT_803de62c,(double)FLOAT_803de62c,
                   &DAT_80396850);
      dVar8 = (double)FLOAT_803de62c;
      FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar8,dVar8,dVar8,dVar8,
                   &DAT_803967f0);
      dVar8 = (double)FLOAT_803de62c;
      FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar8,(double)FLOAT_803de630,dVar8,
                   dVar8,&DAT_80396820);
    }
    FUN_8025cf48(&DAT_80338750,DAT_803dc890);
    FUN_8000f0b8(param_1);
  }
  else {
    iVar5 = (uint)bVar3 * 0x34;
    DAT_803dc88d = bVar3;
    FUN_800550d0(0,0,*(undefined4 *)(&DAT_802c5e20 + iVar5),*(undefined4 *)(&DAT_802c5e24 + iVar5),
                 *(undefined4 *)(&DAT_802c5e28 + iVar5),*(undefined4 *)(&DAT_802c5e2c + iVar5));
    uVar6 = (uint)DAT_803dc88d;
    if ((*(uint *)(&DAT_802c5e30 + uVar6 * 0x34) & 1) == 0) {
      (&DAT_802c5ed8)[uVar6 * 8] = 0;
      (&DAT_802c5eda)[uVar6 * 8] = 0;
      (&DAT_802c5ed0)[uVar6 * 8] = 0;
      (&DAT_802c5ed2)[uVar6 * 8] = 0;
    }
    DAT_803dc88d = bVar4;
    if (DAT_803dc890 == 1) {
      FUN_80247698((double)FLOAT_803dc8a0,(double)FLOAT_803dc89c,(double)FLOAT_803dc898,
                   (double)FLOAT_803dc894,(double)FLOAT_803db260,(double)FLOAT_803db264,
                   &DAT_80338750);
    }
    else {
      FUN_802475c8((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803db260,
                   (double)FLOAT_803db264,&DAT_80338750);
      FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803de628,
                   (double)FLOAT_803de628,(double)FLOAT_803de62c,(double)FLOAT_803de62c,
                   &DAT_80396850);
      dVar8 = (double)FLOAT_803de62c;
      FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar8,dVar8,dVar8,dVar8,
                   &DAT_803967f0);
      dVar8 = (double)FLOAT_803de62c;
      FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar8,(double)FLOAT_803de630,dVar8,
                   dVar8,&DAT_80396820);
    }
    FUN_8025cf48(&DAT_80338750,DAT_803dc890);
  }
  DAT_803dc88d = bVar3;
  return;
}

