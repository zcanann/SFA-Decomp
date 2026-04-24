// Function: FUN_8020d7ec
// Entry: 8020d7ec
// Size: 496 bytes

void FUN_8020d7ec(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  ushort uVar5;
  undefined4 uVar4;
  char *pcVar6;
  byte *pbVar7;
  undefined4 *puVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  
  iVar2 = FUN_802860d0();
  iVar11 = *(int *)(iVar2 + 0xb8);
  DAT_803ddd04 = 0;
  FUN_800200e8(0xa63,1);
  uVar10 = 0;
  iVar9 = 0;
  puVar8 = &DAT_8032a1b4;
  pcVar6 = &DAT_803dc1b8;
  do {
    iVar3 = FUN_8001ffb4(*puVar8);
    if (iVar3 != 0) {
      bVar1 = true;
      if ((*pcVar6 != '\0') && (uVar5 = FUN_800ea2bc(), 0xad < uVar5)) {
        bVar1 = false;
      }
      if (bVar1) {
        uVar10 = uVar10 | 1 << iVar9;
      }
    }
    puVar8 = puVar8 + 1;
    pcVar6 = pcVar6 + 1;
    iVar9 = iVar9 + 1;
  } while (iVar9 < 5);
  *(char *)(iVar11 + 0x11) = (char)uVar10;
  if (DAT_803dc1f0 == -1) {
    iVar9 = 0;
    pbVar7 = &DAT_803dc1c0;
    do {
      iVar3 = FUN_8001ffb4((&DAT_8032a1b4)[*pbVar7]);
      if (iVar3 != 0) {
        *(undefined *)(iVar11 + 0x10) = (&DAT_803dc1c0)[iVar9];
        break;
      }
      pbVar7 = pbVar7 + 1;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 5);
  }
  else {
    *(char *)(iVar11 + 0x10) = (char)DAT_803dc1f0;
  }
  DAT_803ddd08 = 0;
  FUN_8005cdf8(0);
  FUN_80009a94(0xf);
  FUN_8000a518(0x8f,1);
  FLOAT_803ddd2c = FLOAT_803e65f8;
  FUN_8012dd7c(1);
  DAT_803ddd28 = 0xffffffff;
  FUN_8004350c(0,0,1);
  FUN_800437bc(0x2d,0x10000000);
  uVar4 = FUN_800571e4();
  (**(code **)(*DAT_803dcaac + 0x1c))(iVar2 + 0xc,0,0,uVar4);
  (**(code **)(*DAT_803dca4c + 0xc))(0x1e,1);
  DAT_803ddd0a = 10;
  FUN_800200e8(DAT_8032a1bc,1);
  *(undefined2 *)(iVar11 + 6) = 0x78;
  FUN_800887f8(0);
  FUN_8028611c();
  return;
}

