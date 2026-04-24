// Function: FUN_8001a26c
// Entry: 8001a26c
// Size: 492 bytes

void FUN_8001a26c(void)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined2 *puVar7;
  int iVar8;
  
  iVar3 = 0x94;
  iVar8 = -0x7fd37200;
  while( true ) {
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *(undefined2 *)(iVar8 + -0x18) = *(undefined2 *)(iVar8 + -0x1e);
    *(undefined2 *)(iVar8 + -0x16) = *(undefined2 *)(iVar8 + -0x1a);
    iVar8 = iVar8 + -0x20;
  }
  iVar8 = 8;
  puVar4 = &DAT_8033a8a0;
  puVar6 = (undefined4 *)0x8033a6a0;
  puVar7 = (undefined2 *)0x8033a680;
  while( true ) {
    puVar4 = puVar4 + -0x10;
    puVar6 = puVar6 + -1;
    bVar1 = iVar8 == 0;
    iVar8 = iVar8 + -1;
    if (bVar1) break;
    *puVar6 = puVar4;
    puVar7[-6] = 0xffff;
    puVar7[-5] = 1;
    *(undefined *)(puVar7 + -4) = 0xff;
    *(undefined *)((int)puVar7 + -7) = 0;
    *(undefined *)(puVar7 + -3) = 0;
    *(undefined *)((int)puVar7 + -5) = 0;
    *(undefined4 **)(puVar7 + -2) = puVar6;
    puVar7 = puVar7 + -6;
  }
  iVar3 = 0x94;
  iVar8 = -0x7fd37200;
  while( true ) {
    fVar2 = FLOAT_803df384;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *(undefined *)(iVar8 + -2) = 0xff;
    iVar8 = iVar8 + -0x20;
  }
  iVar8 = 4;
  puVar4 = (undefined4 *)&DAT_8033bc40;
  while( true ) {
    puVar6 = puVar4 + -10;
    bVar1 = iVar8 == 0;
    iVar8 = iVar8 + -1;
    if (bVar1) break;
    puVar4[-8] = 0;
    puVar4[-7] = 0;
    *puVar6 = 0;
    puVar4[-9] = 0;
    puVar4[-3] = 0;
    puVar4[-2] = fVar2;
    *(undefined *)(puVar4 + -1) = 0xff;
    *(undefined *)((int)puVar4 + -3) = 6;
    iVar3 = 3;
    puVar5 = puVar4 + -7;
    while( true ) {
      bVar1 = iVar3 == 0;
      iVar3 = iVar3 + -1;
      puVar4 = puVar6;
      if (bVar1) break;
      puVar5[3] = 0;
      puVar5 = puVar5 + -1;
    }
  }
  DAT_803dd66c = &DAT_8033bbf0;
  DAT_803dd668 = 2;
  DAT_803dd664 = 0xffffffff;
  DAT_803dd65c = 0xffffffff;
  DAT_803dd64c = 0;
  DAT_803dd660 = 0xffffffff;
  DAT_803dd658 = 0xffffffff;
  DAT_803dd63c = 0;
  DAT_803dd627 = 0xff;
  DAT_803dd626 = 0xff;
  DAT_803dd625 = 0xff;
  DAT_803dd624 = 0xff;
  DAT_803dd648 = 0;
  DAT_803dd644 = &DAT_8033a9a0;
  DAT_803dd5fc = 0;
  DAT_803dd5f4 = &DAT_8033a620;
  DAT_803dd5f8 = *DAT_8033a628;
  DAT_803dd612 = 0;
  DAT_803dd611 = 0;
  DAT_803dd610 = 0;
  DAT_803dd60c = 5;
  DAT_803dd608 = 5;
  DAT_803dd604 = 1;
  DAT_803dd600 = 0;
  FUN_8001a950();
  DAT_803dd65c = 3;
  DAT_803dbfd8 = FUN_80022c14(0x800);
  return;
}

