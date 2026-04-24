// Function: FUN_8001a234
// Entry: 8001a234
// Size: 492 bytes

void FUN_8001a234(void)

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
  iVar8 = -0x7fd37980;
  while( true ) {
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *(undefined2 *)(iVar8 + -0x18) = *(undefined2 *)(iVar8 + -0x1e);
    *(undefined2 *)(iVar8 + -0x16) = *(undefined2 *)(iVar8 + -0x1a);
    iVar8 = iVar8 + -0x20;
  }
  iVar8 = 8;
  puVar4 = &DAT_80339c40;
  puVar6 = (undefined4 *)0x80339a40;
  puVar7 = (undefined2 *)0x80339a20;
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
  iVar8 = -0x7fd37980;
  while( true ) {
    fVar2 = FLOAT_803de704;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *(undefined *)(iVar8 + -2) = 0xff;
    iVar8 = iVar8 + -0x20;
  }
  iVar8 = 4;
  puVar4 = (undefined4 *)&DAT_8033afe0;
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
  DAT_803dc9ec = &DAT_8033af90;
  DAT_803dc9e8 = 2;
  DAT_803dc9e4 = 0xffffffff;
  DAT_803dc9dc = 0xffffffff;
  DAT_803dc9cc = 0;
  DAT_803dc9e0 = 0xffffffff;
  DAT_803dc9d8 = 0xffffffff;
  DAT_803dc9bc = 0;
  DAT_803dc9a7 = 0xff;
  DAT_803dc9a6 = 0xff;
  DAT_803dc9a5 = 0xff;
  DAT_803dc9a4 = 0xff;
  DAT_803dc9c8 = 0;
  DAT_803dc9c4 = &DAT_80339d40;
  DAT_803dc97c = 0;
  DAT_803dc974 = &DAT_803399c0;
  DAT_803dc978 = *DAT_803399c8;
  DAT_803dc992 = 0;
  DAT_803dc991 = 0;
  DAT_803dc990 = 0;
  DAT_803dc98c = 5;
  DAT_803dc988 = 5;
  DAT_803dc984 = 1;
  DAT_803dc980 = 0;
  FUN_8001a918();
  DAT_803dc9dc = 3;
  DAT_803db378 = FUN_80022b50(0x800);
  return;
}

