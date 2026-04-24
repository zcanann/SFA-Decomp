// Function: FUN_80093ae0
// Entry: 80093ae0
// Size: 724 bytes

void FUN_80093ae0(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  char cVar5;
  undefined4 uVar4;
  undefined uVar6;
  undefined uVar7;
  undefined uVar8;
  uint uVar9;
  uint uVar10;
  undefined4 *puVar11;
  undefined2 *puVar12;
  double dVar13;
  undefined4 local_38;
  float local_34;
  longlong local_30;
  
  FUN_802860cc();
  iVar3 = (**(code **)(*DAT_803dca58 + 0x24))(&local_34);
  cVar5 = FUN_8005ce90();
  if (cVar5 == '\0') {
    uVar9 = 0;
    uVar10 = 0xff;
    iVar3 = 1;
  }
  else {
    if (iVar3 == 0) {
      if ((FLOAT_803df288 < local_34) || (FLOAT_803df28c == local_34)) goto LAB_80093d9c;
      uVar10 = (uint)-(FLOAT_803df284 * (local_34 / FLOAT_803df288) - FLOAT_803df284);
      local_30 = (longlong)(int)uVar10;
    }
    else if (local_34 <= FLOAT_803df280) {
      uVar10 = (uint)(FLOAT_803df284 * (local_34 / FLOAT_803df280));
      local_30 = (longlong)(int)uVar10;
    }
    else {
      uVar10 = 0xff;
    }
    uVar9 = 0x4c;
    iVar3 = 2;
  }
  FUN_80258b24(0);
  FUN_8000fb00();
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_800799c0();
  FUN_800790ac();
  FUN_80079804();
  FUN_800789ac();
  local_38 = DAT_803db778;
  dVar13 = (double)FLOAT_803df28c;
  FUN_8025c2d4(dVar13,dVar13,dVar13,dVar13,0,&local_38);
  FUN_8000f564();
  uVar4 = FUN_8000f534();
  FUN_8025d0a8(uVar4,0);
  FUN_8025d124(0);
  puVar12 = &DAT_8039a900 + uVar9;
  puVar11 = &DAT_8039a9b8 + uVar9;
  for (; (int)uVar9 < 0x5c; uVar9 = uVar9 + 1) {
    iVar1 = (uVar9 & 3) * 6;
    uVar6 = FUN_800221a0((&DAT_8030f770)[iVar1],(&DAT_8030f771)[iVar1]);
    uVar7 = FUN_800221a0((&DAT_8030f772)[iVar1],(&DAT_8030f773)[iVar1]);
    uVar8 = FUN_800221a0((&DAT_8030f774)[iVar1],(&DAT_8030f775)[iVar1]);
    uVar2 = uVar10;
    if ((int)uVar9 < 0x4c) {
      iVar1 = ((int)(uVar9 & 0xc) >> 2) * 2;
      iVar1 = FUN_800221a0((&DAT_803db770)[iVar1],*(undefined *)(iVar1 + -0x7fc2488f));
      uVar2 = (int)(uVar10 * iVar1) >> 8;
    }
    FUN_800799e4(uVar6,uVar7,uVar8,uVar2 & 0xff);
    if (uVar9 == 0x4c) {
      FUN_8004c2e4(DAT_803dd1d0,0);
      FUN_800799c0();
      FUN_800795e8();
      FUN_80079804();
    }
    else if (uVar9 == 0x54) {
      FUN_8004c2e4(DAT_803dd1d4,0);
    }
    if ((int)uVar9 < 0x4c) {
      uVar6 = FUN_800221a0(0xc,0xc);
      FUN_80258a6c(uVar6,5);
    }
    else if ((uVar9 & 4) == 0) {
      iVar1 = FUN_800221a0(0x48,0x60);
      FUN_80258a6c(iVar1 / iVar3 & 0xff,5);
    }
    else {
      iVar1 = FUN_800221a0(0x30,0x3c);
      FUN_80258a6c(iVar1 / iVar3 & 0xff,5);
    }
    FUN_8025ced8(*puVar11,*puVar12);
    puVar12 = puVar12 + 1;
    puVar11 = puVar11 + 1;
  }
LAB_80093d9c:
  FUN_80286118();
  return;
}

