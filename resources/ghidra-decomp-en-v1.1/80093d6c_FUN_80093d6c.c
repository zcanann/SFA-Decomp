// Function: FUN_80093d6c
// Entry: 80093d6c
// Size: 724 bytes

void FUN_80093d6c(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  undefined4 *puVar10;
  ushort *puVar11;
  double dVar12;
  uint3 local_38;
  float local_34;
  longlong local_30;
  
  FUN_80286830();
  iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(&local_34);
  uVar3 = FUN_8005d00c();
  if ((uVar3 & 0xff) == 0) {
    uVar3 = 0;
    iVar2 = 0xff;
    iVar9 = 1;
  }
  else {
    if (iVar2 == 0) {
      if ((FLOAT_803dff08 < local_34) || (FLOAT_803dff0c == local_34)) goto LAB_80094028;
      iVar2 = (int)-(FLOAT_803dff04 * (local_34 / FLOAT_803dff08) - FLOAT_803dff04);
      local_30 = (longlong)iVar2;
    }
    else if (local_34 <= FLOAT_803dff00) {
      iVar2 = (int)(FLOAT_803dff04 * (local_34 / FLOAT_803dff00));
      local_30 = (longlong)iVar2;
    }
    else {
      iVar2 = 0xff;
    }
    uVar3 = 0x4c;
    iVar9 = 2;
  }
  FUN_80259288(0);
  FUN_8000fb20();
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80079b3c();
  FUN_80079228();
  FUN_80079980();
  FUN_80078b28();
  _local_38 = DAT_803dc3d8;
  dVar12 = (double)FLOAT_803dff0c;
  FUN_8025ca38(dVar12,dVar12,dVar12,dVar12,0,&local_38);
  FUN_8000f584();
  pfVar4 = (float *)FUN_8000f554();
  FUN_8025d80c(pfVar4,0);
  FUN_8025d888(0);
  puVar11 = &DAT_8039b560 + uVar3;
  puVar10 = &DAT_8039b618 + uVar3;
  for (; (int)uVar3 < 0x5c; uVar3 = uVar3 + 1) {
    iVar1 = (uVar3 & 3) * 6;
    uVar5 = FUN_80022264((uint)(byte)(&DAT_80310330)[iVar1],(uint)(byte)(&DAT_80310331)[iVar1]);
    uVar6 = FUN_80022264((uint)(byte)(&DAT_80310332)[iVar1],(uint)(byte)(&DAT_80310333)[iVar1]);
    uVar7 = FUN_80022264((uint)(byte)(&DAT_80310334)[iVar1],(uint)(byte)(&DAT_80310335)[iVar1]);
    iVar1 = iVar2;
    if ((int)uVar3 < 0x4c) {
      iVar1 = ((int)(uVar3 & 0xc) >> 2) * 2;
      uVar8 = FUN_80022264((uint)(byte)(&DAT_803dc3d0)[iVar1],(uint)*(byte *)(iVar1 + -0x7fc23c2f));
      iVar1 = (int)(iVar2 * uVar8) >> 8;
    }
    FUN_80079b60((char)uVar5,(char)uVar6,(char)uVar7,(char)iVar1);
    if (uVar3 == 0x4c) {
      FUN_8004c460(DAT_803dde50,0);
      FUN_80079b3c();
      FUN_80079764();
      FUN_80079980();
    }
    else if (uVar3 == 0x54) {
      FUN_8004c460(DAT_803dde54,0);
    }
    if ((int)uVar3 < 0x4c) {
      uVar5 = FUN_80022264(0xc,0xc);
      FUN_802591d0(uVar5 & 0xff,5);
    }
    else if ((uVar3 & 4) == 0) {
      uVar5 = FUN_80022264(0x48,0x60);
      FUN_802591d0((int)uVar5 / iVar9 & 0xff,5);
    }
    else {
      uVar5 = FUN_80022264(0x30,0x3c);
      FUN_802591d0((int)uVar5 / iVar9 & 0xff,5);
    }
    FUN_8025d63c(*puVar10,(uint)*puVar11);
    puVar11 = puVar11 + 1;
    puVar10 = puVar10 + 1;
  }
LAB_80094028:
  FUN_8028687c();
  return;
}

