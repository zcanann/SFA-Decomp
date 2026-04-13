// Function: FUN_8003f6a4
// Entry: 8003f6a4
// Size: 584 bytes

void FUN_8003f6a4(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char cVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  iVar2 = (int)uVar8;
  if ((*(char *)((int)((ulonglong)uVar8 >> 0x20) + 0x37) == -1) &&
     ((*(uint *)(param_3 + 0x3c) & 0x40000000) == 0)) {
    if ((*(uint *)(param_3 + 0x3c) & 0x400) == 0) {
      cVar7 = '\0';
      bVar1 = (*(ushort *)(iVar2 + 2) & 0x400) == 0;
      uVar6 = (uint)bVar1;
      uVar5 = (uint)bVar1;
      uVar4 = 1;
      uVar3 = 0;
    }
    else {
      cVar7 = '\0';
      bVar1 = (*(ushort *)(iVar2 + 2) & 0x400) == 0;
      uVar6 = (uint)bVar1;
      uVar5 = (uint)bVar1;
      uVar4 = 0;
      uVar3 = 0x40;
    }
  }
  else {
    cVar7 = '\x01';
    if ((*(ushort *)(iVar2 + 2) & 0x400) == 0) {
      if ((*(ushort *)(iVar2 + 2) & 0x2000) == 0) {
        uVar6 = 1;
        uVar5 = 0;
        uVar4 = 1;
        uVar3 = 0;
      }
      else {
        uVar6 = 1;
        uVar5 = 1;
        uVar4 = 0;
        uVar3 = 0xdf;
      }
    }
    else {
      uVar6 = 0;
      uVar5 = 0;
      uVar4 = 1;
      uVar3 = 0;
    }
  }
  bVar1 = (*(uint *)(param_3 + 0x3c) & 8) != 0;
  if (DAT_803dc0d8 != cVar7) {
    if (cVar7 == '\0') {
      FUN_8025cce8(0,1,0,5);
      DAT_803dc0d8 = cVar7;
    }
    else {
      FUN_8025cce8(1,4,5,5);
      DAT_803dc0d8 = cVar7;
    }
  }
  if ((DAT_803dc0e0 != uVar6) || (DAT_803dc0e1 != uVar5)) {
    FUN_8007048c(uVar6,3,uVar5);
    DAT_803dc0e0 = (byte)uVar6;
    DAT_803dc0e1 = (byte)uVar5;
  }
  if (DAT_803dc0d9 != uVar4) {
    FUN_80070434(uVar4);
    DAT_803dc0d9 = (byte)uVar4;
  }
  if (DAT_803dc0dc != uVar3) {
    DAT_803dc0dc = uVar3;
    if (uVar3 == 0) {
      FUN_8025c754(7,0,0,7,0);
    }
    else {
      FUN_8025c754(4,uVar3,0,4,uVar3);
    }
  }
  if (bVar1 != (bool)DAT_803dc0e2) {
    DAT_803dc0e2 = bVar1;
    if (bVar1) {
      FUN_80259288(2);
    }
    else {
      FUN_80259288(0);
    }
  }
  FUN_80286888();
  return;
}

