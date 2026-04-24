// Function: FUN_8003f5ac
// Entry: 8003f5ac
// Size: 584 bytes

void FUN_8003f5ac(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  bool bVar5;
  char cVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d8();
  iVar2 = (int)uVar7;
  if ((*(char *)((int)((ulonglong)uVar7 >> 0x20) + 0x37) == -1) &&
     ((*(uint *)(param_3 + 0x3c) & 0x40000000) == 0)) {
    if ((*(uint *)(param_3 + 0x3c) & 0x400) == 0) {
      cVar6 = '\0';
      bVar4 = (*(ushort *)(iVar2 + 2) & 0x400) == 0;
      cVar3 = '\x01';
      iVar2 = 0;
      bVar5 = bVar4;
    }
    else {
      cVar6 = '\0';
      bVar4 = (*(ushort *)(iVar2 + 2) & 0x400) == 0;
      cVar3 = '\0';
      iVar2 = 0x40;
      bVar5 = bVar4;
    }
  }
  else {
    cVar6 = '\x01';
    if ((*(ushort *)(iVar2 + 2) & 0x400) == 0) {
      if ((*(ushort *)(iVar2 + 2) & 0x2000) == 0) {
        bVar4 = false;
        cVar3 = '\x01';
        iVar2 = 0;
        bVar5 = true;
      }
      else {
        bVar4 = true;
        cVar3 = '\0';
        iVar2 = 0xdf;
        bVar5 = true;
      }
    }
    else {
      bVar4 = false;
      cVar3 = '\x01';
      iVar2 = 0;
      bVar5 = false;
    }
  }
  bVar1 = (*(uint *)(param_3 + 0x3c) & 8) != 0;
  if (DAT_803db478 != cVar6) {
    if (cVar6 == '\0') {
      FUN_8025c584(0,1,0,5);
      DAT_803db478 = cVar6;
    }
    else {
      FUN_8025c584(1,4,5,5);
      DAT_803db478 = cVar6;
    }
  }
  if (((bool)DAT_803db480 != bVar5) || ((bool)DAT_803db481 != bVar4)) {
    FUN_80070310(bVar5,3,bVar4);
    DAT_803db480 = bVar5;
    DAT_803db481 = bVar4;
  }
  if (DAT_803db479 != cVar3) {
    FUN_800702b8(cVar3);
    DAT_803db479 = cVar3;
  }
  if (DAT_803db47c != iVar2) {
    DAT_803db47c = iVar2;
    if (iVar2 == 0) {
      FUN_8025bff0(7,0,0,7,0);
    }
    else {
      FUN_8025bff0(4,iVar2,0,4,iVar2);
    }
  }
  if (bVar1 != (bool)DAT_803db482) {
    DAT_803db482 = bVar1;
    if (bVar1) {
      FUN_80258b24(2);
    }
    else {
      FUN_80258b24(0);
    }
  }
  FUN_80286124();
  return;
}

