// Function: FUN_80051fb8
// Entry: 80051fb8
// Size: 1048 bytes

void FUN_80051fb8(undefined4 param_1,undefined4 param_2,int param_3,undefined4 *param_4,uint param_5
                 ,uint param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [8];
  
  uVar3 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025bef8(DAT_803dcd90,0,1);
  iVar1 = (param_5 & 0xff) * 0xc;
  FUN_8025bf50(1,*(undefined4 *)(&DAT_8030cf04 + iVar1),*(undefined4 *)(&DAT_8030cf08 + iVar1),
               *(undefined4 *)(&DAT_8030cf0c + iVar1),3);
  if ((int)uVar3 == 0) {
    FUN_80257f10(DAT_803dcd88,1,DAT_803dcd78,0x3c,0,0x7d);
  }
  else {
    FUN_8025d160((int)uVar3,DAT_803dcd80,0);
    FUN_80257f10(DAT_803dcd88,1,DAT_803dcd78,0x3c,0,DAT_803dcd80);
    DAT_803dcd80 = DAT_803dcd80 + 3;
  }
  if ((param_6 & 0xff) == 0) {
    local_28 = *param_4;
    FUN_8025bdac(DAT_803dcd74,&local_28);
    FUN_8025be20(DAT_803dcd90,DAT_803dcd70);
    if (*(int *)(iVar2 + 0x50) == 0) {
      FUN_8025be8c(DAT_803dcd90,DAT_803dcd6c);
    }
    else {
      FUN_8025be8c(DAT_803dcd90 + 1,DAT_803dcd6c);
    }
    DAT_803dcd74 = DAT_803dcd74 + 1;
    DAT_803dcd70 = DAT_803dcd70 + 1;
    DAT_803dcd6c = DAT_803dcd6c + 1;
  }
  else {
    FUN_8004bf88(param_4,1,1,local_20,&local_24);
    FUN_8025be20(DAT_803dcd90,local_20[0]);
    if (*(int *)(iVar2 + 0x50) == 0) {
      FUN_8025be8c(DAT_803dcd90,local_24);
    }
    else {
      FUN_8025be8c(DAT_803dcd90 + 1,local_24);
    }
  }
  if (param_3 == 0) {
    FUN_8025ba40(DAT_803dcd90,0xf,8,0xe,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025ba40(DAT_803dcd90,0xf,8,4,6);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,8,0,1,0xf);
  }
  if (DAT_803dcd6b == '\0') {
    FUN_8025bac0(DAT_803dcd90,7,4,6,7);
  }
  else {
    FUN_8025bac0(DAT_803dcd90,7,4,0,7);
  }
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025a8f0(iVar2 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(iVar2 + 0x20,*(undefined4 *)(iVar2 + 0x40));
    }
    if (*(int *)(iVar2 + 0x50) != 0) {
      FUN_80053c40(iVar2,&DAT_803779a0);
      FUN_8025a8f0(&DAT_803779a0,1);
    }
  }
  if (*(int *)(iVar2 + 0x50) != 0) {
    DAT_803dcd6a = DAT_803dcd6a + '\x01';
    DAT_803dcd90 = DAT_803dcd90 + 1;
    DAT_803dcd8c = DAT_803dcd8c + 1;
    FUN_8025b71c();
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,0);
    FUN_8025bac0(DAT_803dcd90,7,4,6,7);
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
    FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  }
  DAT_803dcd6b = 1;
  DAT_803dcd78 = DAT_803dcd78 + 1;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  FUN_80286124();
  return;
}

