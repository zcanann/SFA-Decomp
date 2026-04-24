// Function: FUN_8005011c
// Entry: 8005011c
// Size: 1084 bytes

void FUN_8005011c(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int local_48;
  undefined auStack68 [64];
  
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025b71c(DAT_803dcd90 + 1);
  FUN_8025b71c(DAT_803dcd90 + 2);
  FUN_8025b71c(DAT_803dcd90 + 3);
  uVar1 = FUN_8000f558();
  FUN_80246eb4(param_1 + 0x30,uVar1,auStack68);
  FUN_8025d160(auStack68,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0x3c,0,DAT_803dcd80);
  uVar1 = FUN_8000f558();
  FUN_80246eb4(param_1,uVar1,auStack68);
  FUN_8025d160(auStack68,DAT_803dcd80 + 3,0);
  FUN_80257f10(DAT_803dcd88 + 1,0,0,0x3c,0,DAT_803dcd80 + 3);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025c0c4(DAT_803dcd90 + 1,DAT_803dcd88 + 1,DAT_803dcd8c + 1,0xff);
  FUN_8025c0c4(DAT_803dcd90 + 2,DAT_803dcd88 + 1,DAT_803dcd8c + 1,0xff);
  FUN_8025c0c4(DAT_803dcd90 + 3,DAT_803dcd88 + 1,DAT_803dcd8c + 1,0xff);
  FUN_8025be20(DAT_803dcd90 + 2,6);
  FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,8);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,1);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  FUN_8025ba40(DAT_803dcd90 + 1,2,8,0xc,0xf);
  FUN_8025bac0(DAT_803dcd90 + 1,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90 + 1,0,0);
  FUN_8025bb44(DAT_803dcd90 + 1,8,0,0,1,1);
  FUN_8025bc04(DAT_803dcd90 + 1,0,0,0,1,0);
  FUN_8025ba40(DAT_803dcd90 + 2,4,0xe,2,0xf);
  FUN_8025bac0(DAT_803dcd90 + 2,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90 + 2,0,0);
  FUN_8025bb44(DAT_803dcd90 + 2,0,0,0,1,2);
  FUN_8025bc04(DAT_803dcd90 + 2,0,0,0,1,0);
  FUN_8025ba40(DAT_803dcd90 + 3,6,0xf,2,0xf);
  FUN_8025bac0(DAT_803dcd90 + 3,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90 + 3,0,0);
  FUN_8025bb44(DAT_803dcd90 + 3,0,0,0,1,3);
  FUN_8025bc04(DAT_803dcd90 + 3,0,0,0,1,0);
  FUN_8006c5b8(&local_48);
  if (local_48 != 0) {
    if (*(char *)(local_48 + 0x48) == '\0') {
      FUN_8025a8f0(local_48 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(local_48 + 0x20,*(undefined4 *)(local_48 + 0x40));
    }
  }
  iVar2 = *(int *)(param_1 + 0x60);
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025a8f0(iVar2 + 0x20,DAT_803dcd8c + 1);
    }
    else {
      FUN_8025a748(iVar2 + 0x20,*(undefined4 *)(iVar2 + 0x40));
    }
  }
  DAT_803dcd69 = DAT_803dcd69 + '\x02';
  DAT_803dcd6a = DAT_803dcd6a + '\x04';
  DAT_803dcd80 = DAT_803dcd80 + 6;
  DAT_803dcd88 = DAT_803dcd88 + 2;
  DAT_803dcd8c = DAT_803dcd8c + 2;
  DAT_803dcd90 = DAT_803dcd90 + 4;
  return;
}

