// Function: FUN_80241e08
// Entry: 80241e08
// Size: 444 bytes

void FUN_80241e08(void)

{
  ushort uVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = FUN_80241de8();
  FUN_80003494(iVar3 - 0x80,0x81000000,0x80);
  FUN_80003494(0x81000000,0x8032d178,0x80);
  FUN_802420e0(0x81000000,0x80);
  DAT_cc005012 = 0x43;
  DAT_cc00500a = 0x8ac;
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 | 1;
  do {
    uVar1 = DAT_cc00500a;
  } while ((uVar1 & 1) != 0);
  DAT_cc005000 = 0;
  do {
    uVar1 = DAT_cc005004;
  } while ((uVar1 & 0x8000) != 0);
  Ramcc005020 = 0x1000000;
  Ramcc005024 = 0;
  Ramcc005028 = 0x20;
  uVar1 = DAT_cc00500a;
  while ((uVar1 & 0x20) == 0) {
    uVar1 = DAT_cc00500a;
  }
  DAT_cc00500a = uVar1;
  iVar3 = FUN_802473cc();
  do {
    iVar4 = FUN_802473cc();
  } while (iVar4 - iVar3 < 0x892);
  Ramcc005020 = 0x1000000;
  Ramcc005024 = 0;
  Ramcc005028 = 0x20;
  uVar1 = DAT_cc00500a;
  while ((uVar1 & 0x20) == 0) {
    uVar1 = DAT_cc00500a;
  }
  DAT_cc00500a = uVar1;
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 & 0xf7ff;
  do {
    uVar1 = DAT_cc00500a;
  } while ((uVar1 & 0x400) != 0);
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 & 0xfffb;
  uVar1 = DAT_cc005004;
  while ((uVar1 & 0x8000) == 0) {
    uVar1 = DAT_cc005004;
  }
  uVar1 = DAT_cc00500a;
  uVar2 = DAT_cc005006;
  DAT_cc00500a = uVar1 | 4;
  DAT_cc00500a = 0x8ac;
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 | 1;
  do {
    uVar1 = DAT_cc00500a;
  } while ((uVar1 & 1) != 0);
  iVar3 = FUN_80241de8();
  FUN_80003494(0x81000000,iVar3 - 0x80,0x80);
  return;
}

