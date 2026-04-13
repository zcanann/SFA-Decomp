// Function: FUN_80241fc4
// Entry: 80241fc4
// Size: 216 bytes

void FUN_80241fc4(void)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  
  DAT_cc00500a = 0x804;
  uVar1 = DAT_cc005036;
  DAT_cc005036 = uVar1 & 0x7fff;
  uVar1 = DAT_cc00500a;
  while ((uVar1 & 0x400) != 0) {
    uVar1 = DAT_cc00500a;
  }
  uVar1 = DAT_cc00500a;
  while ((uVar1 & 0x200) != 0) {
    uVar1 = DAT_cc00500a;
  }
  DAT_cc00500a = 0x8ac;
  DAT_cc005000 = 0;
  do {
    uVar1 = DAT_cc005004;
  } while ((uVar1 & 0x8000) != 0);
  iVar2 = FUN_802473cc();
  do {
    iVar3 = FUN_802473cc();
  } while (iVar3 - iVar2 < 0x2c);
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 | 1;
  uVar1 = DAT_cc00500a;
  while ((uVar1 & 1) != 0) {
    uVar1 = DAT_cc00500a;
  }
  return;
}

