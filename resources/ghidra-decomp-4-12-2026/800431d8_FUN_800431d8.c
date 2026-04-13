// Function: FUN_800431d8
// Entry: 800431d8
// Size: 1068 bytes

uint FUN_800431d8(void)

{
  uint uVar1;
  
  FUN_80243e74();
  FUN_80243e74();
  uVar1 = DAT_803dd900;
  FUN_80243e9c();
  if ((((DAT_803dd914 & 4) != 0) && ((uVar1 & 4) == 0)) && (DAT_8035fc54 == -1)) {
    FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
  }
  if ((((DAT_803dd914 & 8) != 0) && ((uVar1 & 8) == 0)) && (DAT_8035fcc0 == -1)) {
    FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
  }
  if ((((DAT_803dd914 & 0x40) != 0) && ((uVar1 & 0x40) == 0)) && (DAT_8035fc68 == -1)) {
    FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
  }
  if ((((DAT_803dd914 & 0x80) != 0) && ((uVar1 & 0x80) == 0)) && (DAT_8035fcd0 == -1)) {
    FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
  }
  if ((((DAT_803dd914 & 0x400) != 0) && ((uVar1 & 0x400) == 0)) && (DAT_8035fc34 == -1)) {
    FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
  }
  if ((((DAT_803dd914 & 0x800) != 0) && ((uVar1 & 0x800) == 0)) && (DAT_8035fcdc == -1)) {
    FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
  }
  if ((((DAT_803dd914 & 0x4000) != 0) && ((uVar1 & 0x4000) == 0)) && (DAT_8035fc28 == -1)) {
    FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
  }
  if ((((DAT_803dd914 & 0x8000) != 0) && ((uVar1 & 0x8000) == 0)) && (DAT_8035fcd4 == -1)) {
    FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
  }
  if ((((DAT_803dd914 & 0x20000) != 0) && ((uVar1 & 0x20000) == 0)) && (DAT_8035fc3c == -1)) {
    FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
  }
  if ((((DAT_803dd914 & 0x80000) != 0) && ((uVar1 & 0x80000) == 0)) && (DAT_8035fcc4 == -1)) {
    FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
  }
  if ((((DAT_803dd914 & 0x2000000) != 0) && ((uVar1 & 0x2000000) == 0)) && (DAT_8035fc14 == -1)) {
    FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
  }
  if ((((DAT_803dd914 & 0x8000000) != 0) && ((uVar1 & 0x8000000) == 0)) && (DAT_8035fcf8 == -1)) {
    FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
  }
  if ((((DAT_803dd914 & 0x20000000) != 0) && ((uVar1 & 0x20000000) == 0)) && (DAT_8035fbdc == -1)) {
    FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
  }
  if ((((DAT_803dd914 & 0x80000000) != 0) && ((uVar1 & 0x80000000) == 0)) && (DAT_8035fcfc == -1)) {
    FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
  }
  DAT_803dd914 = uVar1;
  DAT_803dd900 = DAT_803dd900 ^ DAT_803dd904;
  DAT_803dd904 = 0;
  FUN_80243e9c();
  return DAT_803dd900;
}

