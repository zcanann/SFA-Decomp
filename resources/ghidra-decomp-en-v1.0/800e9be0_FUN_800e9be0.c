// Function: FUN_800e9be0
// Entry: 800e9be0
// Size: 184 bytes

void FUN_800e9be0(void)

{
  uint uVar1;
  int iVar2;
  
  DAT_803dd494 = 0xff;
  DAT_803dd48c = 0xffffffff;
  FUN_8004350c(0,0,1);
  FUN_800033a8(&DAT_803a3994,0,0x884);
  FUN_8002070c();
  FUN_80009a94(7);
  FUN_80014a28();
  FUN_8011f394();
  uVar1 = (uint)DAT_803a32c8;
  FUN_80020770((double)(float)(&DAT_803a392c)[uVar1 * 4],(double)(float)(&DAT_803a3930)[uVar1 * 4],
               (double)(float)(&DAT_803a3934)[uVar1 * 4],(int)(char)(&DAT_803a3939)[uVar1 * 0x10]);
  iVar2 = FUN_80014940();
  if (iVar2 != 4) {
    FUN_80014948(1);
  }
  FUN_800d7b04(0x1e,1);
  DAT_803dd488 = 2;
  return;
}

