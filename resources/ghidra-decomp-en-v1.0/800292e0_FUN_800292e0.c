// Function: FUN_800292e0
// Entry: 800292e0
// Size: 136 bytes

void FUN_800292e0(void)

{
  short *psVar1;
  undefined auStack8 [8];
  
  DAT_803dcb54[4] = *DAT_803dcb54;
  while( true ) {
    psVar1 = (short *)DAT_803dcb54[4];
    if (psVar1 == (short *)DAT_803dcb54[1]) break;
    if (*psVar1 == -1) {
      FUN_800033a8(auStack8,0,*(undefined *)(DAT_803dcb54 + 3));
    }
    else {
      FUN_80003494(auStack8,psVar1 + 1,*(undefined *)(DAT_803dcb54 + 3));
    }
    DAT_803dcb54[4] = DAT_803dcb54[4] + (uint)*(byte *)((int)DAT_803dcb54 + 0xd) * 2;
  }
  return;
}

