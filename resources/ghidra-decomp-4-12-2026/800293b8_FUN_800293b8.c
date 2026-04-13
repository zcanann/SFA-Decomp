// Function: FUN_800293b8
// Entry: 800293b8
// Size: 136 bytes

void FUN_800293b8(void)

{
  short *psVar1;
  undefined auStack_8 [8];
  
  DAT_803dd7d4[4] = *DAT_803dd7d4;
  while( true ) {
    psVar1 = (short *)DAT_803dd7d4[4];
    if (psVar1 == (short *)DAT_803dd7d4[1]) break;
    if (*psVar1 == -1) {
      FUN_800033a8((int)auStack_8,0,(uint)*(byte *)(DAT_803dd7d4 + 3));
    }
    else {
      FUN_80003494((uint)auStack_8,(uint)(psVar1 + 1),(uint)*(byte *)(DAT_803dd7d4 + 3));
    }
    DAT_803dd7d4[4] = DAT_803dd7d4[4] + (uint)*(byte *)((int)DAT_803dd7d4 + 0xd) * 2;
  }
  return;
}

