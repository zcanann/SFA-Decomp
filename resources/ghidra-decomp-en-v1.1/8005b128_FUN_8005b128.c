// Function: FUN_8005b128
// Entry: 8005b128
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x8005b208) */
/* WARNING: Removing unreachable block (ram,0x8005b138) */

int FUN_8005b128(void)

{
  int iVar1;
  int iVar2;
  double dVar3;
  
  dVar3 = (double)FUN_802925a0();
  iVar2 = (int)(dVar3 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000) -
                                       DOUBLE_803df840));
  dVar3 = (double)FUN_802925a0();
  iVar1 = (int)(dVar3 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000) -
                                       DOUBLE_803df840));
  if ((iVar2 < 0) || (0xf < iVar2)) {
    iVar2 = -1;
  }
  else if ((iVar1 < 0) || (0xf < iVar1)) {
    iVar2 = -1;
  }
  else {
    iVar2 = (int)*(short *)(DAT_80382f00 + (iVar2 + iVar1 * 0x10) * 0xc);
  }
  return iVar2;
}

