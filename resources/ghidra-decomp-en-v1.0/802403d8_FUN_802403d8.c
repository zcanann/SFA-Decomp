// Function: FUN_802403d8
// Entry: 802403d8
// Size: 40 bytes

int FUN_802403d8(void)

{
  int iVar1;
  
  if ((DAT_803dddd8 == 0) || (iVar1 = *(int *)(DAT_803dddd8 + 0x2c), iVar1 == 0)) {
    iVar1 = 0x10000002;
  }
  return iVar1;
}

