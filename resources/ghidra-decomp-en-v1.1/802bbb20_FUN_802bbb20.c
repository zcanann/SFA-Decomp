// Function: FUN_802bbb20
// Entry: 802bbb20
// Size: 240 bytes

void FUN_802bbb20(void)

{
  int iVar1;
  char in_r8;
  int iVar2;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (in_r8 == -1) {
    FUN_8003b9ec(iVar1);
    FUN_80038524(iVar1,1,(float *)(iVar2 + 0x9e8),(undefined4 *)(iVar2 + 0x9ec),
                 (float *)(iVar2 + 0x9f0),0);
    FUN_80038378(iVar1,2,4,(float *)(iVar2 + 0x9b0));
  }
  if ((*(char *)(iVar2 + 0xa8a) != '\x02') && (in_r8 != '\0')) {
    FUN_8003b9ec(iVar1);
    FUN_80038524(iVar1,1,(float *)(iVar2 + 0x9e8),(undefined4 *)(iVar2 + 0x9ec),
                 (float *)(iVar2 + 0x9f0),0);
    FUN_80038378(iVar1,2,4,(float *)(iVar2 + 0x9b0));
  }
  FUN_80286884();
  return;
}

