// Function: FUN_80241b3c
// Entry: 80241b3c
// Size: 204 bytes

ulonglong FUN_80241b3c(void)

{
  int iVar1;
  int iVar2;
  undefined4 in_HID2;
  
  iVar1 = -0x80000000;
  iVar2 = 0x400;
  do {
    dataCacheBlockTouch(iVar1);
    dataCacheBlockStore(iVar1);
    iVar1 = iVar1 + 0x20;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  instructionSynchronize();
  iVar1 = -0x20000000;
  iVar2 = 0x200;
  do {
    dataCacheBlockSetToZeroLocked(iVar1);
    iVar1 = iVar1 + 0x20;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return CONCAT44(iVar1,in_HID2) | 0x100f0000;
}

