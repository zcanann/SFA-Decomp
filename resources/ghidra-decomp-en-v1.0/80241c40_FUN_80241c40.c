// Function: FUN_80241c40
// Entry: 80241c40
// Size: 40 bytes

ulonglong FUN_80241c40(void)

{
  int iVar1;
  int iVar2;
  undefined4 in_HID2;
  
  iVar1 = -0x20000000;
  iVar2 = 0x200;
  do {
    dataCacheBlockInvalidate(iVar1);
    iVar1 = iVar1 + 0x20;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return CONCAT44(iVar1,in_HID2) & 0xffffffffefffffff;
}

