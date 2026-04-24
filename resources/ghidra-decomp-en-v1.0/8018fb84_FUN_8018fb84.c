// Function: FUN_8018fb84
// Entry: 8018fb84
// Size: 124 bytes

undefined4 FUN_8018fb84(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  
  for (bVar1 = 0; bVar1 < *(byte *)(param_3 + 0x8b); bVar1 = bVar1 + 1) {
    if (*(char *)(param_3 + bVar1 + 0x81) == '\x01') {
      FUN_8018f2d8(param_1);
    }
  }
  return 0;
}

