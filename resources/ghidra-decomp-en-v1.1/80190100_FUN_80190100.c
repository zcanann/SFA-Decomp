// Function: FUN_80190100
// Entry: 80190100
// Size: 124 bytes

undefined4 FUN_80190100(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  
  for (bVar1 = 0; bVar1 < *(byte *)(param_3 + 0x8b); bVar1 = bVar1 + 1) {
    if (*(char *)(param_3 + bVar1 + 0x81) == '\x01') {
      FUN_8018f854();
    }
  }
  return 0;
}

