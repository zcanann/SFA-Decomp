// Function: FUN_80245218
// Entry: 80245218
// Size: 48 bytes

uint FUN_80245218(void)

{
  uint uVar1;
  
  if (DAT_800030e2 == '\0') {
    uVar1 = DAT_cc003024;
    uVar1 = uVar1 >> 3;
  }
  else {
    uVar1 = 0x80000000;
  }
  return uVar1;
}

