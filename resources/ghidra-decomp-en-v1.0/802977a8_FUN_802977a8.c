// Function: FUN_802977a8
// Entry: 802977a8
// Size: 124 bytes

undefined4 FUN_802977a8(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0xe,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e7f08;
  if (*(char *)(param_2 + 0x346) == '\0') {
    uVar1 = 0;
  }
  else {
    *(undefined4 *)(param_2 + 0x308) = 0;
    uVar1 = 0x41;
  }
  return uVar1;
}

