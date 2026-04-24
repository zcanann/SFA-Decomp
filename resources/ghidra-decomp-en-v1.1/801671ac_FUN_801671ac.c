// Function: FUN_801671ac
// Entry: 801671ac
// Size: 312 bytes

void FUN_801671ac(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  double dVar3;
  float afStack_58 [12];
  float local_28;
  undefined4 local_24;
  float local_20;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(*(int *)(iVar1 + 0xb8) + 0x40c);
  if ((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if ((*(char *)(iVar2 + 0x90) == '\x06') && ((*(byte *)(iVar2 + 0x92) >> 3 & 1) != 0)) {
      if ((*(byte *)(iVar2 + 0x92) >> 2 & 1) == 0) {
        FUN_801672e4((float *)(iVar2 + 4),(float *)(iVar1 + 0x24),(float *)(iVar2 + 0x7c));
      }
      dVar3 = (double)*(float *)(iVar1 + 8);
      FUN_8002191c(dVar3,dVar3,dVar3,afStack_58);
      FUN_800223a8(afStack_58,(float *)(iVar2 + 4),afStack_58);
      local_28 = *(float *)(iVar1 + 0xc) - FLOAT_803dda58;
      local_24 = *(undefined4 *)(iVar1 + 0x10);
      local_20 = *(float *)(iVar1 + 0x14) - FLOAT_803dda5c;
      FUN_8003ba48(afStack_58);
      FUN_8003b9ec(iVar1);
      FUN_8003ba48(0);
    }
    else {
      FUN_8003b9ec(iVar1);
    }
  }
  FUN_80286888();
  return;
}

