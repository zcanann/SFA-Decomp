// Function: FUN_80172fc8
// Entry: 80172fc8
// Size: 260 bytes

void FUN_80172fc8(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((((in_r8 != '\0') && (*(float *)(iVar2 + 8) == FLOAT_803e40f4)) &&
      (*(int *)(iVar1 + 0xf4) == 0)) &&
     ((*(short *)(iVar1 + 0x46) == 0x156 || (*(char *)(iVar2 + 0x1e) == '\0')))) {
    if (((*(uint *)(*(int *)(iVar1 + 0x50) + 0x44) & 0x10000) != 0) &&
       (*(char *)(iVar2 + 0x36) != '\0')) {
      FUN_8003b700((ushort)*(byte *)(iVar2 + 0x38),(ushort)*(byte *)(iVar2 + 0x39),
                   (ushort)*(byte *)(iVar2 + 0x3a));
    }
    FUN_8003b9ec(iVar1);
    if (*(short *)(iVar1 + 0x46) == 0xa8) {
      FUN_80097568((double)FLOAT_803e40ec,(double)FLOAT_803e4124,iVar1,7,5,1,10,0,0x20000000);
    }
  }
  FUN_8028688c();
  return;
}

