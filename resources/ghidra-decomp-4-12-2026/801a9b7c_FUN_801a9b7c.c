// Function: FUN_801a9b7c
// Entry: 801a9b7c
// Size: 324 bytes

void FUN_801a9b7c(void)

{
  int iVar1;
  char *pcVar2;
  char in_r8;
  double dVar3;
  
  iVar1 = FUN_80286840();
  pcVar2 = *(char **)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    if (*pcVar2 == '\x02') {
      if ((pcVar2[1] & 2U) != 0) {
        *(short *)(pcVar2 + 0xc) = *(short *)(pcVar2 + 0xc) + 0x1000;
        dVar3 = (double)FUN_802945e0();
        FUN_8003b700((short)(int)(FLOAT_803e5270 * (float)((double)FLOAT_803e5274 + dVar3)) + 0x7fU
                     & 0xff,0xff,0xff);
      }
    }
    else if (*pcVar2 == '\x03') {
      if (*(short *)(pcVar2 + 0xc) < 32000) {
        *(short *)(pcVar2 + 0xc) = *(short *)(pcVar2 + 0xc) + 0xff;
      }
      FUN_8003b700(*(short *)(pcVar2 + 0xc) >> 7,0xff,0xff);
    }
    else {
      FUN_8003b700(0xff,0xff,0xff);
    }
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

