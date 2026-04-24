// Function: FUN_8002977c
// Entry: 8002977c
// Size: 192 bytes

void FUN_8002977c(void)

{
  int *piVar1;
  
  DAT_803dd7d4 = FUN_80013d94(0x8c,4);
  DAT_803dd7d0 = FUN_80013d94(0xc4,4);
  DAT_803dd7e4 = FUN_80023d8c(0x830,10);
  DAT_803dd7e0 = DAT_803dd7e4 + 0x800;
  DAT_803dd7dc = DAT_803dd7e4 + 0x810;
  piVar1 = (int *)FUN_80043860(0x2a);
  if (piVar1 != (int *)0x0) {
    DAT_803dd7e8 = 0;
    for (; *piVar1 != -1; piVar1 = piVar1 + 1) {
      DAT_803dd7e8 = DAT_803dd7e8 + 1;
    }
    DAT_803dd7e8 = DAT_803dd7e8 + -1;
    DAT_803dd7cc = FUN_80043860(0x2f);
    if (DAT_803dd7cc != (undefined *)0x0) {
      DAT_803dd7d8 = 0;
    }
  }
  return;
}

