// Function: FUN_8028e2ac
// Entry: 8028e2ac
// Size: 152 bytes

void FUN_8028e2ac(void)

{
  int *piVar1;
  int *piVar2;
  
  piVar1 = (int *)&DAT_80332fe0;
  while( true ) {
    piVar2 = piVar1;
    if (piVar2 == (int *)0x0) break;
    if ((*(ushort *)(piVar2 + 1) >> 6 & 7) != 0) {
      FUN_8028f4b8(piVar2);
    }
    piVar1 = (int *)piVar2[0x13];
    if (*(char *)(piVar2 + 3) == '\0') {
      *(ushort *)(piVar2 + 1) = *(ushort *)(piVar2 + 1) & 0xfe3f | 0xc0;
      if ((piVar1 != (int *)0x0) && (*(char *)(piVar1 + 3) != '\0')) {
        piVar2[0x13] = 0;
      }
    }
    else {
      FUN_8028dcd4(piVar2);
    }
  }
  return;
}

