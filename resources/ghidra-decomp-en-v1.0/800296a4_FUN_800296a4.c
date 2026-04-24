// Function: FUN_800296a4
// Entry: 800296a4
// Size: 192 bytes

void FUN_800296a4(void)

{
  int *piVar1;
  
  DAT_803dcb54 = FUN_80013d74(0x8c,4);
  DAT_803dcb50 = FUN_80013d74(0xc4,4);
  DAT_803dcb64 = FUN_80023cc8(0x830,10,0);
  DAT_803dcb60 = DAT_803dcb64 + 0x800;
  DAT_803dcb5c = DAT_803dcb64 + 0x810;
  piVar1 = (int *)FUN_800436e4(0x2a);
  if (piVar1 != (int *)0x0) {
    DAT_803dcb68 = 0;
    for (; *piVar1 != -1; piVar1 = piVar1 + 1) {
      DAT_803dcb68 = DAT_803dcb68 + 1;
    }
    DAT_803dcb68 = DAT_803dcb68 + -1;
    DAT_803dcb4c = FUN_800436e4(0x2f);
    if (DAT_803dcb4c != 0) {
      DAT_803dcb58 = 0;
    }
  }
  return;
}

