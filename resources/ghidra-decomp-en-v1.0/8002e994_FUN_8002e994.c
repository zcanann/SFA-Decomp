// Function: FUN_8002e994
// Entry: 8002e994
// Size: 448 bytes

void FUN_8002e994(void)

{
  int iVar1;
  short *psVar2;
  int *piVar3;
  
  DAT_803dcb98 = FUN_80023cc8(0x640,0xe,0);
  DAT_803dcb90 = FUN_80023cc8(0x60,0xe,0);
  DAT_803dcbc0 = FUN_80023cc8(0x10,0xe,0);
  FUN_8001f768(&DAT_803dcba0,0x3f);
  iVar1 = FUN_80048f10(0x3f);
  DAT_803dcb9c = (iVar1 >> 1) + -1;
  for (psVar2 = (short *)(DAT_803dcba0 + DAT_803dcb9c * 2); *psVar2 == 0; psVar2 = psVar2 + -1) {
    DAT_803dcb9c = DAT_803dcb9c + -1;
  }
  FUN_8001f768(&DAT_803dcbbc,0x3d);
  DAT_803dcbb8 = 0;
  for (piVar3 = DAT_803dcbbc; *piVar3 != -1; piVar3 = piVar3 + 1) {
    DAT_803dcbb8 = DAT_803dcbb8 + 1;
  }
  DAT_803dcbb8 = DAT_803dcbb8 + -1;
  DAT_803dcba8 = FUN_80023cc8(DAT_803dcbb8 * 4,0xe,0);
  DAT_803dcba4 = FUN_80023cc8(DAT_803dcbb8,0xe,0);
  for (iVar1 = 0; iVar1 < DAT_803dcbb8; iVar1 = iVar1 + 1) {
    *(undefined *)(DAT_803dcba4 + iVar1) = 0;
  }
  FUN_8001f768(&DAT_803dcbb4,0x16);
  FUN_8001f768(&DAT_803dcbb0,0x17);
  DAT_803dcbac = 0;
  for (piVar3 = DAT_803dcbb0; *piVar3 != -1; piVar3 = piVar3 + 1) {
    DAT_803dcbac = DAT_803dcbac + 1;
  }
  DAT_803dcb88 = FUN_80023cc8(0x960,0xe,0);
  FUN_80036b0c();
  DAT_803dcb94 = 0;
  DAT_803dcb8c = 0;
  DAT_803dcb70 = 0;
  DAT_803dcb84 = 0;
  FUN_80013b6c(&DAT_803dcb7c,0x38);
  DAT_803dcbc4 = 0;
  FUN_8003744c();
  FUN_800369f0();
  return;
}

