// Function: FUN_80054db0
// Entry: 80054db0
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x80054df8) */
/* WARNING: Removing unreachable block (ram,0x80054e44) */

void FUN_80054db0(void)

{
  int *piVar1;
  int iVar2;
  
  DAT_803dcdc4 = FUN_80023cc8(0x2bc0,6,0);
  iVar2 = 0;
  DAT_803dcdbc = 0;
  DAT_8037e0b4 = (int *)FUN_800436e4(0x24);
  for (piVar1 = DAT_8037e0b4; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_8037e0a8 = iVar2 + -1;
  iVar2 = 0;
  DAT_8037e0b8 = (int *)FUN_800436e4(0x21);
  for (piVar1 = DAT_8037e0b8; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_8037e0ac = iVar2 + -1;
  iVar2 = 0;
  DAT_8037e0bc = (int *)FUN_800436e4(0x50);
  for (piVar1 = DAT_8037e0bc; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_8037e0b0 = iVar2 + -1;
  FUN_8001f768(&DAT_803dcdc0,0x22);
  iVar2 = 0;
  for (piVar1 = DAT_8037e0b4; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_8037e0a8 = iVar2 + -1;
  iVar2 = 0;
  for (piVar1 = DAT_8037e0b8; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_8037e0ac = iVar2 + -1;
  DAT_803dcdb8 = FUN_80023cc8(0x120,6,0);
  FUN_800544a4(0,0);
  return;
}

