// Function: FUN_80175ec8
// Entry: 80175ec8
// Size: 240 bytes

void FUN_80175ec8(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = *(int *)(param_1 + 0xb8);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x411) {
    FUN_800200e8((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((sVar1 < 0x411) && (sVar1 == 0x21e)) {
    FUN_800200e8((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((((-1 < *(short *)(iVar3 + 0x18)) && (sVar1 != 0x54a)) && (sVar1 != 0x5ae)) &&
          ((sVar1 != 0x108 && (*(char *)(iVar2 + 0x146) != '\0')))) {
    FUN_800e8370(param_1);
  }
  if ((*(ushort *)(iVar2 + 0x100) & 1) != 0) {
    iVar2 = DAT_803ddab8 * 4;
    DAT_803ddab8 = DAT_803ddab8 + 1;
    *(undefined4 *)(&DAT_803ac6e0 + iVar2) = *(undefined4 *)(iVar3 + 0x14);
  }
  FUN_80036fa4(param_1,5);
  return;
}

