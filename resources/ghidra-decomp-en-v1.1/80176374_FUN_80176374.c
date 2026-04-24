// Function: FUN_80176374
// Entry: 80176374
// Size: 240 bytes

void FUN_80176374(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = *(int *)(param_1 + 0xb8);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x411) {
    FUN_800201ac((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((sVar1 < 0x411) && (sVar1 == 0x21e)) {
    FUN_800201ac((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((((-1 < *(short *)(iVar3 + 0x18)) && (sVar1 != 0x54a)) && (sVar1 != 0x5ae)) &&
          ((sVar1 != 0x108 && (*(char *)(iVar2 + 0x146) != '\0')))) {
    FUN_800e85f4(param_1);
  }
  if ((*(ushort *)(iVar2 + 0x100) & 1) != 0) {
    iVar2 = DAT_803de738 * 4;
    DAT_803de738 = DAT_803de738 + 1;
    *(undefined4 *)(&DAT_803ad340 + iVar2) = *(undefined4 *)(iVar3 + 0x14);
  }
  FUN_8003709c(param_1,5);
  return;
}

