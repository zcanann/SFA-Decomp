// Function: FUN_80182b44
// Entry: 80182b44
// Size: 252 bytes

void FUN_80182b44(void)

{
  short sVar1;
  int iVar2;
  int iVar3;
  char in_r8;
  int iVar4;
  
  iVar2 = FUN_80286838();
  iVar4 = *(int *)(iVar2 + 0xb8);
  iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(*(int *)(iVar2 + 0x4c) + 0x14));
  if (iVar3 == 0) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
  }
  else {
    sVar1 = *(short *)(iVar4 + 10);
    if (((sVar1 == 0) || (0x32 < sVar1)) && (*(int *)(iVar4 + 0x14) == 0)) {
      if ((*(int *)(iVar2 + 0xf8) == 0) || (in_r8 == -1)) {
        FUN_8003b9ec(iVar2);
      }
      else {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      }
    }
    else {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
    }
  }
  FUN_80286884();
  return;
}

