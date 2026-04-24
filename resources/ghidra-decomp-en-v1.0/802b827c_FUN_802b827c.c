// Function: FUN_802b827c
// Entry: 802b827c
// Size: 228 bytes

void FUN_802b827c(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  if ((*(char *)(param_3 + 0x2e) != '\0') && ((*(ushort *)(param_2 + 0x400) & 2) != 0)) {
    iVar2 = *(int *)(param_1 + 0x4c);
    if ((*(int *)(iVar2 + 0x14) == 0x46a51) && (iVar1 = FUN_8001ffb4(0xc49), iVar1 == 0)) {
      FUN_800200e8(0xc49,1);
    }
    else if ((*(int *)(iVar2 + 0x14) == 0x46a55) && (iVar1 = FUN_8001ffb4(0xc4a), iVar1 == 0)) {
      FUN_800200e8(0xc4a,1);
    }
    else if ((*(int *)(iVar2 + 0x14) == 0x49928) && (iVar2 = FUN_8001ffb4(0xc4b), iVar2 == 0)) {
      FUN_800200e8(0xc4b,1);
    }
    *(undefined *)(param_3 + 0x2e) = 0;
  }
  return;
}

