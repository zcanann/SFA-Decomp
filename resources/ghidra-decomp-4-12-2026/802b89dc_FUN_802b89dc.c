// Function: FUN_802b89dc
// Entry: 802b89dc
// Size: 228 bytes

void FUN_802b89dc(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  if ((*(char *)(param_3 + 0x2e) != '\0') && ((*(ushort *)(param_2 + 0x400) & 2) != 0)) {
    iVar2 = *(int *)(param_1 + 0x4c);
    if ((*(int *)(iVar2 + 0x14) == 0x46a51) && (uVar1 = FUN_80020078(0xc49), uVar1 == 0)) {
      FUN_800201ac(0xc49,1);
    }
    else if ((*(int *)(iVar2 + 0x14) == 0x46a55) && (uVar1 = FUN_80020078(0xc4a), uVar1 == 0)) {
      FUN_800201ac(0xc4a,1);
    }
    else if ((*(int *)(iVar2 + 0x14) == 0x49928) && (uVar1 = FUN_80020078(0xc4b), uVar1 == 0)) {
      FUN_800201ac(0xc4b,1);
    }
    *(undefined *)(param_3 + 0x2e) = 0;
  }
  return;
}

