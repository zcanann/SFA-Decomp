// Function: FUN_80037afc
// Entry: 80037afc
// Size: 100 bytes

bool FUN_80037afc(int param_1)

{
  int iVar1;
  byte bVar2;
  
  iVar1 = FUN_8002bac4();
  bVar2 = FUN_80296434(iVar1);
  if (bVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  return bVar2 == 0;
}

