// Function: FUN_8012b9f8
// Entry: 8012b9f8
// Size: 192 bytes

undefined4 FUN_8012b9f8(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  byte bVar4;
  
  iVar1 = FUN_8002bac4();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar3 = FUN_80296328(iVar1);
    uVar3 = countLeadingZeros(uVar3);
    if ((uVar3 >> 5 & 0xff) == 0) {
      if (*(int *)(iVar1 + 0x30) == 0) {
        uVar3 = FUN_8005b128();
        uVar3 = uVar3 & 0xff;
      }
      else {
        uVar3 = (uint)*(byte *)(*(int *)(iVar1 + 0x30) + 0xac);
      }
      for (bVar4 = 0; bVar4 < 9; bVar4 = bVar4 + 1) {
        if (uVar3 == (byte)s_B8CDEFGHI_8031bca0[bVar4]) {
          return 0;
        }
      }
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}

