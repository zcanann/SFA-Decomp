// Function: FUN_8012b6bc
// Entry: 8012b6bc
// Size: 192 bytes

undefined4 FUN_8012b6bc(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  char cVar4;
  byte bVar5;
  
  iVar2 = FUN_8002b9ec();
  if (iVar2 == 0) {
    uVar3 = 0;
  }
  else {
    uVar3 = FUN_80295bc8();
    uVar1 = countLeadingZeros(uVar3);
    if ((uVar1 >> 5 & 0xff) == 0) {
      if (*(int *)(iVar2 + 0x30) == 0) {
        cVar4 = FUN_8005afac((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x14));
      }
      else {
        cVar4 = *(char *)(*(int *)(iVar2 + 0x30) + 0xac);
      }
      for (bVar5 = 0; bVar5 < 9; bVar5 = bVar5 + 1) {
        if (cVar4 == s_B8CDEFGHI_8031b050[bVar5]) {
          return 0;
        }
      }
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

