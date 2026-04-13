// Function: FUN_802398bc
// Entry: 802398bc
// Size: 244 bytes

undefined4 FUN_802398bc(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = FUN_8002bac4();
  if ((iVar2 != 0) && (iVar2 = FUN_80296e2c(iVar2), iVar2 != 0)) {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
      if (bVar1 == 2) {
        FUN_8016de98(iVar2,5,(char)*(undefined4 *)(param_1 + 0xf8));
      }
      else if (bVar1 < 2) {
        if (bVar1 != 0) {
          FUN_8016de98(iVar2,5,1);
        }
      }
      else if (bVar1 < 4) {
        FUN_8016de98(iVar2,5,0);
      }
    }
  }
  return 0;
}

