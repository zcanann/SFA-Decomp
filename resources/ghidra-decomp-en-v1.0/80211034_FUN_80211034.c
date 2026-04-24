// Function: FUN_80211034
// Entry: 80211034
// Size: 188 bytes

void FUN_80211034(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_80035f20();
  iVar1 = (int)*(short *)(param_2 + 0x1a) / 10 + ((int)*(short *)(param_2 + 0x1a) >> 0x1f);
  FUN_80035df4(param_1,0x1d,iVar1 - (iVar1 >> 0x1f),0);
  FUN_8008016c(iVar2 + 0xc);
  if ((*(short *)(param_2 + 0x1e) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    FUN_80080178(iVar2 + 0xc,0x708);
    FUN_80035f00(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  return;
}

