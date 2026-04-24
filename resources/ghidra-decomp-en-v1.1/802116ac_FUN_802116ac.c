// Function: FUN_802116ac
// Entry: 802116ac
// Size: 188 bytes

void FUN_802116ac(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_80036018(param_1);
  iVar1 = (int)*(short *)(param_2 + 0x1a) / 10 + ((int)*(short *)(param_2 + 0x1a) >> 0x1f);
  FUN_80035eec(param_1,0x1d,(char)iVar1 - (char)(iVar1 >> 0x1f),0);
  FUN_800803f8((undefined4 *)(iVar3 + 0xc));
  if (((int)*(short *)(param_2 + 0x1e) != 0xffffffff) &&
     (uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1e)), uVar2 != 0)) {
    FUN_80080404((float *)(iVar3 + 0xc),0x708);
    FUN_80035ff8(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  return;
}

