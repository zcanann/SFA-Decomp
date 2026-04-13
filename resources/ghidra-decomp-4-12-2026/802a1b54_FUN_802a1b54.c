// Function: FUN_802a1b54
// Entry: 802a1b54
// Size: 260 bytes

void FUN_802a1b54(uint param_1,int param_2)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    iVar2 = FUN_8005b128();
    if (iVar2 == 0x12) {
      FUN_8000bb38(param_1,0x211);
    }
    else {
      FUN_8000bb38(param_1,0x10);
    }
  }
  if ((0 < DAT_803df0fc) && (DAT_803df0fc = DAT_803df0fc - (uint)DAT_803dc070, DAT_803df0fc < 0)) {
    DAT_803df0fc = 0;
  }
  if ((((*(uint *)(param_2 + 0x314) & 0x80) != 0) && (DAT_803df0fc == 0)) &&
     (uVar3 = FUN_80022264(1,100), (int)uVar3 < 0x46)) {
    if (*(short *)(iVar4 + 0x81a) == 0) {
      uVar1 = 0x398;
    }
    else {
      uVar1 = 0x25;
    }
    FUN_8000bb38(param_1,uVar1);
    DAT_803df0fc = 0x3c;
  }
  return;
}

