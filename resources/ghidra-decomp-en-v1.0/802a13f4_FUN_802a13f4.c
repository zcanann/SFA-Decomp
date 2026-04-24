// Function: FUN_802a13f4
// Entry: 802a13f4
// Size: 260 bytes

void FUN_802a13f4(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    iVar2 = FUN_8005afac((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x14));
    if (iVar2 == 0x12) {
      FUN_8000bb18(param_1,0x211);
    }
    else {
      FUN_8000bb18(param_1,0x10);
    }
  }
  if ((0 < DAT_803de47c) && (DAT_803de47c = DAT_803de47c - (uint)DAT_803db410, DAT_803de47c < 0)) {
    DAT_803de47c = 0;
  }
  if ((((*(uint *)(param_2 + 0x314) & 0x80) != 0) && (DAT_803de47c == 0)) &&
     (iVar2 = FUN_800221a0(1,100), iVar2 < 0x46)) {
    if (*(short *)(iVar3 + 0x81a) == 0) {
      uVar1 = 0x398;
    }
    else {
      uVar1 = 0x25;
    }
    FUN_8000bb18(param_1,uVar1);
    DAT_803de47c = 0x3c;
  }
  return;
}

