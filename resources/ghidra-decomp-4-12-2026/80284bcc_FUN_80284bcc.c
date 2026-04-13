// Function: FUN_80284bcc
// Entry: 80284bcc
// Size: 236 bytes

int FUN_80284bcc(uint param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  iVar1 = DAT_803df004;
  uVar3 = param_2 + 0x1fU & 0xffffffe0;
  if (DAT_803df00c == (code *)0x0) {
    FUN_802420e0(param_1,uVar3);
    FUN_8028479c(param_1,DAT_803df004,uVar3,0,0,0);
    DAT_803df004 = DAT_803df004 + uVar3;
  }
  else {
    for (; uVar3 != 0; uVar3 = uVar3 - uVar4) {
      uVar4 = uVar3;
      if (DAT_803df010 <= uVar3) {
        uVar4 = DAT_803df010;
      }
      uVar2 = (*DAT_803df00c)(param_1,uVar4);
      FUN_802420e0(uVar2,uVar4);
      FUN_8028479c(uVar2,DAT_803df004,uVar4,0,0,0);
      param_1 = param_1 + uVar4;
      DAT_803df004 = DAT_803df004 + uVar4;
    }
  }
  return iVar1;
}

