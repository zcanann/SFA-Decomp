// Function: FUN_80284468
// Entry: 80284468
// Size: 236 bytes

int FUN_80284468(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  
  iVar1 = DAT_803de384;
  uVar3 = param_2 + 0x1fU & 0xffffffe0;
  if (DAT_803de38c == (code *)0x0) {
    FUN_802419e8(param_1,uVar3);
    FUN_80284038(param_1,DAT_803de384,uVar3,0,0,0);
    DAT_803de384 = DAT_803de384 + uVar3;
  }
  else {
    for (; uVar3 != 0; uVar3 = uVar3 - uVar4) {
      uVar4 = uVar3;
      if (DAT_803de390 <= uVar3) {
        uVar4 = DAT_803de390;
      }
      uVar2 = (*DAT_803de38c)(param_1,uVar4);
      FUN_802419e8(uVar2,uVar4);
      FUN_80284038(uVar2,DAT_803de384,uVar4,0,0,0);
      param_1 = param_1 + uVar4;
      DAT_803de384 = DAT_803de384 + uVar4;
    }
  }
  return iVar1;
}

