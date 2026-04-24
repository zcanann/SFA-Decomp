// Function: FUN_801a6638
// Entry: 801a6638
// Size: 196 bytes

undefined4 FUN_801a6638(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = FUN_8002b9ec();
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 2) {
      FUN_80008cbc(param_1,uVar2,0x138,0);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      FUN_80008cbc(param_1,uVar2,0x13b,0);
    }
  }
  FUN_801a6778(param_1);
  return 0;
}

