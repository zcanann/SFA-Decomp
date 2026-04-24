// Function: FUN_802281cc
// Entry: 802281cc
// Size: 136 bytes

void FUN_802281cc(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar1 = FUN_802860dc();
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
      puVar2 = (undefined4 *)FUN_800394ac(iVar1,0,0);
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0x100;
      }
      *(undefined4 *)(iVar1 + 0xf4) = 1;
    }
  }
  FUN_80286128(0);
  return;
}

