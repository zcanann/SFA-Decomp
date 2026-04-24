// Function: FUN_80228874
// Entry: 80228874
// Size: 136 bytes

void FUN_80228874(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar1 = FUN_80286840();
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
      puVar2 = (undefined4 *)FUN_800395a4(iVar1,0);
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0x100;
      }
      *(undefined4 *)(iVar1 + 0xf4) = 1;
    }
  }
  FUN_8028688c();
  return;
}

