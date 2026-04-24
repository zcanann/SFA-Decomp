// Function: FUN_8021f99c
// Entry: 8021f99c
// Size: 144 bytes

undefined4 FUN_8021f99c(int param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  int iVar2;
  
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    if ((*(char *)(param_3 + iVar2 + 0x81) == '\x01') &&
       (puVar1 = (undefined4 *)FUN_800395a4(param_1,0), puVar1 != (undefined4 *)0x0)) {
      *puVar1 = 0;
    }
  }
  return 0;
}

