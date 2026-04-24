// Function: FUN_802c136c
// Entry: 802c136c
// Size: 200 bytes

undefined4 FUN_802c136c(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 local_18 [2];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  local_18[0] = 1;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_3 + iVar1 + 0x81) == '\x01') {
      (**(code **)(*DAT_803dd71c + 0x8c))((double)FLOAT_803e90a8,iVar2 + 0x35c,param_1,local_18,0xf)
      ;
    }
  }
  *(byte *)(iVar2 + 0xbc1) = *(byte *)(iVar2 + 0xbc1) & 0x7f | 0x80;
  return 0;
}

