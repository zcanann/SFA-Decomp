// Function: FUN_80218b24
// Entry: 80218b24
// Size: 164 bytes

undefined4 FUN_80218b24(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    if ((*(char *)(param_3 + iVar2 + 0x81) == '\x01') && (iVar1 = *(int *)(iVar3 + 4), iVar1 != -1))
    {
      (**(code **)(*DAT_803dca68 + 0x38))(iVar1,0x14,0x8c,0);
      *(undefined4 *)(iVar3 + 4) = 0xffffffff;
    }
  }
  return 0;
}

