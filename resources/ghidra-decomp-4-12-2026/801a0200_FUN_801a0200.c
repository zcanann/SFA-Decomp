// Function: FUN_801a0200
// Entry: 801a0200
// Size: 92 bytes

undefined4 FUN_801a0200(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0x74) == '\0') && (*(char *)(param_3 + 0x80) == '\x02'))
  {
    *(undefined *)(*(int *)(param_1 + 0xb8) + 0x74) = 1;
    iVar1 = FUN_8002bac4();
    FUN_80297184(iVar1,2);
  }
  return 0;
}

