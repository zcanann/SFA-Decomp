// Function: FUN_8019fc84
// Entry: 8019fc84
// Size: 92 bytes

undefined4 FUN_8019fc84(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0x74) == '\0') && (*(char *)(param_3 + 0x80) == '\x02'))
  {
    *(undefined *)(*(int *)(param_1 + 0xb8) + 0x74) = 1;
    uVar1 = FUN_8002b9ec();
    FUN_80296a24(uVar1,2);
  }
  return 0;
}

