// Function: FUN_801504bc
// Entry: 801504bc
// Size: 60 bytes

void FUN_801504bc(int param_1,char param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0x33d) =
       param_2 + (&PTR_DAT_8031f170)[(uint)*(byte *)(iVar1 + 0x33b) * 10][8] + '\x01';
  *(undefined *)(iVar1 + 0x33e) = 1;
  return;
}

