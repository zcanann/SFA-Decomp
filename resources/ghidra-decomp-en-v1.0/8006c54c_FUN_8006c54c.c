// Function: FUN_8006c54c
// Entry: 8006c54c
// Size: 108 bytes

int FUN_8006c54c(void)

{
  int iVar1;
  
  iVar1 = FUN_80054c98(0x200,0x200,1,0,0,0,0,0,0);
  *(undefined2 *)(iVar1 + 0xe) = 1;
  FUN_802419e8(iVar1 + 0x60,*(undefined4 *)(iVar1 + 0x44));
  return iVar1;
}

