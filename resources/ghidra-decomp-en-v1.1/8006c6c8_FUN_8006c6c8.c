// Function: FUN_8006c6c8
// Entry: 8006c6c8
// Size: 108 bytes

int FUN_8006c6c8(void)

{
  int iVar1;
  
  iVar1 = FUN_80054e14(0x200,0x200,1,'\0',0,0,0,0,0);
  *(undefined2 *)(iVar1 + 0xe) = 1;
  FUN_802420e0(iVar1 + 0x60,*(int *)(iVar1 + 0x44));
  return iVar1;
}

