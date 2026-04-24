// Function: FUN_8015cb0c
// Entry: 8015cb0c
// Size: 196 bytes

void FUN_8015cb0c(undefined4 param_1,int param_2)

{
  char cVar2;
  int iVar1;
  
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    iVar1 = FUN_8002bdf4(0x24,100);
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_2 + 0x14);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_2 + 0x18);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_2 + 0x1c);
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    *(undefined2 *)(iVar1 + 0x1e) = 0xffff;
    *(undefined2 *)(iVar1 + 0x20) = 0xffff;
    iVar1 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (iVar1 != 0) {
      *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_2 + 0x38);
      *(undefined4 *)(iVar1 + 0x28) = *(undefined4 *)(param_2 + 0x3c);
      *(undefined4 *)(iVar1 + 0x2c) = *(undefined4 *)(param_2 + 0x40);
      *(undefined4 *)(iVar1 + 0xc4) = param_1;
    }
  }
  return;
}

