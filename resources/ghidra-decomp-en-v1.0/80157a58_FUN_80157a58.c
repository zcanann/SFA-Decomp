// Function: FUN_80157a58
// Entry: 80157a58
// Size: 256 bytes

void FUN_80157a58(undefined4 param_1)

{
  char cVar2;
  int iVar1;
  
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    iVar1 = FUN_8002bdf4(0x24,0x710);
    FUN_8003842c(param_1,0,iVar1 + 8,iVar1 + 0xc,iVar1 + 0x10,0);
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 4;
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    *(undefined *)(iVar1 + 0x18) = 0;
    *(undefined *)(iVar1 + 0x19) = 0;
    *(undefined2 *)(iVar1 + 0x1a) = 0;
    *(undefined2 *)(iVar1 + 0x1c) = 10;
    *(undefined2 *)(iVar1 + 0x1e) = 0;
    *(undefined2 *)(iVar1 + 0x20) = 0;
    *(undefined *)(iVar1 + 0x22) = 3;
    *(undefined *)(iVar1 + 0x23) = 0;
    iVar1 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (iVar1 != 0) {
      FUN_80037d2c(param_1,iVar1,0);
      FUN_8021fad0(iVar1);
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
    }
  }
  return;
}

