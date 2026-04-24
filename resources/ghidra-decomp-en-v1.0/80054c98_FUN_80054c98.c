// Function: FUN_80054c98
// Entry: 80054c98
// Size: 188 bytes

void FUN_80054c98(undefined4 param_1,undefined4 param_2,undefined param_3,undefined4 param_4,
                 undefined4 param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9)

{
  undefined2 uVar2;
  int iVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_802860d0();
  iVar1 = FUN_8025a0ec();
  iVar1 = FUN_80023cc8(iVar1 + 0x60,6,0);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    FUN_800033a8(iVar1,0,100);
    *(undefined *)(iVar1 + 0x16) = param_3;
    *(undefined2 *)(iVar1 + 10) = uVar2;
    *(undefined2 *)(iVar1 + 0xc) = extraout_r4;
    *(undefined2 *)(iVar1 + 0x10) = 1;
    *(undefined2 *)(iVar1 + 0xe) = 0;
    *(undefined *)(iVar1 + 0x17) = param_6;
    *(undefined *)(iVar1 + 0x18) = param_7;
    *(undefined *)(iVar1 + 0x19) = param_8;
    *(undefined *)(iVar1 + 0x1a) = param_9;
    *(undefined4 *)(iVar1 + 0x50) = 0;
    FUN_80053d58(iVar1);
  }
  FUN_8028611c(iVar1);
  return;
}

