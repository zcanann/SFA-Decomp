// Function: FUN_8013209c
// Entry: 8013209c
// Size: 168 bytes

void FUN_8013209c(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5)

{
  undefined2 uVar2;
  int iVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_80286840();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  iVar1 = FUN_80023d8c(0x12,5);
  *(undefined *)(iVar1 + 5) = 2;
  *(undefined2 *)(iVar1 + 0xe) = uVar2;
  *(undefined2 *)(iVar1 + 0x10) = extraout_r4;
  *(short *)(iVar1 + 0xc) = param_5;
  *(short *)(iVar1 + 8) = param_3;
  *(short *)(iVar1 + 10) = param_4;
  *(undefined *)(iVar1 + 4) = 2;
  *(undefined *)(iVar1 + 6) = 4;
  FUN_8028688c();
  return;
}

