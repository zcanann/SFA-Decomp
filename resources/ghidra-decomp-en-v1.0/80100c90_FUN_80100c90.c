// Function: FUN_80100c90
// Entry: 80100c90
// Size: 316 bytes

undefined4 FUN_80100c90(int param_1,undefined4 *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack24 [3];
  byte local_15;
  
  iVar1 = FUN_80028424(*param_2,param_3);
  FUN_800528f0();
  if (*(char *)(iVar1 + 0x29) == '\x01') {
    if ((*(byte *)(DAT_803dd524 + 0x141) & 0x20) == 0) {
      local_15 = 0;
    }
    else {
      local_15 = *(byte *)(param_1 + 0x36);
    }
  }
  else {
    local_15 = *(byte *)(param_1 + 0x36);
  }
  if (*(char *)(DAT_803dd524 + 0x138) == '\b') {
    local_15 = 0;
  }
  uVar2 = FUN_800536c0(*(undefined4 *)(iVar1 + 0x24));
  FUN_80051d5c(uVar2,0,0,auStack24);
  FUN_800528bc();
  if (local_15 < 0xff) {
    FUN_8025c584(1,4,5,5);
    FUN_80070310(1,3,0);
  }
  else {
    FUN_8025c584(0,1,0,5);
    FUN_80070310(1,3,1);
  }
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(2);
  return 1;
}

