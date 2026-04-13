// Function: FUN_80100f2c
// Entry: 80100f2c
// Size: 316 bytes

undefined4 FUN_80100f2c(int param_1,int *param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  char acStack_18 [3];
  byte local_15;
  
  iVar1 = FUN_800284e8(*param_2,param_3);
  FUN_80052a6c();
  if (*(char *)(iVar1 + 0x29) == '\x01') {
    if ((*(byte *)(DAT_803de19c + 0x141) & 0x20) == 0) {
      local_15 = 0;
    }
    else {
      local_15 = *(byte *)(param_1 + 0x36);
    }
  }
  else {
    local_15 = *(byte *)(param_1 + 0x36);
  }
  if (*(char *)(DAT_803de19c + 0x138) == '\b') {
    local_15 = 0;
  }
  uVar2 = FUN_8005383c(*(uint *)(iVar1 + 0x24));
  FUN_80051ed8(uVar2,(float *)0x0,0,acStack_18);
  FUN_80052a38();
  if (local_15 < 0xff) {
    FUN_8025cce8(1,4,5,5);
    FUN_8007048c(1,3,0);
  }
  else {
    FUN_8025cce8(0,1,0,5);
    FUN_8007048c(1,3,1);
  }
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(2);
  return 1;
}

