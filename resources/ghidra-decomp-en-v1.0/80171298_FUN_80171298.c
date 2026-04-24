// Function: FUN_80171298
// Entry: 80171298
// Size: 96 bytes

void FUN_80171298(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8002b588();
  FUN_8002852c(uVar1,FUN_800284cc);
  if (*(short *)(param_1 + 0x46) == 0x836) {
    FUN_80170380(param_1,5);
  }
  else {
    FUN_80170380(param_1,7);
  }
  return;
}

