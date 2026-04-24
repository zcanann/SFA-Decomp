// Function: FUN_8005da48
// Entry: 8005da48
// Size: 240 bytes

void FUN_8005da48(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_8002b588();
  if (*(int *)(iVar1 + 0x58) == 0) {
    (**(code **)(*DAT_803dca7c + 0x1c))(0,0,0,1,param_1);
    FUN_8003fc60();
    FUN_8003b958(0,0,0,0,param_1,1);
    FUN_8000f9b4();
    if ((*(int *)(param_1 + 100) == 0) || (*(int *)(*(int *)(param_1 + 100) + 0xc) == 0)) {
      if (*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 3) {
        FUN_80061654(param_1,iVar1);
      }
    }
    else {
      FUN_80062498(param_1,0,0,DAT_803db410);
    }
    FUN_8000f780();
  }
  else {
    FUN_8003d980(param_1,iVar1);
  }
  return;
}

