// Function: FUN_8005dbc4
// Entry: 8005dbc4
// Size: 240 bytes

void FUN_8005dbc4(ushort *param_1)

{
  int iVar1;
  
  iVar1 = FUN_8002b660((int)param_1);
  if (*(int *)(iVar1 + 0x58) == 0) {
    (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,1,param_1);
    FUN_8003fd58();
    FUN_8003ba50(0,0,0,0,(int)param_1,1);
    FUN_8000f9d4();
    if ((*(int *)(param_1 + 0x32) == 0) || (*(int *)(*(int *)(param_1 + 0x32) + 0xc) == 0)) {
      if (*(short *)(*(int *)(param_1 + 0x28) + 0x48) == 3) {
        FUN_800617d0(param_1,iVar1);
      }
    }
    else {
      FUN_80062614();
    }
    FUN_8000f7a0();
  }
  else {
    FUN_8003da78(param_1,iVar1);
  }
  return;
}

