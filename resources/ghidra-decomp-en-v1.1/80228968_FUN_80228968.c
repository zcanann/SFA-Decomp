// Function: FUN_80228968
// Entry: 80228968
// Size: 180 bytes

void FUN_80228968(int param_1)

{
  uint uVar1;
  
  if ((*(int *)(param_1 + 0xf4) != 0) && (uVar1 = FUN_80022264(0,5), uVar1 == 0)) {
    if (*(char *)(param_1 + 0xad) == '\0') {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x73f,0,2,0xffffffff,param_1);
    }
    else {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x740,0,2,0xffffffff,param_1);
    }
  }
  return;
}

