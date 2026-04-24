// Function: FUN_801696d4
// Entry: 801696d4
// Size: 312 bytes

void FUN_801696d4(int param_1)

{
  undefined uVar1;
  int *piVar2;
  int local_18 [2];
  undefined4 local_10;
  uint uStack12;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  *(undefined *)(param_1 + 0x36) = 0;
  *(undefined4 *)(param_1 + 0xf4) = 0xdc;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  if (*piVar2 != 0) {
    FUN_8001db6c((double)FLOAT_803e30e0,*piVar2,0);
  }
  if (*(short *)(param_1 + 0x46) == 0x869) {
    uVar1 = FUN_800221a0(0,1);
    uStack12 = FUN_800221a0(0x32,0x3c);
    uStack12 = uStack12 ^ 0x80000000;
    local_10 = 0x43300000;
    FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e30e8),param_1,1,
                 1,0,uVar1,0,1,0);
  }
  else {
    for (local_18[0] = 0; local_18[0] < 0x19; local_18[0] = local_18[0] + 1) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x715,0,1,0xffffffff,local_18);
    }
    FUN_8000bb18(param_1,0x279);
  }
  return;
}

