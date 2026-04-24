// Function: FUN_80169b80
// Entry: 80169b80
// Size: 312 bytes

void FUN_80169b80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  int *piVar2;
  int local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  *(undefined *)(param_9 + 0x36) = 0;
  *(undefined4 *)(param_9 + 0xf4) = 0xdc;
  *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
  if (*piVar2 != 0) {
    FUN_8001dc30((double)FLOAT_803e3d78,*piVar2,'\0');
  }
  if (*(short *)(param_9 + 0x46) == 0x869) {
    uVar1 = FUN_80022264(0,1);
    uStack_c = FUN_80022264(0x32,0x3c);
    uStack_c = uStack_c ^ 0x80000000;
    local_10 = 0x43300000;
    FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e3d80),param_2,
                 param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,0,1,0);
  }
  else {
    for (local_18[0] = 0; local_18[0] < 0x19; local_18[0] = local_18[0] + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,local_18);
    }
    FUN_8000bb38(param_9,0x279);
  }
  return;
}

