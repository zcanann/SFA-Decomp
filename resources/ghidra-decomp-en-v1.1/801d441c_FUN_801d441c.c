// Function: FUN_801d441c
// Entry: 801d441c
// Size: 456 bytes

void FUN_801d441c(int param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  undefined local_28 [8];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_28[0] = 5;
  *(float *)(iVar3 + 0x274) = FLOAT_803e6088;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  *(float *)(param_1 + 0x28) = FLOAT_803e608c;
  FUN_80035ff8(param_1);
  uVar1 = FUN_80022264(0,0xffff);
  *(short *)(iVar3 + 0x2ac) = (short)uVar1;
  uStack_1c = FUN_80022264(0,1000);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(iVar3 + 0x280) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6038) / FLOAT_803e6028;
  (**(code **)(*DAT_803dd728 + 4))(iVar3 + 8,0,0x40002,1);
  (**(code **)(*DAT_803dd728 + 0xc))(iVar3 + 8,1,&DAT_803279d8,&DAT_803dcc28,local_28);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 8);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x3f1,0,4,0xffffffff,0);
  piVar2 = FUN_8001f58c(param_1,'\x01');
  if (piVar2 != (int *)0x0) {
    FUN_8001dbf0((int)piVar2,2);
    FUN_8001dbb4((int)piVar2,0xff,0,0xff,0);
    FUN_8001dbd8((int)piVar2,1);
    FUN_8001dcfc((double)FLOAT_803e6020,(double)FLOAT_803e6024,(int)piVar2);
  }
  *(int **)(iVar3 + 0x270) = piVar2;
  FUN_80037a5c(param_1,2);
  uVar1 = FUN_80022264(0xfffffe00,0x200);
  *(short *)(iVar3 + 0x2ae) = (short)uVar1;
  return;
}

