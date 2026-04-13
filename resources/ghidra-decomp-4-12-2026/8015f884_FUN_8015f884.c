// Function: FUN_8015f884
// Entry: 8015f884
// Size: 292 bytes

void FUN_8015f884(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  uVar5 = 6;
  if (param_11 != 0) {
    uVar5 = 7;
  }
  if ((*(byte *)(param_10 + 0x2b) & 0x20) == 0) {
    uVar5 = uVar5 | 8;
  }
  uVar2 = 7;
  uVar3 = 6;
  uVar4 = 0x102;
  iVar6 = *DAT_803dd738;
  (**(code **)(iVar6 + 0x58))((double)FLOAT_803e3aac,param_9,param_10,iVar8);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  pfVar7 = *(float **)(iVar8 + 0x40c);
  uVar1 = FUN_80022264(10,300);
  *pfVar7 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3aa0);
  FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,8,0,uVar2,uVar3,uVar4,uVar5,iVar6);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar8,0);
  *(undefined2 *)(iVar8 + 0x270) = 0;
  *(undefined *)(iVar8 + 0x25f) = 0;
  FUN_80035ff8(param_9);
  return;
}

