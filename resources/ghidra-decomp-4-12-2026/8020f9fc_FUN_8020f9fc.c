// Function: FUN_8020f9fc
// Entry: 8020f9fc
// Size: 528 bytes

void FUN_8020f9fc(ushort *param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  int local_28;
  float local_24;
  float local_20 [2];
  undefined8 local_18;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  dVar5 = (double)(**(code **)(**(int **)(param_2 + 0x68) + 0x44))(param_2,&local_24);
  dVar7 = (double)FLOAT_803dce8c;
  dVar6 = (double)FLOAT_803e737c;
  local_24 = (float)(dVar6 * (double)(float)(dVar5 * dVar7) + dVar7);
  iVar3 = **(int **)(param_2 + 0x68);
  (**(code **)(iVar3 + 0x40))(param_2,local_20,&local_28);
  dVar5 = (double)FLOAT_803e7380;
  iVar2 = (int)(dVar5 * (double)local_20[0]);
  local_18 = (double)(longlong)iVar2;
  if (iVar2 < 0) {
    iVar2 = -iVar2;
  }
  if ((local_28 == 0) || ((int)(short)param_1[0x50] != (uint)*(ushort *)(iVar4 + 0xa8))) {
    FUN_8002ee64(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,
                 *(ushort *)(iVar4 + 0xa8) + 2,(short)iVar2);
  }
  else {
    FUN_8002ee64(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,
                 *(ushort *)(iVar4 + 0xa8) + 1,(short)iVar2);
  }
  local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
  dVar5 = (double)(float)(local_18 - DOUBLE_803e7398);
  iVar2 = FUN_8002fb40((double)local_24,dVar5);
  if ((iVar2 != 0) && ((int)(short)param_1[0x50] != (uint)*(ushort *)(iVar4 + 0xa8))) {
    *(float *)(iVar4 + 0x30) = FLOAT_803e7384;
    iVar2 = *(int *)(iVar4 + 0x9c);
    if (iVar2 < 1) {
      iVar2 = 1;
    }
    else if (400 < iVar2) {
      iVar2 = 400;
    }
    *(int *)(iVar4 + 0x9c) = iVar2;
    uVar1 = FUN_8008038c(2);
    if (uVar1 == 0) {
      FUN_8003042c((double)FLOAT_803e7388,dVar5,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,
                   (uint)*(ushort *)(iVar4 + 0xa8),0,iVar3,param_5,param_6,param_7,param_8);
    }
    else {
      iVar2 = FUN_8002bac4();
      iVar2 = FUN_800386e0(param_1,iVar2,(float *)0x0);
      if ((short)iVar2 < 0) {
        *(float *)(iVar4 + 0x30) = FLOAT_803e7390;
        FUN_8000bb38((uint)param_1,0x2e2);
        iVar2 = *(ushort *)(iVar4 + 0xa8) + 4;
      }
      else {
        *(float *)(iVar4 + 0x30) = FLOAT_803e738c;
        FUN_8000bb38((uint)param_1,0x2e3);
        iVar2 = *(ushort *)(iVar4 + 0xa8) + 8;
      }
      FUN_8003042c((double)FLOAT_803e7388,dVar5,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,iVar2,0,
                   iVar3,param_5,param_6,param_7,param_8);
      *(int *)(iVar4 + 0x9c) = *(int *)(iVar4 + 0x9c) + 100;
    }
  }
  return;
}

