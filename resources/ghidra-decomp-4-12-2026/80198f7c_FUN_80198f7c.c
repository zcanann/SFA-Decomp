// Function: FUN_80198f7c
// Entry: 80198f7c
// Size: 360 bytes

void FUN_80198f7c(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  undefined8 extraout_f1;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar8;
  undefined4 local_28;
  float local_24;
  longlong local_20;
  
  uVar8 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  uVar4 = (undefined4)uVar8;
  local_28 = 0x17;
  iVar5 = *(int *)(iVar1 + 0xb8);
  uVar2 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(iVar5 + 0x28),(double)*(float *)(iVar5 + 0x2c),
                     (double)*(float *)(iVar5 + 0x30),&local_28,1,
                     (int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x38));
  iVar3 = (**(code **)(*DAT_803dd71c + 0x4c))
                    ((double)*(float *)(iVar5 + 0x28),(double)*(float *)(iVar5 + 0x2c),
                     (double)*(float *)(iVar5 + 0x30),uVar2,&local_24);
  dVar6 = (double)*(float *)(iVar5 + 0x20);
  dVar7 = (double)*(float *)(iVar5 + 0x24);
  iVar5 = (**(code **)(*DAT_803dd71c + 0x4c))((double)*(float *)(iVar5 + 0x1c),uVar2,&local_24);
  if (iVar3 == 0) {
    if (iVar5 == 0) {
      local_20 = (longlong)(int)local_24;
      FUN_8019992c(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,0xfffffffe,
                   (int)local_24,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      local_20 = (longlong)(int)local_24;
      FUN_8019992c(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,0xffffffff,
                   (int)local_24,in_r7,in_r8,in_r9,in_r10);
    }
  }
  else if (iVar5 == 0) {
    local_20 = (longlong)(int)local_24;
    FUN_8019992c(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,1,(int)local_24,
                 in_r7,in_r8,in_r9,in_r10);
  }
  else {
    local_20 = (longlong)(int)local_24;
    FUN_8019992c(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,2,(int)local_24,
                 in_r7,in_r8,in_r9,in_r10);
  }
  FUN_8028688c();
  return;
}

