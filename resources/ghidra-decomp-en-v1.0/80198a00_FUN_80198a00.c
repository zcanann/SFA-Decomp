// Function: FUN_80198a00
// Entry: 80198a00
// Size: 360 bytes

void FUN_80198a00(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined4 local_28;
  float local_24;
  longlong local_20;
  
  uVar6 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  uVar4 = (undefined4)uVar6;
  local_28 = 0x17;
  iVar5 = *(int *)(iVar1 + 0xb8);
  uVar2 = (**(code **)(*DAT_803dca9c + 0x14))
                    ((double)*(float *)(iVar5 + 0x28),(double)*(float *)(iVar5 + 0x2c),
                     (double)*(float *)(iVar5 + 0x30),&local_28,1,
                     (int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x38));
  iVar3 = (**(code **)(*DAT_803dca9c + 0x4c))
                    ((double)*(float *)(iVar5 + 0x28),(double)*(float *)(iVar5 + 0x2c),
                     (double)*(float *)(iVar5 + 0x30),uVar2,&local_24);
  iVar5 = (**(code **)(*DAT_803dca9c + 0x4c))
                    ((double)*(float *)(iVar5 + 0x1c),(double)*(float *)(iVar5 + 0x20),
                     (double)*(float *)(iVar5 + 0x24),uVar2,&local_24);
  if (iVar3 == 0) {
    if (iVar5 == 0) {
      local_20 = (longlong)(int)local_24;
      FUN_801993b0(iVar1,uVar4,0xfffffffe,(int)local_24);
    }
    else {
      local_20 = (longlong)(int)local_24;
      FUN_801993b0(iVar1,uVar4,0xffffffff,(int)local_24);
    }
  }
  else if (iVar5 == 0) {
    local_20 = (longlong)(int)local_24;
    FUN_801993b0(iVar1,uVar4,1,(int)local_24);
  }
  else {
    local_20 = (longlong)(int)local_24;
    FUN_801993b0(iVar1,uVar4,2,(int)local_24);
  }
  FUN_80286128();
  return;
}

