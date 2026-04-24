// Function: FUN_8020377c
// Entry: 8020377c
// Size: 584 bytes

void FUN_8020377c(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar7 = FUN_8028683c();
  uVar1 = (uint)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  iVar5 = *(int *)(iVar3 + 0x40c);
  local_30 = FLOAT_803e6f48;
  iVar4 = *(int *)(uVar1 + 0x4c);
  uStack_1c = (uint)*(ushort *)(iVar3 + 0x3fe);
  local_20 = 0x43300000;
  iVar2 = (**(code **)(*DAT_803dd738 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6f78),uVar1
                     ,param_3,0x8000);
  if ((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) {
    iVar2 = FUN_80036f50(0x24,uVar1,&local_30);
  }
  if ((((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) &&
      ((*(byte *)(iVar3 + 0x404) & 2) == 0)) && ((*(byte *)(iVar4 + 0x2b) & 2) != 0)) {
    iVar2 = FUN_80036f50(0x24,uVar1,(float *)0x0);
  }
  if ((iVar2 == 0) || ((*(byte *)(iVar3 + 0x404) & 2) != 0)) {
    iVar2 = FUN_8002bac4();
    if (iVar2 == 0) {
      dVar6 = (double)FLOAT_803e6fec;
    }
    else {
      local_2c = *(float *)(iVar2 + 0x18) - *(float *)(uVar1 + 0x18);
      local_28 = *(float *)(iVar2 + 0x1c) - *(float *)(uVar1 + 0x1c);
      local_24 = *(float *)(iVar2 + 0x20) - *(float *)(uVar1 + 0x20);
      dVar6 = FUN_80293900((double)(local_24 * local_24 + local_2c * local_2c + local_28 * local_28)
                          );
    }
    if ((*(float *)(iVar5 + 0x10) < *(float *)(iVar5 + 0xc)) && (dVar6 < (double)FLOAT_803e701c)) {
      FUN_8000bb38(uVar1,(ushort)DAT_8032a284);
      uStack_1c = FUN_80022264(0x32,0xfa);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar5 + 0x10) =
           *(float *)(iVar5 + 0x10) +
           (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7000);
    }
    *(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + FLOAT_803dc074;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x28))
              (uVar1,param_3,iVar3 + 0x35c,(int)*(short *)(iVar3 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar2;
    *(undefined *)(param_3 + 0x349) = 0;
    FUN_800372f8(uVar1,3);
    *(undefined2 *)(iVar3 + 0x402) = 1;
  }
  FUN_80286888();
  return;
}

