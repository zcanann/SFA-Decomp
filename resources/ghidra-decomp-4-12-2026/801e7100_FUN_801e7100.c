// Function: FUN_801e7100
// Entry: 801e7100
// Size: 504 bytes

undefined4
FUN_801e7100(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  short *psVar4;
  int iVar5;
  double dVar6;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar1 = FUN_8002bac4();
  iVar5 = *(int *)(param_9 + 0x5c);
  *(undefined *)(iVar5 + 0x9d6) = 0xff;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e667c;
  if (param_9[0x50] != 0) {
    FUN_8003042c((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  FUN_80036018((int)param_9);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  uVar2 = FUN_80020078(0x617);
  if (uVar2 == 0) {
    local_28[0] = 1;
    psVar4 = *(short **)(iVar5 + 0x9b0);
    uVar2 = FUN_800138e4(psVar4);
    if (uVar2 == 0) {
      FUN_80013978(psVar4,(uint)local_28);
    }
    uVar3 = 7;
  }
  else {
    FUN_801e823c(param_9,iVar1,0);
    uStack_1c = (uint)*(ushort *)(iVar5 + 0x9ca);
    local_20 = 0x43300000;
    dVar6 = (double)FUN_802945e0();
    *(float *)(param_9 + 8) =
         (float)((double)*(float *)(iVar5 + 0x9b8) * dVar6 + (double)*(float *)(iVar5 + 0x9bc));
    uVar2 = (uint)*(ushort *)(iVar5 + 0x9ca) + (uint)DAT_803dc070 * 0x100;
    if (0xffff < uVar2) {
      uStack_1c = FUN_80022264(0xf,0x23);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar5 + 0x9b8) =
           FLOAT_803e6688 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6698);
    }
    *(short *)(iVar5 + 0x9ca) = (short)uVar2;
    if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
      iVar1 = FUN_80296ffc(iVar1);
      if (iVar1 < 1) {
        uVar2 = FUN_80022264(0,2);
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar2,param_9,0xffffffff);
        FUN_80014b68(0,0x100);
      }
      else {
        FUN_800201ac(0x61d,1);
        FUN_80014b68(0,0x100);
      }
    }
    uVar3 = 0;
  }
  return uVar3;
}

