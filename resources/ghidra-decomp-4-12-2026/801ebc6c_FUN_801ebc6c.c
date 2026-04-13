// Function: FUN_801ebc6c
// Entry: 801ebc6c
// Size: 780 bytes

void FUN_801ebc6c(int param_1,int param_2)

{
  bool bVar1;
  ushort uVar3;
  int iVar2;
  int iVar4;
  uint uVar5;
  double dVar6;
  int local_38;
  uint uStack_34;
  int iStack_30;
  float afStack_2c [3];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar4 = *(int *)(param_1 + 0x54);
  uVar3 = FUN_80036074(param_1);
  if (uVar3 != 0) {
    if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
      FUN_80035eec(param_1,0x15,1,0);
    }
    else {
      FUN_80035ea4(param_1);
      FUN_80035f9c(param_1);
    }
    iVar2 = FUN_80036974(param_1,&local_38,&iStack_30,&uStack_34);
    if (iVar2 == 0x15) {
      if (*(float *)(param_2 + 0x3e4) == FLOAT_803e6780) {
        FUN_80247ef8((float *)(param_1 + 0x24),afStack_2c);
        dVar6 = FUN_80247f90(afStack_2c,(float *)(local_38 + 0x24));
        FUN_80247edc((double)(float)(dVar6 * (double)*(float *)(param_2 + 0x4ac) +
                                    (double)FLOAT_803e6784),(float *)(param_2 + 0x494),
                     (float *)(param_2 + 0x494));
        *(float *)(param_2 + 0x498) = *(float *)(param_2 + 0x498) * FLOAT_803e6840;
        *(float *)(param_2 + 0x3e4) = FLOAT_803e678c;
        *(float *)(param_2 + 0x3e0) = FLOAT_803e6784;
      }
    }
    else if (iVar2 < 0x15) {
      if ((iVar2 == 0xd) && ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0)) {
        *(int *)(param_2 + 0x42c) = local_38;
        *(float *)(param_2 + 0x3e0) = FLOAT_803e6784;
      }
    }
    else if ((iVar2 == 0x1d) && ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0)) {
      FUN_80055240((double)FLOAT_803e6844,1);
      dVar6 = DOUBLE_803e6798;
      uStack_1c = DAT_803dcd38 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(param_2 + 0x3e4) =
           (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6798);
      *(float *)(param_2 + 0x3e0) = FLOAT_803dcd30;
      uStack_14 = DAT_803dcd34 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(param_2 + 0x4c4) = (float)((double)CONCAT44(0x43300000,uStack_14) - dVar6);
    }
    local_38 = *(int *)(iVar4 + 0x50);
    if (((local_38 != 0) &&
        (*(int *)(param_2 + 0x42c) = local_38, *(float *)(param_2 + 0x3e4) == FLOAT_803e6780)) &&
       (iVar4 = FUN_80080100((int *)&DAT_8032916c,0xc,(int)*(short *)(local_38 + 0x46)), iVar4 != -1
       )) {
      FUN_8009ab54((double)FLOAT_803e6848,param_1);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x551,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x552,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x554,0,4,0xffffffff,0);
      uVar5 = 0x32 / DAT_803dc070;
      while (bVar1 = uVar5 != 0, uVar5 = uVar5 - 1, bVar1) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x553,0,2,0xffffffff,0);
      }
      *(float *)(param_2 + 0x3e4) = FLOAT_803e678c;
      *(float *)(param_2 + 0x3e0) = FLOAT_803e6784;
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        *(float *)(param_2 + 0x3e4) =
             (float)((double)CONCAT44(0x43300000,DAT_803dcd3c ^ 0x80000000) - DOUBLE_803e6798);
      }
    }
  }
  return;
}

