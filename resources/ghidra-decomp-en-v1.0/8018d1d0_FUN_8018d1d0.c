// Function: FUN_8018d1d0
// Entry: 8018d1d0
// Size: 732 bytes

void FUN_8018d1d0(int param_1,int param_2)

{
  int iVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined auStack72 [8];
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  uVar3 = (uint)*(byte *)(param_2 + 0x1a);
  if (uVar3 != 0) {
    local_40 = 0x43300000;
    *(float *)(param_1 + 8) =
         FLOAT_803e3d88 * (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e3da0);
    uStack60 = uVar3;
  }
  iVar4 = FUN_8001ffb4(0x8c);
  if (iVar4 != 0) {
    *(byte *)((int)piVar6 + 0x11) = *(byte *)((int)piVar6 + 0x11) | 1;
  }
  *(undefined2 *)(piVar6 + 3) = *(undefined2 *)(param_2 + 0x18);
  if ((*(short *)(piVar6 + 3) != -1) && (iVar4 = FUN_8001ffb4(), iVar4 != 0)) {
    *(byte *)((int)piVar6 + 0x11) = *(byte *)((int)piVar6 + 0x11) | 4;
  }
  *(undefined *)(piVar6 + 4) = *(undefined *)(param_2 + 0x1b);
  fVar2 = *(float *)(param_1 + 8) / *(float *)(*(int *)(param_1 + 0x50) + 4);
  iVar5 = *(int *)(param_1 + 0x54);
  uStack60 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
  local_40 = 0x43300000;
  iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e3da8) * fVar2);
  local_38 = (longlong)iVar4;
  uStack44 = (int)*(short *)(iVar5 + 0x5c) ^ 0x80000000;
  local_30 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e3da8) * fVar2);
  local_28 = (double)(longlong)iVar1;
  uStack28 = (int)*(short *)(iVar5 + 0x5e) ^ 0x80000000;
  local_20 = 0x43300000;
  iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3da8) * fVar2);
  local_18 = (longlong)iVar5;
  FUN_80035b50(param_1,iVar4,iVar1,iVar5);
  piVar6[1] = (int)FLOAT_803e3d80;
  piVar6[2] = (int)FLOAT_803e3d78;
  if (*piVar6 == 0) {
    iVar4 = FUN_8001f4c8(param_1,1);
    *piVar6 = iVar4;
  }
  if (*piVar6 != 0) {
    FUN_8001db2c(*piVar6,2);
    FUN_8001daf0(*piVar6,0xff,0x7f,0,0xff);
    FUN_8001da18(*piVar6,0xff,0x7f,0,0xff);
    uStack28 = (uint)(FLOAT_803e3d8c * *(float *)(param_1 + 8));
    local_18 = (longlong)(int)uStack28;
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,uStack28);
    FUN_8001dc38((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3da8),
                 (double)(FLOAT_803e3d90 + (float)(local_28 - DOUBLE_803e3da8)),*piVar6);
    iVar4 = (**(code **)(*DAT_803dca58 + 0x24))(auStack72);
    if (iVar4 == 0) {
      FUN_8001db6c((double)FLOAT_803e3d7c,*piVar6,0);
    }
    else {
      FUN_8001db6c((double)FLOAT_803e3d7c,*piVar6,1);
    }
    FUN_8001dd88((double)FLOAT_803e3d7c,(double)FLOAT_803e3d94,(double)FLOAT_803e3d7c,*piVar6);
    FUN_8001d620(*piVar6,1,3);
    FUN_8001dab8(*piVar6,0xff,0x5c,0,0xff);
    FUN_8001d730((double)(FLOAT_803e3d98 * *(float *)(param_1 + 8)),*piVar6,0,0xff,0x7f,0,0x87);
    FUN_8001d714((double)FLOAT_803e3d90,*piVar6);
  }
  return;
}

