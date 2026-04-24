// Function: FUN_801a651c
// Entry: 801a651c
// Size: 268 bytes

void FUN_801a651c(int param_1,int param_2)

{
  float fVar1;
  double dVar2;
  int iVar3;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  uint uStack12;
  undefined4 local_8;
  uint uStack4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_18 = DAT_803e4460;
  local_14 = DAT_803e4464;
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
  *(undefined2 *)(param_1 + 4) = 0x4000;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_2 + 0x10);
  dVar2 = DOUBLE_803e4488;
  fVar1 = FLOAT_803e447c;
  uStack12 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(iVar3 + 0x10c) =
       (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e4488) / FLOAT_803e447c;
  uStack4 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
  local_8 = 0x43300000;
  *(float *)(iVar3 + 0x108) = (float)((double)CONCAT44(0x43300000,uStack4) - dVar2) / fVar1;
  *(undefined *)(iVar3 + 0x114) = 0;
  *(undefined *)(iVar3 + 0x115) = 1;
  *(float *)(iVar3 + 0x110) = FLOAT_803e4468;
  (**(code **)(*DAT_803dca9c + 0x8c))((double)FLOAT_803e44b8,iVar3,param_1,&local_18,0xffffffff);
  return;
}

