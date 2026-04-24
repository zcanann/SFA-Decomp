// Function: FUN_801d1978
// Entry: 801d1978
// Size: 644 bytes

void FUN_801d1978(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  undefined4 local_38;
  undefined4 local_34 [2];
  undefined4 local_2c;
  undefined4 local_18;
  uint uStack20;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  local_38 = 0x19;
  iVar2 = FUN_8002b9ec();
  *(undefined **)(param_1 + 0xbc) = &LAB_801d0828;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1a));
  if (iVar3 != 0) {
    *(undefined *)(iVar4 + 0x136) = 8;
    FUN_80035f00(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) | 0x810;
  *(float *)(iVar4 + 0x110) = FLOAT_803e52e0;
  uStack20 = (uint)*(byte *)(param_2 + 0x1c);
  local_18 = 0x43300000;
  *(float *)(iVar4 + 0x114) =
       FLOAT_803e52e4 *
       ((float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e52c0) / FLOAT_803e52e8);
  FUN_80030334((double)FLOAT_803e5288,param_1,1,0);
  FUN_8002fa48((double)FLOAT_803e52a8,(double)FLOAT_803e52a8,param_1,local_34);
  *(undefined4 *)(iVar4 + 0x118) = local_34[0];
  if (*(float *)(iVar4 + 0x118) < FLOAT_803e5288) {
    *(float *)(iVar4 + 0x118) = -*(float *)(iVar4 + 0x118);
  }
  *(float *)(iVar4 + 0x118) = *(float *)(iVar4 + 0x118) * *(float *)(iVar4 + 0x110);
  *(float *)(iVar4 + 0x118) = *(float *)(iVar4 + 0x118) + FLOAT_803e52a0;
  FUN_80030334((double)FLOAT_803e5288,param_1,4,0);
  FUN_8002fa48((double)FLOAT_803e52a8,(double)FLOAT_803e52a8,param_1,local_34);
  *(undefined4 *)(iVar4 + 0x11c) = local_2c;
  if (*(float *)(iVar4 + 0x11c) < FLOAT_803e5288) {
    *(float *)(iVar4 + 0x11c) = -*(float *)(iVar4 + 0x11c);
  }
  *(float *)(iVar4 + 0x11c) = *(float *)(iVar4 + 0x11c) + FLOAT_803e52a0;
  FUN_80037964(param_1,1);
  if ((*(byte *)(param_2 + 0x18) < 6) && (3 < *(byte *)(param_2 + 0x18))) {
    *(byte *)(iVar4 + 0x137) = *(byte *)(iVar4 + 0x137) | 2;
    (**(code **)(*DAT_803dca9c + 0x8c))((double)FLOAT_803e52ec,iVar4,param_1,&local_38,0xffffffff);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar4 + 0x68);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar4 + 0x70);
  }
  *(float *)(iVar4 + 0x120) = FLOAT_803e52f0;
  fVar1 = FLOAT_803e52f4;
  if (iVar2 == 0) {
    *(float *)(iVar4 + 0x108) = FLOAT_803e52f4;
    *(float *)(iVar4 + 0x10c) = fVar1;
  }
  else {
    dVar5 = (double)FUN_80021704(iVar2 + 0x18,param_1 + 0x18);
    *(float *)(iVar4 + 0x108) = (float)dVar5;
    *(float *)(iVar4 + 0x10c) = (float)dVar5;
  }
  FUN_80037200(param_1,0x31);
  FUN_80037200(param_1,0x47);
  if (*(short *)(param_1 + 0x46) == 0x658) {
    *(undefined2 *)(iVar4 + 0x134) = 0x66d;
  }
  else {
    *(undefined2 *)(iVar4 + 0x134) = 0xc1;
  }
  return;
}

