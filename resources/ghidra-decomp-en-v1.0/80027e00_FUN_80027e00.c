// Function: FUN_80027e00
// Entry: 80027e00
// Size: 692 bytes

/* WARNING: Removing unreachable block (ram,0x8002808c) */

void FUN_80027e00(double param_1,double param_2,int *param_3,int param_4,int param_5,float *param_6,
                 undefined2 *param_7)

{
  uint uVar1;
  float fVar2;
  byte bVar3;
  double dVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  short local_48;
  short local_46;
  short local_44;
  double local_40;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  fVar2 = FLOAT_803de828;
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(short *)(*param_3 + 0xec) == 0) {
    *param_6 = FLOAT_803de828;
    param_6[1] = fVar2;
    param_6[2] = fVar2;
    *param_7 = 0;
    param_7[1] = 0;
    param_7[2] = 0;
  }
  if (param_4 == 0) {
    iVar7 = param_3[0xb];
  }
  else {
    iVar7 = param_3[0xc];
  }
  uVar6 = *(undefined4 *)(iVar7 + 0x34);
  *(undefined4 *)(iVar7 + 0x34) = *(undefined4 *)(iVar7 + param_5 * 4 + 0x34);
  if ((*(ushort *)(*param_3 + 2) & 0x40) == 0) {
    iVar5 = *(int *)(*(int *)(*param_3 + 100) + (uint)*(ushort *)(iVar7 + param_5 * 2 + 0x44) * 4);
  }
  else if (param_5 < 2) {
    iVar5 = *(int *)(iVar7 + (uint)*(ushort *)(iVar7 + param_5 * 2 + 0x44) * 4 + 0x1c) + 0x80;
  }
  else {
    iVar5 = *(int *)(iVar7 + (uint)*(ushort *)(iVar7 + param_5 * 2 + 0x44) * 4 + 0x24) + 0x80;
  }
  *(float *)(iVar7 + 4) = (float)(param_1 * (double)*(float *)(iVar7 + 0x14));
  bVar3 = *(byte *)(*(int *)(iVar7 + 0x34) + 2);
  uVar1 = (uint)*(float *)(iVar7 + 4);
  local_40 = (double)(longlong)(int)uVar1;
  uStack52 = uVar1 ^ 0x80000000;
  local_38 = 0x43300000;
  fVar2 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de820);
  if (fVar2 == *(float *)(iVar7 + 4)) {
    *(undefined2 *)(iVar7 + 0x4c) = 0;
  }
  else {
    *(ushort *)(iVar7 + 0x4c) = (ushort)bVar3;
  }
  if ((*(char *)(iVar7 + 0x60) != '\0') && (fVar2 == *(float *)(iVar7 + 0x14) - FLOAT_803de818)) {
    *(ushort *)(iVar7 + 0x4c) = -(ushort)bVar3 * (short)uVar1;
  }
  *(uint *)(iVar7 + 0x2c) = iVar5 + (int)*(short *)(iVar5 + 2) + bVar3 * uVar1;
  FUN_80007f78(iVar7,&local_48,param_7);
  *(undefined4 *)(iVar7 + 0x34) = uVar6;
  fVar2 = FLOAT_803de880;
  dVar4 = DOUBLE_803de820;
  *param_6 = FLOAT_803de880 *
             (float)((double)CONCAT44(0x43300000,(int)local_48 ^ 0x80000000) - DOUBLE_803de820);
  local_40 = (double)CONCAT44(0x43300000,(int)local_46 ^ 0x80000000);
  param_6[1] = fVar2 * (float)(local_40 - dVar4);
  param_6[2] = fVar2 * (float)((double)CONCAT44(0x43300000,(int)local_44 ^ 0x80000000) - dVar4);
  *param_6 = *param_6 + *(float *)(*(int *)(*param_3 + 0x3c) + 4);
  param_6[1] = param_6[1] + *(float *)(*(int *)(*param_3 + 0x3c) + 8);
  param_6[2] = param_6[2] + *(float *)(*(int *)(*param_3 + 0x3c) + 0xc);
  *param_6 = (float)((double)*param_6 * param_2);
  param_6[1] = (float)((double)param_6[1] * param_2);
  param_6[2] = (float)((double)param_6[2] * param_2);
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return;
}

