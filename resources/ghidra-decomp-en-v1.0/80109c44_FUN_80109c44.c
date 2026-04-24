// Function: FUN_80109c44
// Entry: 80109c44
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x80109ed0) */
/* WARNING: Removing unreachable block (ram,0x80109ec8) */
/* WARNING: Removing unreachable block (ram,0x80109ed8) */

void FUN_80109c44(short *param_1)

{
  short sVar2;
  uint uVar1;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 uVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  if (*(char *)((int)DAT_803dd558 + 0xf5) == '\0') {
    iVar4 = *(int *)(param_1 + 0x52);
    iVar5 = *(int *)(*DAT_803dd558 + 0x4c);
    if ((*(byte *)(iVar5 + 0x1b) & 1) == 0) {
      *param_1 = *(short *)(iVar5 + 0x1c) + -0x8000;
    }
    if ((*(byte *)(iVar5 + 0x1b) & 2) == 0) {
      param_1[1] = *(short *)(iVar5 + 0x1e);
    }
    if ((*(byte *)(iVar5 + 0x1b) & 4) == 0) {
      param_1[2] = *(short *)(iVar5 + 0x20);
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*DAT_803dd558 + 0x18);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(*DAT_803dd558 + 0x1c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*DAT_803dd558 + 0x20);
    *(float *)(param_1 + 0x5a) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1a)) - DOUBLE_803e1880);
    dVar10 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0x18));
    dVar9 = (double)(*(float *)(param_1 + 0xe) - *(float *)(iVar4 + 0x1c));
    dVar8 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar4 + 0x20));
    if ((*(byte *)(iVar5 + 0x1b) & 1) != 0) {
      sVar2 = FUN_800217c0(dVar10,dVar8);
      *param_1 = -0x8000 - sVar2;
    }
    if ((*(byte *)(iVar5 + 0x1b) & 2) != 0) {
      uVar7 = FUN_802931a0((double)(float)(dVar10 * dVar10 + (double)(float)(dVar8 * dVar8)));
      uVar1 = FUN_800217c0(dVar9,uVar7);
      iVar3 = ((uVar1 & 0xffff) - (int)*(short *)(iVar5 + 0x1e)) - ((int)param_1[1] & 0xffffU);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      param_1[1] = param_1[1] + (short)((int)(iVar3 * (uint)DAT_803db410) >> 3);
    }
    if ((*(byte *)(iVar5 + 0x1b) & 4) != 0) {
      iVar4 = (int)param_1[2] - ((int)*(short *)(iVar4 + 4) & 0xffffU);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      param_1[2] = param_1[2] + (short)((int)(iVar4 * (uint)DAT_803db410) >> 3);
    }
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  return;
}

