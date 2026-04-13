// Function: FUN_80109ee0
// Entry: 80109ee0
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x8010a174) */
/* WARNING: Removing unreachable block (ram,0x8010a16c) */
/* WARNING: Removing unreachable block (ram,0x8010a164) */
/* WARNING: Removing unreachable block (ram,0x80109f00) */
/* WARNING: Removing unreachable block (ram,0x80109ef8) */
/* WARNING: Removing unreachable block (ram,0x80109ef0) */

void FUN_80109ee0(short *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  if (*(char *)((int)DAT_803de1d0 + 0xf5) == '\0') {
    iVar3 = *(int *)(param_1 + 0x52);
    iVar4 = *(int *)(*DAT_803de1d0 + 0x4c);
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      *param_1 = *(short *)(iVar4 + 0x1c) + -0x8000;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) == 0) {
      param_1[1] = *(short *)(iVar4 + 0x1e);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
      param_1[2] = *(short *)(iVar4 + 0x20);
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*DAT_803de1d0 + 0x18);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(*DAT_803de1d0 + 0x1c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*DAT_803de1d0 + 0x20);
    *(float *)(param_1 + 0x5a) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x1a)) - DOUBLE_803e2500);
    dVar6 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar3 + 0x18));
    dVar5 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar3 + 0x20));
    if ((*(byte *)(iVar4 + 0x1b) & 1) != 0) {
      iVar1 = FUN_80021884();
      *param_1 = -0x8000 - (short)iVar1;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) != 0) {
      FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
      uVar2 = FUN_80021884();
      iVar1 = ((uVar2 & 0xffff) - (int)*(short *)(iVar4 + 0x1e)) - (uint)(ushort)param_1[1];
      if (0x8000 < iVar1) {
        iVar1 = iVar1 + -0xffff;
      }
      if (iVar1 < -0x8000) {
        iVar1 = iVar1 + 0xffff;
      }
      param_1[1] = param_1[1] + (short)((int)(iVar1 * (uint)DAT_803dc070) >> 3);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) != 0) {
      iVar3 = (int)param_1[2] - (uint)*(ushort *)(iVar3 + 4);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      param_1[2] = param_1[2] + (short)((int)(iVar3 * (uint)DAT_803dc070) >> 3);
    }
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

