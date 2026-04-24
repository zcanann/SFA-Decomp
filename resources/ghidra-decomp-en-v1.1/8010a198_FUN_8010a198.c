// Function: FUN_8010a198
// Entry: 8010a198
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x8010a378) */
/* WARNING: Removing unreachable block (ram,0x8010a370) */
/* WARNING: Removing unreachable block (ram,0x8010a368) */
/* WARNING: Removing unreachable block (ram,0x8010a1b8) */
/* WARNING: Removing unreachable block (ram,0x8010a1b0) */
/* WARNING: Removing unreachable block (ram,0x8010a1a8) */

void FUN_8010a198(void)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  
  psVar2 = (short *)FUN_80286840();
  iVar7 = *(int *)(psVar2 + 0x52);
  if (DAT_803de1d0 == (int *)0x0) {
    DAT_803de1d0 = (int *)FUN_80023d8c(0xf8,0xf);
  }
  *(undefined *)(DAT_803de1d0 + 0x3d) = 1;
  *(undefined *)((int)DAT_803de1d0 + 0xf5) = 0;
  iVar3 = FUN_80109da0((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
                       (double)*(float *)(iVar7 + 0x20));
  if (iVar3 == 0) {
    *(undefined *)((int)DAT_803de1d0 + 0xf5) = 1;
  }
  else {
    *DAT_803de1d0 = iVar3;
    iVar8 = *(int *)(iVar3 + 0x4c);
    dVar10 = (double)(*(float *)(iVar3 + 0x18) - *(float *)(iVar7 + 0x18));
    dVar9 = (double)(*(float *)(iVar3 + 0x20) - *(float *)(iVar7 + 0x20));
    if ((*(byte *)(iVar8 + 0x1b) & 1) == 0) {
      sVar1 = *(short *)(iVar8 + 0x1c);
    }
    else {
      iVar4 = FUN_80021884();
      sVar1 = -(short)iVar4;
    }
    if ((*(byte *)(iVar8 + 0x1b) & 2) == 0) {
      sVar5 = *(short *)(iVar8 + 0x1e);
    }
    else {
      FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
      iVar4 = FUN_80021884();
      sVar5 = (short)iVar4 - *(short *)(iVar8 + 0x1e);
    }
    if ((*(byte *)(iVar8 + 0x1b) & 4) == 0) {
      sVar6 = *(short *)(iVar8 + 0x20);
    }
    else {
      sVar6 = *(short *)(iVar7 + 4);
    }
    dVar9 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar8 + 0x1a)) - DOUBLE_803e2500;
    *(undefined4 *)(psVar2 + 0xc) = *(undefined4 *)(iVar3 + 0x18);
    *(undefined4 *)(psVar2 + 0xe) = *(undefined4 *)(iVar3 + 0x1c);
    *(undefined4 *)(psVar2 + 0x10) = *(undefined4 *)(iVar3 + 0x20);
    *psVar2 = sVar1 + -0x8000;
    psVar2[1] = sVar5;
    psVar2[2] = sVar6;
    *(float *)(psVar2 + 0x5a) = (float)dVar9;
    FUN_8000e054((double)*(float *)(psVar2 + 0xc),(double)*(float *)(psVar2 + 0xe),
                 (double)*(float *)(psVar2 + 0x10),(float *)(psVar2 + 6),(float *)(psVar2 + 8),
                 (float *)(psVar2 + 10),*(int *)(psVar2 + 0x18));
  }
  FUN_8028688c();
  return;
}

