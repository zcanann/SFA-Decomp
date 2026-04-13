// Function: FUN_801a497c
// Entry: 801a497c
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801a4a90) */
/* WARNING: Removing unreachable block (ram,0x801a4a88) */
/* WARNING: Removing unreachable block (ram,0x801a4994) */
/* WARNING: Removing unreachable block (ram,0x801a498c) */

void FUN_801a497c(ushort *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  iVar5 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_8002bac4();
  uVar4 = 0xff;
  uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x20));
  if (uVar2 != 0) {
    iVar3 = FUN_800386e0(param_1,iVar1,(float *)0x0);
    iVar3 = (int)(short)iVar3;
    if (iVar3 < 0) {
      iVar3 = -iVar3;
    }
    if (iVar3 < 0x4001) {
      dVar8 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000
                                              ) - DOUBLE_803e5078);
      dVar6 = (double)FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      dVar7 = (double)FUN_8000f4a0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                                   (double)*(float *)(param_1 + 10));
      if (dVar7 < dVar6) {
        dVar6 = (double)FUN_8000f4a0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8)
                                     ,(double)*(float *)(param_1 + 10));
      }
      if (dVar6 < dVar8) {
        uVar4 = (undefined)(int)(FLOAT_803e5074 * (float)(dVar6 / dVar8));
      }
      *(undefined *)(param_1 + 0x1b) = uVar4;
    }
    else {
      *(undefined *)(param_1 + 0x1b) = 0;
    }
  }
  return;
}

