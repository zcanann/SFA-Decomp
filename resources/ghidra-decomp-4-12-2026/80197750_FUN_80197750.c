// Function: FUN_80197750
// Entry: 80197750
// Size: 396 bytes

void FUN_80197750(int param_1)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  int *piVar5;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((((*(byte *)(piVar5 + 5) >> 5 & 1) == 0) &&
      (uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x20)), uVar1 != 0)) &&
     ((*(byte *)(piVar5 + 5) >> 6 & 1) == 0)) {
    *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xdf | 0x20;
    piVar5[4] = 0;
  }
  if (((*(byte *)(piVar5 + 5) >> 5 & 1) != 0) && (*piVar5 != 0)) {
    iVar2 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
    iVar2 = FUN_8005b068(iVar2);
    if ((iVar2 != 0) &&
       (((*(ushort *)(iVar2 + 4) & 8) != 0 &&
        (psVar3 = (short *)FUN_80056810(), psVar3 != (short *)0x0)))) {
      iVar2 = FUN_80056800((int)*psVar3);
      piVar5[4] = piVar5[4] + (uint)*(byte *)(piVar5 + 1) * (uint)DAT_803dc070;
      FUN_80137cd0();
      if (piVar5[4] < 0) {
        piVar5[4] = 0;
      }
      else if (piVar5[2] < piVar5[4]) {
        uVar1 = (uint)*(short *)(iVar4 + 0x1e);
        if (uVar1 == 0xffffffff) {
          piVar5[4] = piVar5[3];
        }
        else {
          FUN_800201ac(uVar1,1);
          *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xdf;
          *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xbf | 0x40;
          piVar5[4] = piVar5[2];
        }
      }
      *(int *)(iVar2 + 4) = piVar5[4];
    }
  }
  return;
}

