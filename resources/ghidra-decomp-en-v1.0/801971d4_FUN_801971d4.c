// Function: FUN_801971d4
// Entry: 801971d4
// Size: 396 bytes

void FUN_801971d4(int param_1)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  int *piVar4;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((((*(byte *)(piVar4 + 5) >> 5 & 1) == 0) &&
      (iVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x20)), iVar1 != 0)) &&
     ((*(byte *)(piVar4 + 5) >> 6 & 1) == 0)) {
    *(byte *)(piVar4 + 5) = *(byte *)(piVar4 + 5) & 0xdf | 0x20;
    piVar4[4] = 0;
  }
  if (((*(byte *)(piVar4 + 5) >> 5 & 1) != 0) && (*piVar4 != 0)) {
    FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14));
    iVar1 = FUN_8005aeec();
    if ((iVar1 != 0) &&
       (((*(ushort *)(iVar1 + 4) & 8) != 0 &&
        (psVar2 = (short *)FUN_80056694(iVar1,*piVar4), psVar2 != (short *)0x0)))) {
      iVar1 = FUN_80056684((int)*psVar2);
      piVar4[4] = piVar4[4] + (uint)*(byte *)(piVar4 + 1) * (uint)DAT_803db410;
      FUN_80137948(s__TEXFRAMEANIM__i_803223e8,piVar4[4]);
      if (piVar4[4] < 0) {
        piVar4[4] = 0;
      }
      else if (piVar4[2] < piVar4[4]) {
        iVar3 = (int)*(short *)(iVar3 + 0x1e);
        if (iVar3 == -1) {
          piVar4[4] = piVar4[3];
        }
        else {
          FUN_800200e8(iVar3,1);
          *(byte *)(piVar4 + 5) = *(byte *)(piVar4 + 5) & 0xdf;
          *(byte *)(piVar4 + 5) = *(byte *)(piVar4 + 5) & 0xbf | 0x40;
          piVar4[4] = piVar4[2];
        }
      }
      *(int *)(iVar1 + 4) = piVar4[4];
    }
  }
  return;
}

