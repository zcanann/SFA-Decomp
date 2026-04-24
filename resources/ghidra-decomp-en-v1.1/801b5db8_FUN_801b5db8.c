// Function: FUN_801b5db8
// Entry: 801b5db8
// Size: 384 bytes

void FUN_801b5db8(uint param_1)

{
  short sVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  short *psVar7;
  
  psVar7 = *(short **)(param_1 + 0x4c);
  pcVar6 = *(char **)(param_1 + 0xb8);
  FUN_8002fb40((double)*(float *)(pcVar6 + 4),(double)FLOAT_803dc074);
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + *(float *)(pcVar6 + 8);
  fVar2 = FLOAT_803e566c;
  if (*(float *)(pcVar6 + 8) != FLOAT_803e566c) {
    *(float *)(pcVar6 + 8) = *(float *)(pcVar6 + 8) * FLOAT_803e5670;
    if (*(float *)(pcVar6 + 8) < fVar2) {
      fVar2 = *(float *)(pcVar6 + 8);
    }
    *(float *)(pcVar6 + 8) = fVar2;
  }
  if ((('\0' < *pcVar6) || (*psVar7 != 0x338)) || (*(float *)(param_1 + 0x98) <= FLOAT_803e5674)) {
    bVar3 = false;
    iVar5 = 0;
    iVar4 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
    if (0 < iVar4) {
      do {
        sVar1 = *(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x46);
        if ((sVar1 == 399) || (sVar1 == 0x1d6)) {
          bVar3 = true;
          break;
        }
        iVar5 = iVar5 + 4;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    if (bVar3) {
      *(float *)(pcVar6 + 4) = FLOAT_803e5678;
      *(float *)(pcVar6 + 8) = FLOAT_803e567c;
      *pcVar6 = '\0';
      FUN_800201ac((int)psVar7[0xf],1);
      FUN_8000bb38(param_1,0x3e1);
    }
  }
  else {
    iVar4 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -0x10;
    if (iVar4 < 0) {
      iVar4 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(char *)(param_1 + 0x36) = (char)iVar4;
  }
  return;
}

