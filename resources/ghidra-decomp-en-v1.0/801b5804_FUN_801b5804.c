// Function: FUN_801b5804
// Entry: 801b5804
// Size: 384 bytes

void FUN_801b5804(int param_1)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  bool bVar5;
  char *pcVar6;
  short *psVar7;
  
  psVar7 = *(short **)(param_1 + 0x4c);
  pcVar6 = *(char **)(param_1 + 0xb8);
  FUN_8002fa48((double)*(float *)(pcVar6 + 4),(double)FLOAT_803db414,param_1,0);
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + *(float *)(pcVar6 + 8);
  fVar2 = FLOAT_803e49d4;
  if (*(float *)(pcVar6 + 8) != FLOAT_803e49d4) {
    *(float *)(pcVar6 + 8) = *(float *)(pcVar6 + 8) * FLOAT_803e49d8;
    if (*(float *)(pcVar6 + 8) < fVar2) {
      fVar2 = *(float *)(pcVar6 + 8);
    }
    *(float *)(pcVar6 + 8) = fVar2;
  }
  if ((('\0' < *pcVar6) || (*psVar7 != 0x338)) || (*(float *)(param_1 + 0x98) <= FLOAT_803e49dc)) {
    bVar5 = false;
    iVar4 = 0;
    iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
    if (0 < iVar3) {
      do {
        sVar1 = *(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar4 + 0x100) + 0x46);
        if ((sVar1 == 399) || (sVar1 == 0x1d6)) {
          bVar5 = true;
          break;
        }
        iVar4 = iVar4 + 4;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (bVar5) {
      *(float *)(pcVar6 + 4) = FLOAT_803e49e0;
      *(float *)(pcVar6 + 8) = FLOAT_803e49e4;
      *pcVar6 = '\0';
      FUN_800200e8((int)psVar7[0xf],1);
      FUN_8000bb18(param_1,0x3e1);
    }
  }
  else {
    iVar3 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -0x10;
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(char *)(param_1 + 0x36) = (char)iVar3;
  }
  return;
}

