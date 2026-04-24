// Function: FUN_8009b648
// Entry: 8009b648
// Size: 792 bytes

undefined4 FUN_8009b648(short *param_1,undefined2 *param_2,short param_3,int param_4,int param_5)

{
  bool bVar1;
  short sVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  short *psVar6;
  uint *puVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  
  sVar2 = -1;
  bVar1 = false;
  iVar4 = 0;
  piVar8 = &DAT_8039c688;
  psVar6 = &DAT_80310488;
  pcVar3 = &DAT_8039c828;
  iVar9 = 0x10;
  pcVar5 = pcVar3;
  do {
    if (((param_5 == *piVar8) && (param_3 == *psVar6)) && (*pcVar5 < '\x19')) {
      sVar2 = (short)iVar4;
      bVar1 = true;
      break;
    }
    if (((param_5 == piVar8[1]) && (param_3 == psVar6[1])) && (pcVar5[1] < '\x19')) {
      sVar2 = (short)(iVar4 + 1);
      bVar1 = true;
      iVar4 = iVar4 + 1;
      break;
    }
    if (((param_5 == piVar8[2]) && (param_3 == psVar6[2])) && (pcVar5[2] < '\x19')) {
      sVar2 = (short)(iVar4 + 2);
      bVar1 = true;
      iVar4 = iVar4 + 2;
      break;
    }
    if (((param_5 == piVar8[3]) && (param_3 == psVar6[3])) && (pcVar5[3] < '\x19')) {
      sVar2 = (short)(iVar4 + 3);
      bVar1 = true;
      iVar4 = iVar4 + 3;
      break;
    }
    if (((param_5 == piVar8[4]) && (param_3 == psVar6[4])) && (pcVar5[4] < '\x19')) {
      sVar2 = (short)(iVar4 + 4);
      bVar1 = true;
      iVar4 = iVar4 + 4;
      break;
    }
    piVar8 = piVar8 + 5;
    psVar6 = psVar6 + 5;
    pcVar5 = pcVar5 + 5;
    iVar4 = iVar4 + 5;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  if (bVar1) {
    iVar9 = 0;
    puVar7 = &DAT_8039c878 + sVar2;
    iVar10 = 0x19;
    do {
      if ((1 << iVar9 & *puVar7) == 0) {
        *param_2 = (short)iVar9;
        *param_1 = sVar2;
        *puVar7 = *puVar7 | 1 << iVar9;
        (&DAT_8039c828)[sVar2] = (&DAT_8039c828)[sVar2] + '\x01';
        return 1;
      }
      iVar9 = iVar9 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  bVar1 = false;
  if (param_4 != -1) {
    if ((param_4 != -1) && (iVar4 = param_4, (char)(&DAT_8039c828)[param_4] < '\x19')) {
      sVar2 = (short)param_4;
      bVar1 = true;
    }
  }
  else {
    iVar4 = 0;
    iVar9 = 0x4f;
    do {
      if (*pcVar3 < '\x01') {
        sVar2 = (short)iVar4;
        bVar1 = true;
        (&DAT_8039c828)[iVar4] = 0;
        break;
      }
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  if (bVar1) {
    iVar9 = 0;
    puVar7 = &DAT_8039c878 + sVar2;
    iVar10 = 0x19;
    do {
      if ((1 << iVar9 & *puVar7) == 0) {
        *param_2 = (short)iVar9;
        *param_1 = sVar2;
        *puVar7 = *puVar7 | 1 << iVar9;
        (&DAT_80310488)[iVar4] = param_3;
        (&DAT_8039c828)[sVar2] = (&DAT_8039c828)[sVar2] + '\x01';
        return 1;
      }
      iVar9 = iVar9 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  return 0xffffffff;
}

