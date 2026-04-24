// Function: FUN_8005f35c
// Entry: 8005f35c
// Size: 888 bytes

void FUN_8005f35c(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 local_48;
  float afStack_44 [13];
  
  local_48 = DAT_803df830;
  if ((*(char *)(param_1 + 0x41) == '\x02') &&
     (iVar1 = FUN_8004c3cc(param_1,1), (*(byte *)(iVar1 + 4) & 0x7f) == 9)) {
    piVar2 = (int *)FUN_8004c3cc(param_1,0);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar6 = 0x50;
      piVar5 = DAT_803ddaec;
      do {
        if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
          iVar1 = FUN_80054dac(iVar1,DAT_803ddaec[iVar3 * 4 + 1]);
          break;
        }
        piVar5 = piVar5 + 4;
        iVar3 = iVar3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      FUN_80247a48((double)(*(float *)(DAT_803ddae8 + iVar3) / FLOAT_803df848),
                   (double)(*(float *)(DAT_803ddae8 + iVar3 + 4) / FLOAT_803df848),
                   (double)FLOAT_803df84c,afStack_44);
      pfVar4 = afStack_44;
    }
    FUN_80051c7c(iVar1,pfVar4,0,(char *)&local_48);
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      FUN_8004daa4();
    }
    piVar2 = (int *)FUN_8004c3cc(param_1,1);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar6 = 0x50;
      piVar5 = DAT_803ddaec;
      do {
        if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
          iVar1 = FUN_80054dac(iVar1,DAT_803ddaec[iVar3 * 4 + 1]);
          break;
        }
        piVar5 = piVar5 + 4;
        iVar3 = iVar3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      FUN_80247a48((double)(*(float *)(DAT_803ddae8 + iVar3) / FLOAT_803df848),
                   (double)(*(float *)(DAT_803ddae8 + iVar3 + 4) / FLOAT_803df848),
                   (double)FLOAT_803df84c,afStack_44);
      pfVar4 = afStack_44;
    }
    FUN_800519e4(iVar1,pfVar4,9);
    FUN_80052668((char *)&local_48);
  }
  else {
    for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_1 + 0x41); iVar1 = iVar1 + 1) {
      piVar2 = (int *)FUN_8004c3cc(param_1,iVar1);
      iVar3 = *piVar2;
      if (iVar3 == 0) {
        FUN_8005254c();
      }
      else {
        if (*(char *)((int)piVar2 + 5) != '\0') {
          iVar6 = 0;
          iVar7 = 0x50;
          piVar5 = DAT_803ddaec;
          do {
            if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar3)) &&
               (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
              iVar3 = FUN_80054dac(iVar3,DAT_803ddaec[iVar6 * 4 + 1]);
              break;
            }
            piVar5 = piVar5 + 4;
            iVar6 = iVar6 + 1;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
        }
        if (*(byte *)((int)piVar2 + 6) == 0xff) {
          pfVar4 = (float *)0x0;
        }
        else {
          pfVar4 = (float *)(DAT_803ddae8 + (uint)*(byte *)((int)piVar2 + 6) * 0x10);
          FUN_80247a48((double)(*pfVar4 / FLOAT_803df848),(double)(pfVar4[1] / FLOAT_803df848),
                       (double)FLOAT_803df84c,afStack_44);
          pfVar4 = afStack_44;
        }
        if ((*(uint *)(param_1 + 0x3c) & 0x40000) == 0) {
          FUN_800519e4(iVar3,pfVar4,*(byte *)(piVar2 + 1) & 0x7f);
        }
        else {
          FUN_800516a4(iVar3,pfVar4);
        }
      }
    }
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      FUN_8004daa4();
    }
  }
  return;
}

