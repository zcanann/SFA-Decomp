// Function: FUN_8005f1e0
// Entry: 8005f1e0
// Size: 888 bytes

void FUN_8005f1e0(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  undefined *puVar4;
  float *pfVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  undefined4 local_48;
  undefined auStack68 [52];
  
  local_48 = DAT_803debb0;
  if ((*(char *)(param_1 + 0x41) == '\x02') &&
     (iVar1 = FUN_8004c250(param_1,1), (*(byte *)(iVar1 + 4) & 0x7f) == 9)) {
    piVar2 = (int *)FUN_8004c250(param_1,0);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar7 = 0x50;
      piVar6 = DAT_803dce6c;
      do {
        if (((0 < *(short *)(piVar6 + 3)) && (*piVar6 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar6 + 0xe))) {
          iVar1 = FUN_80054c30(iVar1,DAT_803dce6c[iVar3 * 4 + 1]);
          break;
        }
        piVar6 = piVar6 + 4;
        iVar3 = iVar3 + 1;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      puVar4 = (undefined *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      FUN_802472e4((double)(*(float *)(DAT_803dce68 + iVar3) / FLOAT_803debc8),
                   (double)(*(float *)(DAT_803dce68 + iVar3 + 4) / FLOAT_803debc8),
                   (double)FLOAT_803debcc,auStack68);
      puVar4 = auStack68;
    }
    FUN_80051b00(iVar1,puVar4,0,&local_48);
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      FUN_8004d928();
    }
    piVar2 = (int *)FUN_8004c250(param_1,1);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar7 = 0x50;
      piVar6 = DAT_803dce6c;
      do {
        if (((0 < *(short *)(piVar6 + 3)) && (*piVar6 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar6 + 0xe))) {
          iVar1 = FUN_80054c30(iVar1,DAT_803dce6c[iVar3 * 4 + 1]);
          break;
        }
        piVar6 = piVar6 + 4;
        iVar3 = iVar3 + 1;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      puVar4 = (undefined *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      FUN_802472e4((double)(*(float *)(DAT_803dce68 + iVar3) / FLOAT_803debc8),
                   (double)(*(float *)(DAT_803dce68 + iVar3 + 4) / FLOAT_803debc8),
                   (double)FLOAT_803debcc,auStack68);
      puVar4 = auStack68;
    }
    FUN_80051868(iVar1,puVar4,9);
    FUN_800524ec(&local_48);
  }
  else {
    for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_1 + 0x41); iVar1 = iVar1 + 1) {
      piVar2 = (int *)FUN_8004c250(param_1,iVar1);
      iVar3 = *piVar2;
      if (iVar3 == 0) {
        FUN_800523d0();
      }
      else {
        if (*(char *)((int)piVar2 + 5) != '\0') {
          iVar7 = 0;
          iVar8 = 0x50;
          piVar6 = DAT_803dce6c;
          do {
            if (((0 < *(short *)(piVar6 + 3)) && (*piVar6 == iVar3)) &&
               (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar6 + 0xe))) {
              iVar3 = FUN_80054c30(iVar3,DAT_803dce6c[iVar7 * 4 + 1]);
              break;
            }
            piVar6 = piVar6 + 4;
            iVar7 = iVar7 + 1;
            iVar8 = iVar8 + -1;
          } while (iVar8 != 0);
        }
        if (*(byte *)((int)piVar2 + 6) == 0xff) {
          puVar4 = (undefined *)0x0;
        }
        else {
          pfVar5 = (float *)(DAT_803dce68 + (uint)*(byte *)((int)piVar2 + 6) * 0x10);
          FUN_802472e4((double)(*pfVar5 / FLOAT_803debc8),(double)(pfVar5[1] / FLOAT_803debc8),
                       (double)FLOAT_803debcc,auStack68);
          puVar4 = auStack68;
        }
        if ((*(uint *)(param_1 + 0x3c) & 0x40000) == 0) {
          FUN_80051868(iVar3,puVar4,*(byte *)(piVar2 + 1) & 0x7f);
        }
        else {
          FUN_80051528(iVar3);
        }
      }
    }
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      FUN_8004d928();
    }
  }
  return;
}

