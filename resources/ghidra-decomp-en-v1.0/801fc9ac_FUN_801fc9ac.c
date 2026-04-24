// Function: FUN_801fc9ac
// Entry: 801fc9ac
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x801fca58) */

void FUN_801fc9ac(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  double dVar5;
  
  iVar2 = FUN_8002b9ec();
  pfVar4 = *(float **)(param_1 + 0xb8);
  if (*(short *)((int)pfVar4 + 6) != -1) {
    if (*(char *)((int)pfVar4 + 0xd) != '\0') {
      iVar2 = FUN_8001ffb4();
      if (iVar2 != 0) {
        return;
      }
      FUN_800200e8((int)*(short *)((int)pfVar4 + 6),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
    iVar3 = FUN_8001ffb4();
    if (iVar3 != 0) {
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
  }
  if (*(char *)((int)pfVar4 + 0xd) == '\0') {
    bVar1 = *(byte *)((int)pfVar4 + 0xe);
    if (bVar1 == 3) {
      dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
      if (((dVar5 < (double)*pfVar4) && (*(short *)(pfVar4 + 1) != -1)) &&
         (iVar2 = FUN_8001ffb4(), iVar2 == 0)) {
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
        FUN_800200e8((int)*(short *)(pfVar4 + 1),1);
        *(undefined *)((int)pfVar4 + 0xd) = 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if ((*(short *)(pfVar4 + 1) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else if (bVar1 == 0) {
        dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
        if (dVar5 < (double)*pfVar4) {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else {
        dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
        if (((dVar5 < (double)*pfVar4) && (*(short *)(pfVar4 + 1) != -1)) &&
           (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
    }
    else if (bVar1 == 5) {
      if ((*(short *)(pfVar4 + 1) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      }
    }
    else if (((bVar1 < 5) && (*(short *)(pfVar4 + 1) != -1)) && (iVar2 = FUN_8001ffb4(), iVar2 == 0)
            ) {
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      FUN_800200e8((int)*(short *)(pfVar4 + 1),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
    }
  }
  return;
}

