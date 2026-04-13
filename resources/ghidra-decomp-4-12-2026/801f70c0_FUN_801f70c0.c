// Function: FUN_801f70c0
// Entry: 801f70c0
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x801f7168) */

void FUN_801f70c0(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  uint *puVar6;
  float *pfVar7;
  double dVar8;
  
  iVar1 = FUN_80286840();
  iVar2 = FUN_8002bac4();
  pfVar7 = *(float **)(iVar1 + 0xb8);
  uVar3 = (uint)*(short *)((int)pfVar7 + 6);
  if (uVar3 != 0xffffffff) {
    if (*(char *)((int)pfVar7 + 0xd) != '\0') {
      uVar3 = FUN_80020078(uVar3);
      if (uVar3 == 0) {
        FUN_800201ac((int)*(short *)((int)pfVar7 + 6),1);
        *(undefined *)((int)pfVar7 + 0xd) = 1;
      }
      goto LAB_801f7420;
    }
    uVar3 = FUN_80020078(uVar3);
    if (uVar3 != 0) {
      *(undefined *)((int)pfVar7 + 0xd) = 1;
      goto LAB_801f7420;
    }
  }
  if (*(char *)((int)pfVar7 + 0xd) == '\0') {
    bVar5 = *(byte *)((int)pfVar7 + 0xe);
    if (bVar5 == 3) {
      dVar8 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
      if (((dVar8 < (double)*pfVar7) && ((int)*(short *)(pfVar7 + 1) != 0xffffffff)) &&
         (uVar3 = FUN_80020078((int)*(short *)(pfVar7 + 1)), uVar3 == 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar7 + 2),iVar1,0xffffffff);
        FUN_800201ac((int)*(short *)(pfVar7 + 1),1);
        *(undefined *)((int)pfVar7 + 0xd) = 1;
      }
    }
    else if (bVar5 < 3) {
      if (bVar5 == 1) {
        if (((int)*(short *)(pfVar7 + 1) != 0xffffffff) &&
           (uVar3 = FUN_80020078((int)*(short *)(pfVar7 + 1)), uVar3 != 0)) {
          if (*(short *)(pfVar7 + 2) == 0x22) {
            iVar2 = 0;
            puVar6 = &DAT_80329908;
            do {
              FUN_800201ac(*puVar6,0);
              iVar4 = FUN_8002e1ac(puVar6[1]);
              *(undefined *)(*(int *)(iVar4 + 0xb8) + 0xd) = 0;
              if (*(short *)(iVar4 + 0xb4) != -1) {
                (**(code **)(*DAT_803dd6d4 + 0x4c))();
              }
              puVar6 = puVar6 + 2;
              iVar2 = iVar2 + 1;
            } while (iVar2 < 5);
          }
          else if (*(short *)(pfVar7 + 2) == 1) {
            bVar5 = FUN_80089094(0);
            *(byte *)((int)pfVar7 + 0xf) = bVar5;
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar7 + 2),iVar1,0xffffffff);
          *(undefined *)((int)pfVar7 + 0xd) = 1;
        }
      }
      else if (bVar5 == 0) {
        dVar8 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
        if (dVar8 < (double)*pfVar7) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar7 + 2),iVar1,0xffffffff);
          *(undefined *)((int)pfVar7 + 0xd) = 1;
        }
      }
      else {
        dVar8 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
        if (((dVar8 < (double)*pfVar7) && ((int)*(short *)(pfVar7 + 1) != 0xffffffff)) &&
           (uVar3 = FUN_80020078((int)*(short *)(pfVar7 + 1)), uVar3 != 0)) {
          if (*(short *)(pfVar7 + 2) == 0x21) {
            FUN_800201ac(0xd1b,0);
            iVar2 = FUN_8002e1ac(0x4aeb1);
            *(undefined *)(*(int *)(iVar2 + 0xb8) + 0xd) = 0;
            if (*(short *)(iVar2 + 0xb4) != -1) {
              (**(code **)(*DAT_803dd6d4 + 0x4c))();
            }
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar7 + 2),iVar1,0xffffffff);
          *(undefined *)((int)pfVar7 + 0xd) = 1;
        }
      }
    }
    else if (bVar5 == 5) {
      if (((int)*(short *)(pfVar7 + 1) != 0xffffffff) &&
         (uVar3 = FUN_80020078((int)*(short *)(pfVar7 + 1)), uVar3 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar7 + 2),iVar1,0xffffffff);
      }
    }
    else if (((bVar5 < 5) && ((int)*(short *)(pfVar7 + 1) != 0xffffffff)) &&
            (uVar3 = FUN_80020078((int)*(short *)(pfVar7 + 1)), uVar3 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar7 + 2),iVar1,0xffffffff);
      FUN_800201ac((int)*(short *)(pfVar7 + 1),1);
      *(undefined *)((int)pfVar7 + 0xd) = 1;
    }
  }
LAB_801f7420:
  FUN_8028688c();
  return;
}

