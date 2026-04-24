// Function: FUN_801f6a88
// Entry: 801f6a88
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x801f6b30) */

void FUN_801f6a88(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  undefined4 *puVar6;
  float *pfVar7;
  double dVar8;
  
  iVar2 = FUN_802860dc();
  iVar3 = FUN_8002b9ec();
  pfVar7 = *(float **)(iVar2 + 0xb8);
  if (*(short *)((int)pfVar7 + 6) != -1) {
    if (*(char *)((int)pfVar7 + 0xd) != '\0') {
      iVar2 = FUN_8001ffb4();
      if (iVar2 == 0) {
        FUN_800200e8((int)*(short *)((int)pfVar7 + 6),1);
        *(undefined *)((int)pfVar7 + 0xd) = 1;
      }
      goto LAB_801f6de8;
    }
    iVar4 = FUN_8001ffb4();
    if (iVar4 != 0) {
      *(undefined *)((int)pfVar7 + 0xd) = 1;
      goto LAB_801f6de8;
    }
  }
  if (*(char *)((int)pfVar7 + 0xd) == '\0') {
    bVar1 = *(byte *)((int)pfVar7 + 0xe);
    if (bVar1 == 3) {
      dVar8 = (double)FUN_80021704(iVar2 + 0x18,iVar3 + 0x18);
      if (((dVar8 < (double)*pfVar7) && (*(short *)(pfVar7 + 1) != -1)) &&
         (iVar3 = FUN_8001ffb4(), iVar3 == 0)) {
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar7 + 2),iVar2,0xffffffff);
        FUN_800200e8((int)*(short *)(pfVar7 + 1),1);
        *(undefined *)((int)pfVar7 + 0xd) = 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if ((*(short *)(pfVar7 + 1) != -1) && (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
          if (*(short *)(pfVar7 + 2) == 0x22) {
            iVar3 = 0;
            puVar6 = &DAT_80328cc8;
            do {
              FUN_800200e8(*puVar6,0);
              iVar4 = FUN_8002e0b4(puVar6[1]);
              *(undefined *)(*(int *)(iVar4 + 0xb8) + 0xd) = 0;
              if (*(short *)(iVar4 + 0xb4) != -1) {
                (**(code **)(*DAT_803dca54 + 0x4c))();
              }
              puVar6 = puVar6 + 2;
              iVar3 = iVar3 + 1;
            } while (iVar3 < 5);
          }
          else if (*(short *)(pfVar7 + 2) == 1) {
            uVar5 = FUN_80088e08(0);
            *(undefined *)((int)pfVar7 + 0xf) = uVar5;
          }
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar7 + 2),iVar2,0xffffffff);
          *(undefined *)((int)pfVar7 + 0xd) = 1;
        }
      }
      else if (bVar1 == 0) {
        dVar8 = (double)FUN_80021704(iVar2 + 0x18,iVar3 + 0x18);
        if (dVar8 < (double)*pfVar7) {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar7 + 2),iVar2,0xffffffff);
          *(undefined *)((int)pfVar7 + 0xd) = 1;
        }
      }
      else {
        dVar8 = (double)FUN_80021704(iVar2 + 0x18,iVar3 + 0x18);
        if (((dVar8 < (double)*pfVar7) && (*(short *)(pfVar7 + 1) != -1)) &&
           (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
          if (*(short *)(pfVar7 + 2) == 0x21) {
            FUN_800200e8(0xd1b,0);
            iVar3 = FUN_8002e0b4(0x4aeb1);
            *(undefined *)(*(int *)(iVar3 + 0xb8) + 0xd) = 0;
            if (*(short *)(iVar3 + 0xb4) != -1) {
              (**(code **)(*DAT_803dca54 + 0x4c))();
            }
          }
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar7 + 2),iVar2,0xffffffff);
          *(undefined *)((int)pfVar7 + 0xd) = 1;
        }
      }
    }
    else if (bVar1 == 5) {
      if ((*(short *)(pfVar7 + 1) != -1) && (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar7 + 2),iVar2,0xffffffff);
      }
    }
    else if (((bVar1 < 5) && (*(short *)(pfVar7 + 1) != -1)) && (iVar3 = FUN_8001ffb4(), iVar3 == 0)
            ) {
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(short *)(pfVar7 + 2),iVar2,0xffffffff);
      FUN_800200e8((int)*(short *)(pfVar7 + 1),1);
      *(undefined *)((int)pfVar7 + 0xd) = 1;
    }
  }
LAB_801f6de8:
  FUN_80286128();
  return;
}

