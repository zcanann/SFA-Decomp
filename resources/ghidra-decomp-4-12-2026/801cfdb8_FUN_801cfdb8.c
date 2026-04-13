// Function: FUN_801cfdb8
// Entry: 801cfdb8
// Size: 796 bytes

/* WARNING: Removing unreachable block (ram,0x801d00b4) */
/* WARNING: Removing unreachable block (ram,0x801cfe28) */
/* WARNING: Removing unreachable block (ram,0x801cfdc8) */

void FUN_801cfdb8(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  char cVar7;
  int iVar5;
  byte *pbVar6;
  int iVar8;
  char *pcVar9;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  int local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar1 = FUN_8028683c();
  pcVar9 = *(char **)(iVar1 + 0xb8);
  iVar1 = FUN_8002ba84();
  iVar2 = FUN_8002bac4();
  local_34[0] = DAT_802c2b68;
  local_34[1] = DAT_802c2b6c;
  local_34[2] = DAT_802c2b70;
  if (iVar1 != 0) {
    if (*pcVar9 == '\x01') {
      if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + FLOAT_803dc074;
      }
      uVar3 = FUN_80020078(0x4e3);
      if ((uVar3 == 1) && (pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))(), 3 < *pbVar6)) {
        FUN_800201ac(0x4e3,0xff);
      }
      if (FLOAT_803e5f00 <= *(float *)(pcVar9 + 4)) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - FLOAT_803e5f00;
        uVar3 = FUN_80020078(0x4e3);
        if ((uVar3 == 0xff) && (pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))(), *pbVar6 < 4)
           ) {
          FUN_800201ac(0x4e3,1);
        }
      }
    }
    else if (*pcVar9 == '\0') {
      uVar3 = FUN_80020078(0xd11);
      if (uVar3 == 0) {
        uVar3 = FUN_80020078(0x544);
        if (uVar3 != 0) {
          cVar7 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x40))(iVar1);
          if (cVar7 == '\0') {
            FUN_800201ac(0x4e4,0);
            *(float *)(pcVar9 + 4) = FLOAT_803e5ef8;
          }
          iVar8 = 0;
          piVar4 = local_34;
          dVar11 = (double)FLOAT_803e5ef8;
          do {
            iVar5 = FUN_8002e1ac(*piVar4);
            if ((iVar5 != 0) && (dVar10 = FUN_8014ca48(iVar5), dVar11 < dVar10)) {
              (**(code **)(**(int **)(iVar1 + 0x68) + 0x34))(iVar1,1,iVar5);
              break;
            }
            piVar4 = piVar4 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 3);
          *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + FLOAT_803dc074;
          if (FLOAT_803e5efc <= *(float *)(pcVar9 + 4)) {
            *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - FLOAT_803e5efc;
            FUN_80138ca8(iVar1,0x152,0x1000);
          }
        }
        piVar4 = FUN_80037048(3,&local_38);
        for (iVar8 = 0; iVar8 < local_38; iVar8 = iVar8 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            dVar11 = FUN_80021794((float *)(*piVar4 + 0x18),(float *)(iVar2 + 0x18));
            dVar10 = FUN_80021794((float *)(*piVar4 + 0x18),(float *)(iVar1 + 0x18));
            if (dVar11 <= dVar10) {
              FUN_8014cae4(*piVar4,iVar2);
            }
            else {
              FUN_8014cae4(*piVar4,iVar1);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      else {
        piVar4 = FUN_80037048(3,&local_38);
        for (iVar1 = 0; iVar1 < local_38; iVar1 = iVar1 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            FUN_8014cae4(*piVar4,iVar2);
          }
          piVar4 = piVar4 + 1;
        }
        FUN_800201ac(0x4e4,1);
        *pcVar9 = '\x01';
      }
    }
  }
  FUN_80286888();
  return;
}

