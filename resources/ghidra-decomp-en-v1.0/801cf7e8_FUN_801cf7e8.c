// Function: FUN_801cf7e8
// Entry: 801cf7e8
// Size: 796 bytes

/* WARNING: Removing unreachable block (ram,0x801cf858) */
/* WARNING: Removing unreachable block (ram,0x801cfae4) */

void FUN_801cf7e8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  char cVar7;
  int iVar5;
  byte *pbVar6;
  undefined4 *puVar8;
  char *pcVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  int local_38;
  undefined4 local_34 [11];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860d8();
  pcVar9 = *(char **)(iVar1 + 0xb8);
  iVar1 = FUN_8002b9ac();
  iVar2 = FUN_8002b9ec();
  local_34[0] = DAT_802c23e8;
  local_34[1] = DAT_802c23ec;
  local_34[2] = DAT_802c23f0;
  if (iVar1 != 0) {
    if (*pcVar9 == '\x01') {
      if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + FLOAT_803db414;
      }
      iVar1 = FUN_8001ffb4(0x4e3);
      if ((iVar1 == 1) && (pbVar6 = (byte *)(**(code **)(*DAT_803dcaac + 0x94))(), 3 < *pbVar6)) {
        FUN_800200e8(0x4e3,0xff);
      }
      if (FLOAT_803e5268 <= *(float *)(pcVar9 + 4)) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - FLOAT_803e5268;
        iVar1 = FUN_8001ffb4(0x4e3);
        if ((iVar1 == 0xff) && (pbVar6 = (byte *)(**(code **)(*DAT_803dcaac + 0x94))(), *pbVar6 < 4)
           ) {
          FUN_800200e8(0x4e3,1);
        }
      }
    }
    else if (*pcVar9 == '\0') {
      iVar3 = FUN_8001ffb4(0xd11);
      if (iVar3 == 0) {
        iVar3 = FUN_8001ffb4(0x544);
        if (iVar3 != 0) {
          cVar7 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x40))(iVar1);
          if (cVar7 == '\0') {
            FUN_800200e8(0x4e4,0);
            *(float *)(pcVar9 + 4) = FLOAT_803e5260;
          }
          iVar3 = 0;
          puVar8 = local_34;
          dVar12 = (double)FLOAT_803e5260;
          do {
            iVar5 = FUN_8002e0b4(*puVar8);
            if ((iVar5 != 0) && (dVar11 = (double)FUN_8014c5d0(), dVar12 < dVar11)) {
              (**(code **)(**(int **)(iVar1 + 0x68) + 0x34))(iVar1,1,iVar5);
              break;
            }
            puVar8 = puVar8 + 1;
            iVar3 = iVar3 + 1;
          } while (iVar3 < 3);
          *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + FLOAT_803db414;
          if (FLOAT_803e5264 <= *(float *)(pcVar9 + 4)) {
            *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - FLOAT_803e5264;
            FUN_80138920(iVar1,0x152,0x1000);
          }
        }
        piVar4 = (int *)FUN_80036f50(3,&local_38);
        for (iVar3 = 0; iVar3 < local_38; iVar3 = iVar3 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            dVar12 = (double)FUN_800216d0(*piVar4 + 0x18,iVar2 + 0x18);
            dVar11 = (double)FUN_800216d0(*piVar4 + 0x18,iVar1 + 0x18);
            if (dVar12 <= dVar11) {
              FUN_8014c66c(*piVar4,iVar2);
            }
            else {
              FUN_8014c66c(*piVar4,iVar1);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      else {
        piVar4 = (int *)FUN_80036f50(3,&local_38);
        for (iVar1 = 0; iVar1 < local_38; iVar1 = iVar1 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            FUN_8014c66c(*piVar4,iVar2);
          }
          piVar4 = piVar4 + 1;
        }
        FUN_800200e8(0x4e4,1);
        *pcVar9 = '\x01';
      }
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286124();
  return;
}

