// Function: FUN_8017082c
// Entry: 8017082c
// Size: 1788 bytes

/* WARNING: Removing unreachable block (ram,0x80170f08) */
/* WARNING: Removing unreachable block (ram,0x80170f00) */
/* WARNING: Removing unreachable block (ram,0x80170ef8) */
/* WARNING: Removing unreachable block (ram,0x80170ef0) */
/* WARNING: Removing unreachable block (ram,0x80170854) */
/* WARNING: Removing unreachable block (ram,0x8017084c) */
/* WARNING: Removing unreachable block (ram,0x80170844) */
/* WARNING: Removing unreachable block (ram,0x8017083c) */

void FUN_8017082c(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 uVar15;
  undefined8 local_78;
  undefined8 local_70;
  
  uVar15 = FUN_80286838();
  uVar2 = (uint)((ulonglong)uVar15 >> 0x20);
  pfVar9 = (float *)&DAT_80321678;
  piVar7 = *(int **)(uVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
  iVar6 = 0;
  if (iVar3 != 0) {
    iVar6 = FUN_80296e2c(iVar3);
  }
  fVar1 = FLOAT_803e4064;
  switch((uint)uVar15 & 0xff) {
  case 0:
    if (*piVar7 != 0) {
      FUN_8001dc30((double)FLOAT_803e4040,*piVar7,'\0');
    }
    fVar1 = FLOAT_803e4048;
    if (FLOAT_803e4044 != (float)piVar7[2]) {
      piVar7[4] = (int)FLOAT_803e4048;
      piVar7[1] = (int)fVar1;
      if (iVar6 != 0) {
        FUN_8016de98(iVar6,7,0);
      }
    }
    piVar7[2] = (int)FLOAT_803e4044;
    piVar7[3] = (int)FLOAT_803e404c;
    FUN_8000b844(uVar2,0x42c);
    FUN_8000b844(uVar2,0x42d);
    break;
  case 1:
    if (FLOAT_803e4044 == (float)piVar7[2]) {
      if (iVar6 != 0) {
        FUN_8016de98(iVar6,7,8);
      }
      if (*piVar7 == 0) {
        piVar4 = FUN_8001f58c(0,'\x01');
        *piVar7 = (int)piVar4;
      }
      if (*piVar7 != 0) {
        FUN_8001dbf0(*piVar7,2);
        FUN_8001de4c((double)*(float *)(uVar2 + 0xc),
                     (double)(*(float *)(uVar2 + 0x10) - FLOAT_803e4050),
                     (double)*(float *)(uVar2 + 0x14),(int *)*piVar7);
        FUN_8001dbb4(*piVar7,0,0xff,0xff,0xff);
        FUN_8001dadc(*piVar7,0,0xff,0xff,0xff);
        FUN_8001dcfc((double)FLOAT_803e4054,(double)FLOAT_803e4058,*piVar7);
        FUN_8001dc18(*piVar7,1);
        FUN_8001dc30((double)FLOAT_803e4044,*piVar7,'\x01');
        FUN_8001d6e4(*piVar7,0,0);
        FUN_8001de04(*piVar7,1);
      }
      fVar1 = FLOAT_803e4044;
      if (FLOAT_803e4044 == (float)piVar7[2]) {
        piVar7[4] = (int)FLOAT_803e4048;
        piVar7[1] = (int)fVar1;
      }
      piVar7[2] = (int)FLOAT_803e4048;
      dVar12 = (double)FLOAT_803e405c;
      piVar7[3] = (int)FLOAT_803e405c;
      iVar3 = 0;
      piVar8 = &DAT_80321688;
      dVar11 = (double)FLOAT_803e4040;
      dVar14 = (double)FLOAT_803e4060;
      piVar4 = piVar7;
      dVar13 = DOUBLE_803e4068;
      do {
        *(undefined2 *)(piVar4 + 0xd) = 0xc000;
        dVar10 = (double)FUN_80293a9c();
        piVar7[9] = (int)(*pfVar9 * (float)((double)(float)(dVar12 + dVar10) * dVar11));
        piVar7[5] = *piVar8;
        uVar5 = FUN_80022264(0x78,0x7f);
        local_78 = (double)CONCAT44(0x43300000,iVar3 * uVar5 ^ 0x80000000);
        *(short *)(piVar4 + 0xf) = (short)(int)(dVar14 + (double)(float)(local_78 - dVar13));
        piVar4 = (int *)((int)piVar4 + 2);
        pfVar9 = pfVar9 + 1;
        piVar7 = piVar7 + 1;
        piVar8 = piVar8 + 1;
        iVar3 = iVar3 + 1;
      } while (iVar3 < 4);
      FUN_8000bb38(uVar2,0x42c);
      FUN_8000bb38(uVar2,0x42d);
    }
    break;
  case 2:
    if (iVar6 != 0) {
      FUN_8016de98(iVar6,7,0);
    }
    if (FLOAT_803e4044 != (float)piVar7[2]) {
      piVar7[4] = (int)FLOAT_803e4064;
    }
    piVar7[2] = (int)FLOAT_803e4044;
    piVar7[3] = (int)FLOAT_803e404c;
    if (*piVar7 != 0) {
      FUN_8001dc30((double)FLOAT_803e4040,*piVar7,'\0');
    }
    FUN_8000b844(uVar2,0x42c);
    FUN_8000b844(uVar2,0x42d);
    break;
  case 3:
    if (iVar6 != 0) {
      FUN_8016de98(iVar6,7,8);
    }
    if (*piVar7 == 0) {
      piVar4 = FUN_8001f58c(0,'\x01');
      *piVar7 = (int)piVar4;
    }
    if (*piVar7 != 0) {
      FUN_8001dbf0(*piVar7,2);
      FUN_8001de4c((double)*(float *)(uVar2 + 0xc),
                   (double)(*(float *)(uVar2 + 0x10) - FLOAT_803e4050),
                   (double)*(float *)(uVar2 + 0x14),(int *)*piVar7);
      FUN_8001dbb4(*piVar7,0,0xff,0xff,0xff);
      FUN_8001dadc(*piVar7,0,0xff,0xff,0xff);
      FUN_8001dcfc((double)FLOAT_803e4054,(double)FLOAT_803e4058,*piVar7);
      FUN_8001dc18(*piVar7,1);
      FUN_8001dc30((double)FLOAT_803e4044,*piVar7,'\x01');
      FUN_8001d6e4(*piVar7,0,0);
      FUN_8001de04(*piVar7,1);
    }
    if (FLOAT_803e4044 == (float)piVar7[2]) {
      piVar7[4] = (int)FLOAT_803e4064;
    }
    piVar7[2] = (int)FLOAT_803e4064;
    dVar14 = (double)FLOAT_803e405c;
    piVar7[3] = (int)FLOAT_803e405c;
    iVar3 = 0;
    piVar8 = &DAT_80321688;
    dVar13 = (double)FLOAT_803e4040;
    piVar4 = piVar7;
    do {
      *(undefined2 *)(piVar7 + 0xd) = 0;
      dVar11 = (double)FUN_80293a9c();
      piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar14 + dVar11) * dVar13));
      piVar4[5] = *piVar8;
      piVar7 = (int *)((int)piVar7 + 2);
      pfVar9 = pfVar9 + 1;
      piVar4 = piVar4 + 1;
      piVar8 = piVar8 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 4);
    FUN_8000bb38(uVar2,0x42d);
    FUN_8000bb38(uVar2,0x42c);
    break;
  case 4:
    piVar7[2] = (int)FLOAT_803e4064;
    dVar14 = (double)FLOAT_803e405c;
    piVar7[3] = (int)FLOAT_803e405c;
    piVar7[4] = (int)fVar1;
    iVar3 = 0;
    pfVar9 = (float *)&DAT_80321698;
    piVar8 = &DAT_803216a8;
    dVar11 = (double)FLOAT_803e4040;
    dVar12 = (double)FLOAT_803e4060;
    piVar4 = piVar7;
    dVar13 = DOUBLE_803e4068;
    do {
      *(undefined2 *)(piVar7 + 0xd) = 0xc000;
      dVar10 = (double)FUN_80293a9c();
      piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar14 + dVar10) * dVar11));
      piVar4[5] = *piVar8;
      uVar5 = FUN_80022264(0x78,0x7f);
      local_70 = (double)CONCAT44(0x43300000,iVar3 * uVar5 ^ 0x80000000);
      *(short *)(piVar7 + 0xf) = (short)(int)(dVar12 + (double)(float)(local_70 - dVar13));
      piVar7 = (int *)((int)piVar7 + 2);
      pfVar9 = pfVar9 + 1;
      piVar4 = piVar4 + 1;
      piVar8 = piVar8 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 4);
    FUN_8000bb38(uVar2,0x42d);
    FUN_8000bb38(uVar2,0x42c);
    break;
  case 5:
    piVar7[2] = (int)FLOAT_803e4044;
    piVar7[3] = (int)FLOAT_803e404c;
    piVar7[4] = (int)FLOAT_803e4064;
    FUN_8000b844(uVar2,0x42c);
    FUN_8000b844(uVar2,0x42d);
    break;
  case 6:
    iVar3 = 0;
    pfVar9 = (float *)&DAT_80321698;
    piVar8 = &DAT_803216a8;
    dVar13 = (double)FLOAT_803e405c;
    dVar14 = (double)FLOAT_803e4040;
    piVar4 = piVar7;
    do {
      *(undefined2 *)(piVar7 + 0xd) = 0x4000;
      dVar11 = (double)FUN_80293a9c();
      piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar13 + dVar11) * dVar14));
      piVar4[5] = *piVar8;
      piVar7 = (int *)((int)piVar7 + 2);
      pfVar9 = pfVar9 + 1;
      piVar4 = piVar4 + 1;
      piVar8 = piVar8 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 4);
    break;
  case 7:
    if (iVar6 != 0) {
      FUN_8016de98(iVar6,7,0);
    }
    if (*piVar7 != 0) {
      FUN_8001dc30((double)FLOAT_803e4040,*piVar7,'\0');
    }
    fVar1 = FLOAT_803e4044;
    piVar7[2] = (int)FLOAT_803e4044;
    piVar7[3] = (int)fVar1;
    piVar7[4] = (int)fVar1;
    piVar7[1] = (int)fVar1;
    *(byte *)(piVar7 + 0x17) = *(byte *)(piVar7 + 0x17) | 1;
    *(byte *)((int)piVar7 + 0x5d) = *(byte *)((int)piVar7 + 0x5d) | 1;
    *(byte *)((int)piVar7 + 0x5e) = *(byte *)((int)piVar7 + 0x5e) | 1;
    *(byte *)((int)piVar7 + 0x5f) = *(byte *)((int)piVar7 + 0x5f) | 1;
  }
  FUN_80286884();
  return;
}

