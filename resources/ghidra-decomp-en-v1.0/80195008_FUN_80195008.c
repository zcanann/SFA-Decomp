// Function: FUN_80195008
// Entry: 80195008
// Size: 4624 bytes

/* WARNING: Removing unreachable block (ram,0x801953d0) */

void FUN_80195008(void)

{
  byte bVar1;
  double dVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  ushort *puVar7;
  int iVar8;
  undefined uVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  double local_30;
  double local_28;
  
  iVar5 = FUN_802860d8();
  iVar12 = *(int *)(iVar5 + 0x4c);
  piVar11 = *(int **)(iVar5 + 0xb8);
  FUN_8005b2fc((double)*(float *)(iVar5 + 0xc),(double)*(float *)(iVar5 + 0x10),
               (double)*(float *)(iVar5 + 0x14));
  iVar6 = FUN_8005aeec();
  if (iVar6 == 0) {
    *(undefined *)((int)piVar11 + 0x4d) = 0;
    goto LAB_80196200;
  }
  if ((*(ushort *)(iVar6 + 4) & 8) == 0) goto LAB_80196200;
  if (piVar11[1] == 0) {
    for (iVar10 = 0; iVar10 < (int)(uint)*(ushort *)(iVar6 + 0x9a); iVar10 = iVar10 + 1) {
      puVar7 = (ushort *)FUN_800606ec(iVar6,iVar10);
      iVar8 = FUN_80060678();
      if (*(char *)(iVar12 + 0x28) == iVar8) {
        *piVar11 = *piVar11 + 1;
        piVar11[1] = piVar11[1] + ((uint)puVar7[10] - (uint)*puVar7);
      }
    }
    if (piVar11[1] == 0) goto LAB_80196200;
    piVar11[1] = piVar11[1] * 3;
    if (*(short *)(iVar12 + 0x18) == -1) {
      *(undefined *)(piVar11 + 0x13) = 1;
    }
    else {
      uVar9 = FUN_8001ffb4();
      *(undefined *)(piVar11 + 0x13) = uVar9;
    }
    piVar11[2] = (uint)*(byte *)(iVar6 + 0xa1);
    dVar2 = DOUBLE_803e4010;
    piVar11[0x10] =
         (int)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e4010);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x1e) ^ 0x80000000);
    piVar11[0x11] = (int)(float)(local_30 - dVar2);
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x20) ^ 0x80000000);
    piVar11[0x12] = (int)(float)(local_28 - dVar2);
    if ((*(short *)(iVar12 + 0x1a) != -1) &&
       (iVar10 = FUN_8001ffb4(), dVar2 = DOUBLE_803e4010, iVar10 != 0)) {
      local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x22) ^ 0x80000000);
      piVar11[0x10] = (int)(float)(local_28 - DOUBLE_803e4010);
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x24) ^ 0x80000000);
      piVar11[0x11] = (int)(float)(local_30 - dVar2);
      piVar11[0x12] =
           (int)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x26) ^ 0x80000000) -
                       dVar2);
      *(undefined *)(piVar11 + 0x13) = 1;
    }
    iVar8 = FUN_80023cc8(piVar11[1] * 6 + *piVar11 * 0xc + piVar11[2] * 0xc,5,0);
    piVar11[3] = iVar8;
    iVar10 = *piVar11 * 2;
    iVar8 = iVar8 + piVar11[1] * 6;
    piVar11[6] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[7] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[4] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[5] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[8] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[9] = iVar8;
    iVar8 = iVar8 + iVar10;
    iVar10 = piVar11[2] * 2;
    piVar11[10] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[0xb] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[0xc] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[0xd] = iVar8;
    iVar8 = iVar8 + iVar10;
    piVar11[0xe] = iVar8;
    piVar11[0xf] = iVar8 + iVar10;
    FUN_80194964(iVar12,piVar11,iVar6);
    if (*(char *)(iVar12 + 0x2c) != '\x04') {
      FUN_80194c40(iVar12,piVar11,iVar6);
      *(ushort *)(iVar6 + 4) = *(ushort *)(iVar6 + 4) ^ 1;
      FUN_80194c40(iVar12,piVar11,iVar6);
      *(ushort *)(iVar6 + 4) = *(ushort *)(iVar6 + 4) ^ 1;
    }
  }
  if (*(char *)(iVar12 + 0x2c) == '\x02') {
    iVar10 = FUN_8001ffb4((int)*(short *)(iVar12 + 0x18));
    if (*(char *)(piVar11 + 0x13) != iVar10) {
      *(char *)(piVar11 + 0x13) = (char)iVar10;
      if ((iVar10 == 0) && (-1 < *(short *)(iVar12 + 0x1a))) {
        FUN_800200e8((int)*(short *)(iVar12 + 0x1a),0);
      }
      if ('\x02' < *(char *)((int)piVar11 + 0x4d)) {
        *(undefined *)((int)piVar11 + 0x4d) = 0;
      }
    }
    if ('\x02' < *(char *)((int)piVar11 + 0x4d)) goto LAB_80196200;
    if (*(short *)((int)piVar11 + 0x4e) != 0) {
      FUN_8000da58(iVar5);
    }
  }
  else {
    if ('\x02' < *(char *)((int)piVar11 + 0x4d)) goto LAB_80196200;
    if (*(char *)(piVar11 + 0x13) == '\0') {
      uVar9 = FUN_8001ffb4((int)*(short *)(iVar12 + 0x18));
      *(undefined *)(piVar11 + 0x13) = uVar9;
      if (*(char *)(piVar11 + 0x13) == '\0') goto LAB_80196200;
    }
  }
  dVar2 = DOUBLE_803e4010;
  bVar1 = *(byte *)(iVar12 + 0x2c);
  if (bVar1 == 2) {
    iVar5 = 0;
    if (*(char *)(piVar11 + 0x13) == '\0') {
      if (*(short *)(iVar12 + 0x22) < *(short *)(iVar12 + 0x1c)) {
        piVar11[0x10] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x1c) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar11[0x10]) {
          piVar11[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      else {
        piVar11[0x10] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x1c) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x10] <= (float)(local_28 - dVar2)) {
          piVar11[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x24) < *(short *)(iVar12 + 0x1e)) {
        piVar11[0x11] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x1e) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar11[0x11]) {
          piVar11[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar11[0x11] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x1e) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x11] <= (float)(local_28 - dVar2)) {
          piVar11[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x26) < *(short *)(iVar12 + 0x20)) {
        piVar11[0x12] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x20) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar11[0x12]) {
          piVar11[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar11[0x12] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x20) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x12] <= (float)(local_28 - dVar2)) {
          piVar11[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      if (iVar5 == 3) {
        *(char *)((int)piVar11 + 0x4d) = *(char *)((int)piVar11 + 0x4d) + '\x01';
      }
    }
    else {
      if (*(short *)(iVar12 + 0x22) < *(short *)(iVar12 + 0x1c)) {
        piVar11[0x10] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x22) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x10] <= (float)(local_28 - dVar2)) {
          piVar11[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      else {
        piVar11[0x10] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x22) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar11[0x10]) {
          piVar11[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x24) < *(short *)(iVar12 + 0x1e)) {
        piVar11[0x11] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x24) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x11] <= (float)(local_28 - dVar2)) {
          piVar11[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar11[0x11] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x24) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar11[0x11]) {
          piVar11[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x26) < *(short *)(iVar12 + 0x20)) {
        piVar11[0x12] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x26) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x12] <= (float)(local_28 - dVar2)) {
          piVar11[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar11[0x12] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x26) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar11[0x12]) {
          piVar11[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      if (iVar5 == 3) {
        if (*(short *)(iVar12 + 0x1a) != -1) {
          FUN_800200e8((int)*(short *)(iVar12 + 0x1a),1);
        }
        *(char *)((int)piVar11 + 0x4d) = *(char *)((int)piVar11 + 0x4d) + '\x01';
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
LAB_801953e0:
      iVar5 = 0;
      if (*(short *)(iVar12 + 0x22) < *(short *)(iVar12 + 0x1c)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000);
        piVar11[0x10] =
             (int)-(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 -
                   (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x22) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x10] <= (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x10] = (int)(float)(local_28 - dVar2);
          iVar5 = 1;
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000);
        piVar11[0x10] =
             (int)(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 +
                  (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x22) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_30 - dVar2) <= (float)piVar11[0x10]) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x10] = (int)(float)(local_28 - dVar2);
          iVar5 = 1;
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x24) < *(short *)(iVar12 + 0x1e)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000);
        piVar11[0x11] =
             (int)-(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 -
                   (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x24) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x11] <= (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x11] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000);
        piVar11[0x11] =
             (int)(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 +
                  (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x24) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_30 - dVar2) <= (float)piVar11[0x11]) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x11] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x26) < *(short *)(iVar12 + 0x20)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000);
        piVar11[0x12] =
             (int)-(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 -
                   (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x26) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x12] <= (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x12] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000);
        piVar11[0x12] =
             (int)(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 +
                  (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x26) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_30 - dVar2) <= (float)piVar11[0x12]) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x12] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      if (iVar5 == 3) {
        if (*(short *)(iVar12 + 0x1a) != -1) {
          FUN_800200e8((int)*(short *)(iVar12 + 0x1a),1);
        }
        *(char *)((int)piVar11 + 0x4d) = *(char *)((int)piVar11 + 0x4d) + '\x01';
      }
    }
    else {
      if (*(short *)(iVar12 + 0x22) < *(short *)(iVar12 + 0x1c)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000);
        piVar11[0x10] =
             (int)-(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 -
                   (float)piVar11[0x10]);
        uVar4 = (int)*(short *)(iVar12 + 0x22) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x10] < (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x10] =
               (int)(float)((double)CONCAT44(0x43300000,
                                             (int)*(short *)(iVar12 + 0x1c) -
                                             (int)((float)(local_28 - dVar2) - (float)piVar11[0x10])
                                             ^ 0x80000000) - dVar2);
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x29) ^ 0x80000000);
        piVar11[0x10] =
             (int)(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 +
                  (float)piVar11[0x10]);
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x1c) ^ 0x80000000);
        if ((float)(local_30 - dVar2) < (float)piVar11[0x10]) {
          local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x22) ^ 0x80000000);
          piVar11[0x10] =
               (int)(float)((double)CONCAT44(0x43300000,
                                             (int)*(short *)(iVar12 + 0x22) +
                                             (int)((float)piVar11[0x10] - (float)(local_28 - dVar2))
                                             ^ 0x80000000) - dVar2);
        }
      }
      fVar3 = FLOAT_803e4018;
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x24) < *(short *)(iVar12 + 0x1e)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000);
        piVar11[0x11] =
             (int)-(FLOAT_803e4018 * (float)(local_28 - DOUBLE_803e4010) * FLOAT_803db414 -
                   (float)piVar11[0x11]);
        uVar4 = (int)*(short *)(iVar12 + 0x24) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x11] < (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar11[0x11] =
               (int)-(fVar3 * (float)((double)CONCAT44(0x43300000,
                                                       (int)((float)(local_28 - dVar2) -
                                                            (float)piVar11[0x11]) ^ 0x80000000) -
                                     dVar2) -
                     (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x1e) ^ 0x80000000
                                             ) - dVar2));
        }
      }
      else {
        piVar11[0x11] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2a) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x11]);
        local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x1e) ^ 0x80000000);
        if ((float)(local_28 - dVar2) < (float)piVar11[0x11]) {
          local_30 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(iVar12 + 0x24) +
                                      (int)((float)piVar11[0x11] -
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(iVar12 + 0x24) ^
                                                                    0x80000000) - dVar2)) ^
                                      0x80000000);
          piVar11[0x11] = (int)(float)(local_30 - dVar2);
        }
      }
      dVar2 = DOUBLE_803e4010;
      if (*(short *)(iVar12 + 0x26) < *(short *)(iVar12 + 0x20)) {
        piVar11[0x12] =
             (int)-(FLOAT_803e4018 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000)
                           - DOUBLE_803e4010) * FLOAT_803db414 - (float)piVar11[0x12]);
        uVar4 = (int)*(short *)(iVar12 + 0x26) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar11[0x12] < (float)(local_28 - dVar2)) {
          local_30 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(iVar12 + 0x20) -
                                      (int)((float)((double)CONCAT44(0x43300000,uVar4) - dVar2) -
                                           (float)piVar11[0x12]) ^ 0x80000000);
          piVar11[0x12] = (int)(float)(local_30 - dVar2);
        }
      }
      else {
        piVar11[0x12] =
             (int)(FLOAT_803e4018 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar12 + 0x2b) ^ 0x80000000) -
                          DOUBLE_803e4010) * FLOAT_803db414 + (float)piVar11[0x12]);
        local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x20) ^ 0x80000000);
        if ((float)(local_28 - dVar2) < (float)piVar11[0x12]) {
          local_30 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(iVar12 + 0x26) +
                                      (int)((float)piVar11[0x12] -
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(iVar12 + 0x26) ^
                                                                    0x80000000) - dVar2)) ^
                                      0x80000000);
          piVar11[0x12] = (int)(float)(local_30 - dVar2);
        }
      }
    }
  }
  else if (bVar1 == 4) goto LAB_801953e0;
  FUN_80194c40(iVar12,piVar11,iVar6);
LAB_80196200:
  FUN_80286124();
  return;
}

