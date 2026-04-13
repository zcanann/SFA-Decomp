// Function: FUN_80195584
// Entry: 80195584
// Size: 4624 bytes

/* WARNING: Removing unreachable block (ram,0x8019594c) */

void FUN_80195584(void)

{
  byte bVar1;
  double dVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  ushort *puVar7;
  uint uVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  undefined8 local_30;
  undefined8 local_28;
  
  uVar4 = FUN_8028683c();
  iVar11 = *(int *)(uVar4 + 0x4c);
  piVar10 = *(int **)(uVar4 + 0xb8);
  iVar5 = FUN_8005b478((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10));
  puVar6 = (undefined4 *)FUN_8005b068(iVar5);
  if (puVar6 == (undefined4 *)0x0) {
    *(undefined *)((int)piVar10 + 0x4d) = 0;
    goto LAB_8019677c;
  }
  if ((*(ushort *)(puVar6 + 1) & 8) == 0) goto LAB_8019677c;
  if (piVar10[1] == 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)((int)puVar6 + 0x9a); iVar5 = iVar5 + 1) {
      puVar7 = (ushort *)FUN_80060868((int)puVar6,iVar5);
      uVar8 = FUN_800607f4((int)puVar7);
      if ((int)*(char *)(iVar11 + 0x28) == uVar8) {
        *piVar10 = *piVar10 + 1;
        piVar10[1] = piVar10[1] + ((uint)puVar7[10] - (uint)*puVar7);
      }
    }
    if (piVar10[1] == 0) goto LAB_8019677c;
    piVar10[1] = piVar10[1] * 3;
    if ((int)*(short *)(iVar11 + 0x18) == 0xffffffff) {
      *(undefined *)(piVar10 + 0x13) = 1;
    }
    else {
      uVar8 = FUN_80020078((int)*(short *)(iVar11 + 0x18));
      *(char *)(piVar10 + 0x13) = (char)uVar8;
    }
    piVar10[2] = (uint)*(byte *)((int)puVar6 + 0xa1);
    dVar2 = DOUBLE_803e4ca8;
    piVar10[0x10] =
         (int)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e4ca8);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x1e) ^ 0x80000000);
    piVar10[0x11] = (int)(float)(local_30 - dVar2);
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x20) ^ 0x80000000);
    piVar10[0x12] = (int)(float)(local_28 - dVar2);
    if (((int)*(short *)(iVar11 + 0x1a) != 0xffffffff) &&
       (uVar8 = FUN_80020078((int)*(short *)(iVar11 + 0x1a)), dVar2 = DOUBLE_803e4ca8, uVar8 != 0))
    {
      local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x22) ^ 0x80000000);
      piVar10[0x10] = (int)(float)(local_28 - DOUBLE_803e4ca8);
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x24) ^ 0x80000000);
      piVar10[0x11] = (int)(float)(local_30 - dVar2);
      piVar10[0x12] =
           (int)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x26) ^ 0x80000000) -
                       dVar2);
      *(undefined *)(piVar10 + 0x13) = 1;
    }
    iVar9 = FUN_80023d8c(piVar10[1] * 6 + *piVar10 * 0xc + piVar10[2] * 0xc,5);
    piVar10[3] = iVar9;
    iVar5 = *piVar10 * 2;
    iVar9 = iVar9 + piVar10[1] * 6;
    piVar10[6] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[7] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[4] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[5] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[8] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[9] = iVar9;
    iVar9 = iVar9 + iVar5;
    iVar5 = piVar10[2] * 2;
    piVar10[10] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[0xb] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[0xc] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[0xd] = iVar9;
    iVar9 = iVar9 + iVar5;
    piVar10[0xe] = iVar9;
    piVar10[0xf] = iVar9 + iVar5;
    FUN_80194ee0(iVar11,piVar10,(int)puVar6);
    if (*(char *)(iVar11 + 0x2c) != '\x04') {
      FUN_801951bc(iVar11,piVar10,puVar6);
      *(ushort *)(puVar6 + 1) = *(ushort *)(puVar6 + 1) ^ 1;
      FUN_801951bc(iVar11,piVar10,puVar6);
      *(ushort *)(puVar6 + 1) = *(ushort *)(puVar6 + 1) ^ 1;
    }
  }
  if (*(char *)(iVar11 + 0x2c) == '\x02') {
    uVar8 = FUN_80020078((int)*(short *)(iVar11 + 0x18));
    if ((int)*(char *)(piVar10 + 0x13) != uVar8) {
      *(char *)(piVar10 + 0x13) = (char)uVar8;
      if ((uVar8 == 0) && (-1 < *(short *)(iVar11 + 0x1a))) {
        FUN_800201ac((int)*(short *)(iVar11 + 0x1a),0);
      }
      if ('\x02' < *(char *)((int)piVar10 + 0x4d)) {
        *(undefined *)((int)piVar10 + 0x4d) = 0;
      }
    }
    if ('\x02' < *(char *)((int)piVar10 + 0x4d)) goto LAB_8019677c;
    if (*(ushort *)((int)piVar10 + 0x4e) != 0) {
      FUN_8000da78(uVar4,*(ushort *)((int)piVar10 + 0x4e));
    }
  }
  else {
    if ('\x02' < *(char *)((int)piVar10 + 0x4d)) goto LAB_8019677c;
    if (*(char *)(piVar10 + 0x13) == '\0') {
      uVar4 = FUN_80020078((int)*(short *)(iVar11 + 0x18));
      *(char *)(piVar10 + 0x13) = (char)uVar4;
      if (*(char *)(piVar10 + 0x13) == '\0') goto LAB_8019677c;
    }
  }
  dVar2 = DOUBLE_803e4ca8;
  bVar1 = *(byte *)(iVar11 + 0x2c);
  if (bVar1 == 2) {
    iVar5 = 0;
    if (*(char *)(piVar10 + 0x13) == '\0') {
      if (*(short *)(iVar11 + 0x22) < *(short *)(iVar11 + 0x1c)) {
        piVar10[0x10] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x1c) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar10[0x10]) {
          piVar10[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      else {
        piVar10[0x10] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x1c) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x10] <= (float)(local_28 - dVar2)) {
          piVar10[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x24) < *(short *)(iVar11 + 0x1e)) {
        piVar10[0x11] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x1e) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar10[0x11]) {
          piVar10[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar10[0x11] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x1e) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x11] <= (float)(local_28 - dVar2)) {
          piVar10[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x26) < *(short *)(iVar11 + 0x20)) {
        piVar10[0x12] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x20) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar10[0x12]) {
          piVar10[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar10[0x12] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x20) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x12] <= (float)(local_28 - dVar2)) {
          piVar10[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      if (iVar5 == 3) {
        *(char *)((int)piVar10 + 0x4d) = *(char *)((int)piVar10 + 0x4d) + '\x01';
      }
    }
    else {
      if (*(short *)(iVar11 + 0x22) < *(short *)(iVar11 + 0x1c)) {
        piVar10[0x10] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x22) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x10] <= (float)(local_28 - dVar2)) {
          piVar10[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      else {
        piVar10[0x10] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x22) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar10[0x10]) {
          piVar10[0x10] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = 1;
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x24) < *(short *)(iVar11 + 0x1e)) {
        piVar10[0x11] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x24) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x11] <= (float)(local_28 - dVar2)) {
          piVar10[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar10[0x11] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x24) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar10[0x11]) {
          piVar10[0x11] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x26) < *(short *)(iVar11 + 0x20)) {
        piVar10[0x12] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x26) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x12] <= (float)(local_28 - dVar2)) {
          piVar10[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        piVar10[0x12] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x26) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_28 - dVar2) <= (float)piVar10[0x12]) {
          piVar10[0x12] = (int)(float)((double)CONCAT44(0x43300000,uVar4) - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      if (iVar5 == 3) {
        if ((int)*(short *)(iVar11 + 0x1a) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar11 + 0x1a),1);
        }
        *(char *)((int)piVar10 + 0x4d) = *(char *)((int)piVar10 + 0x4d) + '\x01';
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
LAB_8019595c:
      iVar5 = 0;
      if (*(short *)(iVar11 + 0x22) < *(short *)(iVar11 + 0x1c)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000);
        piVar10[0x10] =
             (int)-(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 -
                   (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x22) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x10] <= (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x10] = (int)(float)(local_28 - dVar2);
          iVar5 = 1;
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000);
        piVar10[0x10] =
             (int)(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 +
                  (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x22) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_30 - dVar2) <= (float)piVar10[0x10]) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x10] = (int)(float)(local_28 - dVar2);
          iVar5 = 1;
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x24) < *(short *)(iVar11 + 0x1e)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000);
        piVar10[0x11] =
             (int)-(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 -
                   (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x24) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x11] <= (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x11] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000);
        piVar10[0x11] =
             (int)(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 +
                  (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x24) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_30 - dVar2) <= (float)piVar10[0x11]) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x11] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x26) < *(short *)(iVar11 + 0x20)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000);
        piVar10[0x12] =
             (int)-(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 -
                   (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x26) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x12] <= (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x12] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000);
        piVar10[0x12] =
             (int)(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 +
                  (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x26) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)(local_30 - dVar2) <= (float)piVar10[0x12]) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x12] = (int)(float)(local_28 - dVar2);
          iVar5 = iVar5 + 1;
        }
      }
      if (iVar5 == 3) {
        if ((int)*(short *)(iVar11 + 0x1a) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar11 + 0x1a),1);
        }
        *(char *)((int)piVar10 + 0x4d) = *(char *)((int)piVar10 + 0x4d) + '\x01';
      }
    }
    else {
      if (*(short *)(iVar11 + 0x22) < *(short *)(iVar11 + 0x1c)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000);
        piVar10[0x10] =
             (int)-(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 -
                   (float)piVar10[0x10]);
        uVar4 = (int)*(short *)(iVar11 + 0x22) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x10] < (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x10] =
               (int)(float)((double)CONCAT44(0x43300000,
                                             (int)*(short *)(iVar11 + 0x1c) -
                                             (int)((float)(local_28 - dVar2) - (float)piVar10[0x10])
                                             ^ 0x80000000) - dVar2);
        }
      }
      else {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x29) ^ 0x80000000);
        piVar10[0x10] =
             (int)(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 +
                  (float)piVar10[0x10]);
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x1c) ^ 0x80000000);
        if ((float)(local_30 - dVar2) < (float)piVar10[0x10]) {
          local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x22) ^ 0x80000000);
          piVar10[0x10] =
               (int)(float)((double)CONCAT44(0x43300000,
                                             (int)*(short *)(iVar11 + 0x22) +
                                             (int)((float)piVar10[0x10] - (float)(local_28 - dVar2))
                                             ^ 0x80000000) - dVar2);
        }
      }
      fVar3 = FLOAT_803e4cb0;
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x24) < *(short *)(iVar11 + 0x1e)) {
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000);
        piVar10[0x11] =
             (int)-(FLOAT_803e4cb0 * (float)(local_28 - DOUBLE_803e4ca8) * FLOAT_803dc074 -
                   (float)piVar10[0x11]);
        uVar4 = (int)*(short *)(iVar11 + 0x24) ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x11] < (float)(local_30 - dVar2)) {
          local_28 = (double)CONCAT44(0x43300000,uVar4);
          piVar10[0x11] =
               (int)-(fVar3 * (float)((double)CONCAT44(0x43300000,
                                                       (int)((float)(local_28 - dVar2) -
                                                            (float)piVar10[0x11]) ^ 0x80000000) -
                                     dVar2) -
                     (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x1e) ^ 0x80000000
                                             ) - dVar2));
        }
      }
      else {
        piVar10[0x11] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2a) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x11]);
        local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x1e) ^ 0x80000000);
        if ((float)(local_28 - dVar2) < (float)piVar10[0x11]) {
          local_30 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(iVar11 + 0x24) +
                                      (int)((float)piVar10[0x11] -
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(iVar11 + 0x24) ^
                                                                    0x80000000) - dVar2)) ^
                                      0x80000000);
          piVar10[0x11] = (int)(float)(local_30 - dVar2);
        }
      }
      dVar2 = DOUBLE_803e4ca8;
      if (*(short *)(iVar11 + 0x26) < *(short *)(iVar11 + 0x20)) {
        piVar10[0x12] =
             (int)-(FLOAT_803e4cb0 *
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000)
                           - DOUBLE_803e4ca8) * FLOAT_803dc074 - (float)piVar10[0x12]);
        uVar4 = (int)*(short *)(iVar11 + 0x26) ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        if ((float)piVar10[0x12] < (float)(local_28 - dVar2)) {
          local_30 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(iVar11 + 0x20) -
                                      (int)((float)((double)CONCAT44(0x43300000,uVar4) - dVar2) -
                                           (float)piVar10[0x12]) ^ 0x80000000);
          piVar10[0x12] = (int)(float)(local_30 - dVar2);
        }
      }
      else {
        piVar10[0x12] =
             (int)(FLOAT_803e4cb0 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x2b) ^ 0x80000000) -
                          DOUBLE_803e4ca8) * FLOAT_803dc074 + (float)piVar10[0x12]);
        local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x20) ^ 0x80000000);
        if ((float)(local_28 - dVar2) < (float)piVar10[0x12]) {
          local_30 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(iVar11 + 0x26) +
                                      (int)((float)piVar10[0x12] -
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(iVar11 + 0x26) ^
                                                                    0x80000000) - dVar2)) ^
                                      0x80000000);
          piVar10[0x12] = (int)(float)(local_30 - dVar2);
        }
      }
    }
  }
  else if (bVar1 == 4) goto LAB_8019595c;
  FUN_801951bc(iVar11,piVar10,puVar6);
LAB_8019677c:
  FUN_80286888();
  return;
}

