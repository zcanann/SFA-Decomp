// Function: FUN_802b1080
// Entry: 802b1080
// Size: 1412 bytes

/* WARNING: Removing unreachable block (ram,0x802b15e4) */
/* WARNING: Removing unreachable block (ram,0x802b15dc) */
/* WARNING: Removing unreachable block (ram,0x802b1098) */
/* WARNING: Removing unreachable block (ram,0x802b1090) */

void FUN_802b1080(void)

{
  ushort uVar1;
  bool bVar2;
  byte bVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  uint uVar10;
  undefined2 *puVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  double dVar15;
  double in_f30;
  double in_f31;
  double dVar16;
  undefined8 uVar17;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_58;
  undefined8 local_50;
  
  uVar17 = FUN_80286838();
  iVar5 = (int)((ulonglong)uVar17 >> 0x20);
  iVar12 = (int)uVar17;
  iVar6 = FUN_800396d0(iVar5,9);
  psVar7 = (short *)FUN_800396d0(iVar5,0);
  bVar2 = false;
  iVar14 = *(int *)(iVar5 + 0xb8);
  if (**(char **)(iVar12 + 0x35c) < '\x01') {
    puVar8 = (undefined4 *)FUN_800395a4(iVar5,5);
    puVar9 = (undefined4 *)FUN_800395a4(iVar5,4);
    if (puVar8 != (undefined4 *)0x0) {
      *puVar8 = 0x200;
    }
    if (puVar9 != (undefined4 *)0x0) {
      *puVar9 = 0x200;
    }
  }
  else {
    FUN_8003b408(iVar5,iVar12 + 0x364);
  }
  if ((*(uint *)(iVar12 + 0x360) & 0x2000000) == 0) {
    dVar15 = (double)FUN_802932a4((double)FLOAT_803e8c8c,(double)FLOAT_803dc074);
    *(short *)(iVar12 + 0x4d0) =
         (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar12 + 0x4d0) ^ 0x80000000)
                                     - DOUBLE_803e8b58) * dVar15);
    dVar15 = (double)FUN_802932a4((double)FLOAT_803e8bb4,(double)FLOAT_803dc074);
    local_78 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d6) ^ 0x80000000);
    *(short *)(iVar12 + 0x4d6) = (short)(int)((double)(float)(local_78 - DOUBLE_803e8b58) * dVar15);
    dVar15 = (double)FUN_802932a4((double)FLOAT_803e8bb4,(double)FLOAT_803dc074);
    *(short *)(iVar12 + 0x4d4) =
         (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar12 + 0x4d4) ^ 0x80000000)
                                     - DOUBLE_803e8b58) * dVar15);
    dVar15 = (double)FUN_802932a4((double)FLOAT_803e8bb4,(double)FLOAT_803dc074);
    local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d2) ^ 0x80000000);
    *(short *)(iVar12 + 0x4d2) = (short)(int)((double)(float)(local_58 - DOUBLE_803e8b58) * dVar15);
  }
  dVar15 = DOUBLE_803e8b58;
  fVar4 = FLOAT_803e8b30;
  bVar3 = *(byte *)(iVar12 + 0x3f0) >> 5 & 1;
  if (bVar3 != 0) {
    dVar16 = (double)(*(float *)(iVar14 + 0x294) / *(float *)(*(int *)(iVar12 + 0x400) + 0x18));
    in_f31 = (double)FLOAT_803e8b3c;
    if ((in_f31 <= dVar16) && (in_f31 = dVar16, (double)FLOAT_803e8b78 < dVar16)) {
      in_f31 = (double)FLOAT_803e8b78;
    }
    in_f30 = (double)(float)((double)FLOAT_803e8b78 - in_f31);
  }
  if (iVar6 != 0) {
    if (bVar3 == 0) {
      *(undefined2 *)(iVar6 + 4) = *(undefined2 *)(iVar12 + 0x4d0);
      *(undefined2 *)(iVar6 + 2) = *(undefined2 *)(iVar12 + 0x4d2);
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d0) ^ 0x80000000);
      local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d2) ^ 0x80000000);
      *(short *)(iVar6 + 4) =
           (short)(int)(FLOAT_803e8b30 *
                       (float)((double)(float)(local_50 - DOUBLE_803e8b58) * in_f30 +
                              (double)(float)((double)(float)(local_58 - DOUBLE_803e8b58) * in_f31))
                       );
      local_70 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d0) ^ 0x80000000);
      *(short *)(iVar6 + 2) =
           (short)(int)(fVar4 * (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                         (int)*(short *)(iVar12 + 
                                                  0x4d2) ^ 0x80000000) - dVar15) * in_f30 +
                                       (double)(float)((double)(float)(local_70 - dVar15) * in_f31))
                       );
    }
  }
  if (psVar7 != (short *)0x0) {
    *psVar7 = -*(short *)(iVar12 + 0x4d6);
    dVar15 = DOUBLE_803e8b58;
    fVar4 = FLOAT_803e8b30;
    if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) {
      psVar7[1] = *(short *)(iVar12 + 0x4d4) / 2;
      psVar7[2] = -(*(short *)(iVar12 + 0x4d0) / 2);
    }
    else {
      uVar13 = (int)*(short *)(iVar12 + 0x4d4) / 2 ^ 0x80000000;
      local_50 = (double)CONCAT44(0x43300000,uVar13);
      uVar10 = -((int)*(short *)(iVar12 + 0x4d0) / 2) ^ 0x80000000;
      local_58 = (double)CONCAT44(0x43300000,uVar10);
      psVar7[1] = (short)(int)(FLOAT_803e8b30 *
                              (float)((double)(float)(local_50 - DOUBLE_803e8b58) * in_f30 +
                                     (double)(float)((double)(float)(local_58 - DOUBLE_803e8b58) *
                                                    in_f31)));
      local_70 = (double)CONCAT44(0x43300000,uVar13);
      psVar7[2] = (short)(int)(fVar4 * (float)((double)(float)((double)CONCAT44(0x43300000,uVar10) -
                                                              dVar15) * in_f30 +
                                              (double)(float)((double)(float)(local_70 - dVar15) *
                                                             in_f31)));
    }
  }
  if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) {
    uVar1 = *(ushort *)(iVar12 + 0x4d0);
    *(ushort *)(iVar5 + 4) = ((short)uVar1 >> 2) + (ushort)((short)uVar1 < 0 && (uVar1 & 3) != 0);
  }
  else {
    dVar15 = (double)FUN_802932a4((double)FLOAT_803e8c8c,(double)FLOAT_803dc074);
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 4) ^ 0x80000000);
    *(short *)(iVar5 + 4) = (short)(int)((double)(float)(local_50 - DOUBLE_803e8b58) * dVar15);
  }
  FUN_80038a80(iVar5,iVar12 + 0x364,(uint)(*(short *)(iVar12 + 0x274) == 1));
  if ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0) {
    if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
      uVar10 = FUN_80296164(iVar5,2);
      if ((((uVar10 == 0) && ('\x04' < **(char **)(iVar12 + 0x35c))) && (DAT_803dd2d4 == '\x01')) &&
         (uVar10 = FUN_80022264(0,300), uVar10 == 1)) {
        DAT_803dd2d4 = '\x02';
        bVar2 = true;
      }
      if (((!bVar2) && (DAT_803dd2d4 == '\x02')) && (uVar10 = FUN_80022264(0,5), uVar10 == 1)) {
        DAT_803dd2d4 = '\x01';
      }
    }
    else {
      DAT_803dd2d4 = '\x05';
    }
    puVar11 = (undefined2 *)FUN_800396d0(iVar5,1);
    if (puVar11 != (undefined2 *)0x0) {
      *puVar11 = 0x1c2;
      puVar11[1] = 0;
      puVar11[2] = 0;
    }
  }
  FUN_80286884();
  return;
}

