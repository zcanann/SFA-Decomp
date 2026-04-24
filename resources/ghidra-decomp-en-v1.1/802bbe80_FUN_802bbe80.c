// Function: FUN_802bbe80
// Entry: 802bbe80
// Size: 1484 bytes

void FUN_802bbe80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  float fVar2;
  short sVar3;
  ushort *puVar4;
  int iVar5;
  undefined uVar8;
  short *psVar6;
  int iVar7;
  undefined *puVar9;
  uint uVar10;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar11;
  char cVar12;
  int iVar13;
  undefined8 extraout_f1;
  undefined8 uVar14;
  double dVar15;
  float local_88;
  ushort local_84;
  ushort local_82;
  ushort local_80;
  float local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  float afStack_6c [27];
  
  puVar4 = (ushort *)FUN_80286838();
  uVar14 = extraout_f1;
  iVar5 = FUN_8002bac4();
  cVar12 = -1;
  iVar13 = *(int *)(puVar4 + 0x5c);
  *(undefined2 *)(iVar13 + 0xa86) = 5;
  *(byte *)((int)puVar4 + 0xaf) = *(byte *)((int)puVar4 + 0xaf) | 8;
  *(undefined2 *)(*(int *)(puVar4 + 0x2a) + 0xb2) = 9;
  if (((&DAT_80335d24)[*(short *)(iVar13 + 0x274)] & 8) == 0) {
    if (((&DAT_80335d24)[*(short *)(iVar13 + 0x274)] & 2) == 0) {
      puVar9 = &DAT_80335cfc;
    }
    else {
      puVar9 = &DAT_80335d10;
    }
    uVar8 = FUN_8003549c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,
                         puVar9,1,(uint)*(byte *)(iVar13 + 0xd00),(float *)(iVar13 + 0xa94),in_r8,
                         in_r9,in_r10);
    *(undefined *)(iVar13 + 0xd00) = uVar8;
    if (*(char *)(iVar13 + 0xd00) != '\0') {
      FUN_8003a260((int)puVar4,iVar13 + 0x980);
      FUN_8003b408((int)puVar4,iVar13 + 0x980);
      goto LAB_802bc434;
    }
  }
  *(byte *)((int)puVar4 + 0xaf) = *(byte *)((int)puVar4 + 0xaf) & 0xf7;
  if (*(char *)(iVar13 + 0xa8a) == '\x02') {
    *(undefined *)(iVar13 + 0x25f) = 1;
    FUN_802bbc14(puVar4,(uint)DAT_803dc070,-1);
  }
  else {
    *(undefined *)(iVar13 + 0x25f) = 0;
    fVar2 = FLOAT_803e8ecc;
    *(float *)(iVar13 + 0x294) = FLOAT_803e8ecc;
    *(float *)(iVar13 + 0x284) = fVar2;
    *(float *)(iVar13 + 0x280) = fVar2;
    *(float *)(puVar4 + 0x12) = fVar2;
    *(float *)(puVar4 + 0x14) = fVar2;
    *(float *)(puVar4 + 0x16) = fVar2;
    (**(code **)(*DAT_803dd728 + 0x20))(puVar4,iVar13 + 4);
    FUN_802bbc14(puVar4,(uint)DAT_803dc070,-1);
  }
  if (*(char *)(iVar13 + 0xa8a) == '\0') {
    (**(code **)(*DAT_803dd6e0 + 0x20))(0);
  }
  else {
    (**(code **)(*DAT_803dd6e0 + 0x20))(1);
  }
  bVar1 = *(byte *)(iVar13 + 0xa8c);
  if ((bVar1 == 5) || ((bVar1 < 5 && (bVar1 == 0)))) {
    iVar11 = *(int *)(puVar4 + 0x5c);
    iVar7 = FUN_8002bac4();
    if ((iVar7 == 0) ||
       ((dVar15 = (double)FUN_800217c8((float *)(iVar7 + 0x18),(float *)(puVar4 + 0xc)),
        (double)FLOAT_803e8ed8 <= dVar15 || (*(char *)(iVar11 + 0xa8a) != '\0')))) {
      *(undefined *)(iVar11 + 0x980) = 0;
    }
    else {
      *(undefined *)(iVar11 + 0x980) = 1;
      *(undefined4 *)(iVar11 + 0x984) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar11 + 0x988) = *(undefined4 *)(iVar7 + 0x10);
      *(undefined4 *)(iVar11 + 0x98c) = *(undefined4 *)(iVar7 + 0x14);
    }
    FUN_8003b5f8((short *)puVar4,(char *)(iVar13 + 0x980));
  }
  bVar1 = *(byte *)(iVar13 + 0xa8c);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
LAB_802bc0c0:
        local_88 = FLOAT_803e8ed8;
        psVar6 = (short *)FUN_80036f50(0x13,puVar4,&local_88);
        if (((*(char *)(iVar13 + 0xa8a) != '\0') || (*(short *)(iVar13 + 0x274) != 7)) ||
           (dVar15 = FUN_80021730((float *)(iVar5 + 0x18),(float *)(puVar4 + 0xc)),
           (double)FLOAT_803e8f4c <= dVar15)) {
          if (*(char *)(iVar13 + 0xa8a) == '\x02') {
            if ((psVar6 == (short *)0x0) || ((*(byte *)((int)psVar6 + 0xaf) & 4) == 0)) {
              FUN_8011f6d0(0x13);
            }
            else {
              FUN_8011f6d0(0x15);
              if ((*(byte *)((int)psVar6 + 0xaf) & 1) != 0) {
                FUN_80014b68(0,0x100);
                FUN_800201ac(0x3e3,0);
                bVar1 = *(byte *)(iVar13 + 0xa8c);
                if (bVar1 == 3) {
                  cVar12 = '\x01';
                }
                else if (bVar1 < 3) {
                  if (bVar1 == 1) {
                    cVar12 = '\0';
                  }
                }
                else if (bVar1 < 5) {
                  cVar12 = '\x02';
                }
                sVar3 = *puVar4 - *psVar6;
                if (0x8000 < sVar3) {
                  sVar3 = sVar3 + 1;
                }
                if (sVar3 < -0x8000) {
                  sVar3 = sVar3 + -1;
                }
                if (-1 < cVar12) {
                  iVar5 = cVar12 * 0x24;
                  FUN_800201ac((uint)*(ushort *)(iVar5 + -0x7fcca352),
                               (int)*(short *)(*(int *)(psVar6 + 0x26) + 0x1a));
                  uVar10 = 0;
                  if ((0x4000 < sVar3) || (sVar3 < -0x4000)) {
                    uVar10 = 1;
                  }
                  FUN_800201ac((uint)*(ushort *)(iVar5 + -0x7fcca350),(int)cVar12 ^ uVar10);
                }
                if ((sVar3 < 0x4001) && (-0x4001 < sVar3)) {
                  FUN_800201ac(0x5bb,1);
                }
                else {
                  FUN_800201ac(0x19,1);
                }
                *(undefined4 *)(iVar13 + 0x31c) = 0;
                (**(code **)(*DAT_803dd6e8 + 0x60))();
                (**(code **)(*DAT_803dd72c + 0x2c))();
              }
            }
          }
        }
        else if (((psVar6 != (short *)0x0) && ((*(byte *)((int)psVar6 + 0xaf) & 4) != 0)) &&
                (FUN_8011f6d0(0x14), (*(byte *)((int)psVar6 + 0xaf) & 1) != 0)) {
          iVar7 = FUN_80057360();
          (**(code **)(*DAT_803dd72c + 0x24))(iVar5 + 0xc,0x584,iVar7,0);
          FUN_80014b68(0,0x100);
          FUN_800201ac(0x3e3,1);
          sVar3 = *puVar4 - *psVar6;
          if (0x8000 < sVar3) {
            sVar3 = sVar3 + 1;
          }
          if (sVar3 < -0x8000) {
            sVar3 = sVar3 + -1;
          }
          if ((sVar3 < 0x4001) && (-0x4001 < sVar3)) {
            FUN_800201ac(0x5ba,1);
          }
          else {
            FUN_800201ac(0x18,1);
          }
          if (*(char *)(iVar13 + 0xa8c) == '\x03') {
            *(undefined2 *)(iVar13 + 0xa88) = 1000;
            (**(code **)(*DAT_803dd6e8 + 0x58))(1000,0x5d0);
          }
        }
      }
    }
    else if (bVar1 < 5) goto LAB_802bc0c0;
  }
  FUN_8003b408((int)puVar4,iVar13 + 0x980);
  local_78 = *(undefined4 *)(puVar4 + 6);
  local_74 = *(undefined4 *)(puVar4 + 8);
  local_70 = *(undefined4 *)(puVar4 + 10);
  local_84 = *puVar4;
  local_82 = puVar4[1];
  local_80 = puVar4[2];
  local_7c = FLOAT_803e8ef0;
  FUN_80021fac(afStack_6c,&local_84);
  iVar5 = *(int *)(puVar4 + 0x32);
  FUN_80022790((double)FLOAT_803e8ecc,(double)FLOAT_803e8f44,(double)FLOAT_803e8f48,afStack_6c,
               (float *)(iVar5 + 0x20),(float *)(iVar5 + 0x24),(float *)(iVar5 + 0x28));
LAB_802bc434:
  FUN_80286884();
  return;
}

