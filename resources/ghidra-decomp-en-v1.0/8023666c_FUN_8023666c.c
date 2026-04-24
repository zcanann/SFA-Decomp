// Function: FUN_8023666c
// Entry: 8023666c
// Size: 1152 bytes

/* WARNING: Removing unreachable block (ram,0x80236acc) */

void FUN_8023666c(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  byte bVar7;
  byte bVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  undefined8 uVar12;
  float local_68;
  float local_64;
  float local_60;
  undefined auStack92 [8];
  undefined4 local_54;
  undefined4 local_40;
  uint uStack60;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar6 = (int)uVar12;
  iVar9 = *(int *)(iVar3 + 0x4c);
  cVar5 = '\0';
  bVar8 = 0;
  bVar7 = 0;
  iVar4 = FUN_8000faac();
  if (*(char *)(iVar6 + 0x25) == '\0') {
    *(float *)(iVar6 + 0x18) = FLOAT_803e7374 * *(float *)(iVar9 + 0x20);
  }
  else {
    uStack60 = (int)*(char *)(iVar6 + 0x26) ^ 0x80000000;
    local_40 = 0x43300000;
    fVar2 = *(float *)(iVar9 + 0x20) * FLOAT_803e737c;
    dVar11 = (double)FUN_80021370((double)((((float)((double)CONCAT44(0x43300000,uStack60) -
                                                    DOUBLE_803e73a0) / FLOAT_803e7378) *
                                            (FLOAT_803e7374 * *(float *)(iVar9 + 0x20) - fVar2) +
                                           fVar2) - *(float *)(iVar6 + 0x18)),(double)FLOAT_803e7380
                                  ,(double)FLOAT_803db414);
    *(float *)(iVar6 + 0x18) = (float)((double)*(float *)(iVar6 + 0x18) + dVar11);
  }
  dVar11 = (double)FUN_80021704(iVar4 + 0x44,iVar3 + 0x18);
  if (*(char *)(iVar6 + 0x25) == '\x01') {
    uStack60 = (uint)*(byte *)(iVar9 + 0x26) << 3;
    local_40 = 0x43300000;
    if ((dVar11 <= (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7358)) &&
       (cVar5 = *(char *)(iVar9 + 0x1b), cVar5 == '\x0f')) {
      cVar5 = FUN_80236480(iVar3,iVar6);
    }
  }
  *(float *)(iVar6 + 4) = *(float *)(iVar6 + 4) - FLOAT_803db414;
  *(float *)(iVar6 + 8) = *(float *)(iVar6 + 8) - FLOAT_803db414;
  if (*(float *)(iVar6 + 4) <= FLOAT_803e7360) {
    bVar1 = *(byte *)(iVar9 + 0x1c);
    if (bVar1 < 9) {
      uStack60 = (uint)*(byte *)(iVar9 + 0x27) << 3;
      local_40 = 0x43300000;
      if (dVar11 <= (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7358)) {
        bVar8 = bVar1;
      }
    }
    if (*(char *)(iVar6 + 0x25) == '\0') {
      uStack60 = (uint)*(byte *)(iVar9 + 0x26) << 3;
      local_40 = 0x43300000;
      if (((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7358) < dVar11) ||
         ((*(byte *)(iVar6 + 0x22) & 8) != 0)) {
        bVar8 = 0;
      }
      else {
        bVar8 = bVar1;
        if (bVar1 == 0) {
          bVar8 = 2;
        }
      }
    }
    if (*(char *)(iVar6 + 0x25) == '\x01') {
      *(float *)(iVar6 + 4) = *(float *)(iVar6 + 4) + FLOAT_803e7384;
    }
    else {
      *(float *)(iVar6 + 4) = *(float *)(iVar6 + 4) + FLOAT_803e7378;
    }
  }
  if (((*(ushort *)(iVar3 + 0xb0) & 0x800) != 0) || ((*(byte *)(iVar6 + 0x22) & 2) != 0)) {
    if (*(short *)(iVar3 + 0x46) == 0x758) {
      if ((*(char *)(iVar6 + 0x25) == '\x01') &&
         (dVar11 <= (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar9 + 0x26) << 3)
                                   - DOUBLE_803e7358))) {
        bVar7 = *(byte *)(iVar9 + 0x1d);
      }
      uStack60 = (uint)*(byte *)(iVar9 + 0x28);
      local_40 = 0x43300000;
      FUN_8009837c((double)*(float *)(iVar6 + 0x18),
                   (double)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7358) /
                           FLOAT_803e7388),iVar3,cVar5,bVar8,bVar7,0);
    }
    else {
      if ((*(char *)(iVar6 + 0x25) == '\x01') && (*(float *)(iVar6 + 8) <= FLOAT_803e7360)) {
        if (*(byte *)(iVar9 + 0x1d) < 4) {
          uStack60 = (uint)*(byte *)(iVar9 + 0x28) << 3;
          local_40 = 0x43300000;
          if (dVar11 <= (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7358)) {
            bVar7 = *(byte *)(iVar9 + 0x1d);
          }
        }
        *(float *)(iVar6 + 8) = *(float *)(iVar6 + 8) + FLOAT_803e738c;
      }
      local_68 = FLOAT_803e7360;
      if (*(short *)(iVar3 + 0x46) == 0x853) {
        if (*(char *)(iVar6 + 0x25) == '\0') {
          local_64 = FLOAT_803e7390;
        }
        else {
          local_64 = FLOAT_803e7394;
        }
      }
      else if (*(char *)(iVar6 + 0x25) == '\0') {
        local_64 = FLOAT_803e7390;
      }
      else {
        local_64 = FLOAT_803e7360;
      }
      local_60 = FLOAT_803e7360;
      FUN_80098b18((double)*(float *)(iVar6 + 0x18),iVar3,cVar5,bVar8,bVar7,&local_68);
    }
  }
  if (((*(char *)(iVar6 + 0x25) == '\x01') && ((*(byte *)(iVar9 + 0x2a) & 2) != 0)) &&
     (*(float *)(iVar6 + 0xc) = *(float *)(iVar6 + 0xc) - FLOAT_803db414,
     *(float *)(iVar6 + 0xc) <= FLOAT_803e7360)) {
    if ((*(ushort *)(iVar3 + 0xb0) & 0x800) != 0) {
      local_54 = *(undefined4 *)(iVar6 + 0x18);
      (**(code **)(*DAT_803dca88 + 8))(iVar3,0x7cb,auStack92,2,0xffffffff,0);
    }
    *(float *)(iVar6 + 0xc) = *(float *)(iVar6 + 0xc) + FLOAT_803e7398;
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286120();
  return;
}

