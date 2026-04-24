// Function: FUN_80299bb0
// Entry: 80299bb0
// Size: 660 bytes

/* WARNING: Removing unreachable block (ram,0x80299ce4) */
/* WARNING: Removing unreachable block (ram,0x80299e24) */

void FUN_80299bb0(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  undefined8 uVar8;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar8 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  iVar5 = (int)uVar8;
  iVar6 = *(int *)(iVar3 + 0xb8);
  local_48 = FLOAT_803e7f5c;
  iVar4 = FUN_80036e58(0x3e,iVar3,&local_48);
  *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xdf | 0x20;
  fVar2 = FLOAT_803e7ea4;
  *(float *)(iVar6 + 0x414) = FLOAT_803e7ea4;
  if (iVar4 == 0) {
    *(byte *)(iVar6 + 0x8aa) = *(byte *)(iVar6 + 0x8aa) ^ 1;
  }
  else {
    local_44 = *(float *)(iVar4 + 0xc) - *(float *)(iVar3 + 0xc);
    local_3c = *(float *)(iVar4 + 0x14) - *(float *)(iVar3 + 0x14);
    local_40 = fVar2;
    FUN_8002282c(&local_44);
    uStack52 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
    local_38 = 0x43300000;
    FUN_80293e80((double)((FLOAT_803e7f94 *
                          (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7ec0)) /
                         FLOAT_803e7f98));
    uStack44 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
    local_30 = 0x43300000;
    FUN_80294204((double)((FLOAT_803e7f94 *
                          (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7ec0)) /
                         FLOAT_803e7f98));
    bVar1 = *(byte *)(*(int *)(iVar4 + 0x50) + 0x75);
    if (bVar1 != 2) {
      if (bVar1 < 2) {
        if (bVar1 != 0) goto LAB_80299d74;
      }
      else if (bVar1 < 4) goto LAB_80299d74;
      *(byte *)(iVar6 + 0x8aa) = *(byte *)(iVar6 + 0x8aa) ^ 1;
    }
  }
LAB_80299d74:
  if ((*(char *)(iVar5 + 0x34b) != '\x02') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e7eac)) {
    FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                 (int)*(short *)(&DAT_803336bc + *(short *)(*(int *)(iVar6 + 0x3dc) + 0x11e2) * 2),0
                );
    *(undefined *)(iVar6 + 0x8a9) = 0x1a;
    *(code **)(iVar5 + 0x308) = FUN_8029bc08;
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                 (int)*(short *)(&DAT_803336bc + *(short *)(*(int *)(iVar6 + 0x3dc) + 0x11e2) * 2),0
                );
    *(undefined *)(iVar6 + 0x8a9) = 0x1a;
    *(code **)(iVar5 + 0x308) = FUN_8029bc08;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286124(0x27);
  return;
}

