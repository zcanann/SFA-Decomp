// Function: FUN_802bab4c
// Entry: 802bab4c
// Size: 756 bytes

/* WARNING: Removing unreachable block (ram,0x802bad18) */

void FUN_802bab4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint unaff_r23;
  uint unaff_r24;
  int unaff_r27;
  int unaff_r28;
  int unaff_r29;
  int unaff_r30;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028682c();
  fVar2 = FLOAT_803e8ecc;
  uVar3 = (uint)((ulonglong)uVar10 >> 0x20);
  puVar7 = (uint *)uVar10;
  puVar7[0xa5] = (uint)FLOAT_803e8ecc;
  puVar7[0xa1] = (uint)fVar2;
  puVar7[0xa0] = (uint)fVar2;
  *(float *)(uVar3 + 0x24) = fVar2;
  *(float *)(uVar3 + 0x28) = fVar2;
  *(float *)(uVar3 + 0x2c) = fVar2;
  *puVar7 = *puVar7 | 0x200000;
  iVar8 = *(int *)(uVar3 + 0xb8);
  iVar4 = FUN_8002bac4();
  bVar1 = *(byte *)(iVar8 + 0xa8c);
  if (bVar1 == 4) {
    unaff_r30 = 0x4963b;
    unaff_r29 = 0x4963c;
    unaff_r28 = 0x4963d;
    unaff_r27 = 0x4963e;
    unaff_r24 = 0x8f9;
    unaff_r23 = 0x85d;
  }
  else if ((bVar1 < 4) && (bVar1 == 1)) {
    unaff_r30 = 0x1602;
    unaff_r29 = 0x454bc;
    unaff_r28 = 0x454b8;
    unaff_r27 = 0x454b9;
    unaff_r24 = 0x172;
    unaff_r23 = 0x9ed;
  }
  if ((*(char *)((int)puVar7 + 0x27a) != '\0') &&
     (puVar7[0xa8] = (uint)FLOAT_803e8f14, *(short *)(uVar3 + 0xa0) != 0x13)) {
    FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar3,0x13,0,in_r6,in_r7,in_r8,in_r9,in_r10);
  }
  uVar5 = FUN_80020078(unaff_r24);
  if ((((uVar5 == 0) || (uVar5 = FUN_80020078(unaff_r23), uVar5 == 0)) || (iVar4 == 0)) ||
     (dVar9 = (double)FUN_800217c8((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18)),
     (double)FLOAT_803e8f24 <= dVar9)) {
    *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) | 8;
    bVar1 = *(byte *)(iVar8 + 0xa91);
    if (bVar1 == 1) {
      dVar9 = (double)FUN_800217c8((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18));
      if (dVar9 < (double)FLOAT_803e8f28) {
        iVar4 = FUN_8002e1ac(unaff_r30);
        if (iVar4 != 0) {
          FUN_8014cab4(iVar4);
        }
        iVar4 = FUN_8002e1ac(unaff_r29);
        if (iVar4 != 0) {
          FUN_8014cab4(iVar4);
        }
        *(undefined *)(iVar8 + 0xa91) = 2;
      }
    }
    else if ((bVar1 == 0) || (bVar1 < 3)) {
      if ((bVar1 == 0) ||
         (dVar9 = (double)FUN_800217c8((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18)),
         (double)FLOAT_803e8ed8 < dVar9)) {
        iVar4 = FUN_8002e1ac(unaff_r30);
        iVar6 = FUN_8002e1ac(unaff_r28);
        if ((iVar4 != 0) && (iVar6 != 0)) {
          FUN_8014cae4(iVar4,iVar6);
        }
        iVar4 = FUN_8002e1ac(unaff_r29);
        iVar6 = FUN_8002e1ac(unaff_r27);
        if ((iVar4 != 0) && (iVar6 != 0)) {
          FUN_8014cae4(iVar4,iVar6);
        }
        *(undefined *)(iVar8 + 0xa91) = 1;
      }
      else {
        uVar5 = FUN_80022150((double)FLOAT_803e8f2c,(double)FLOAT_803e8f1c,(float *)(iVar8 + 0xd08))
        ;
        if (uVar5 != 0) {
          FUN_8000bb38(uVar3,0x375);
        }
      }
    }
  }
  else {
    bVar1 = *(byte *)(iVar8 + 0xa8c);
    if (bVar1 == 4) {
      *(undefined *)(iVar8 + 0xa8d) = 9;
      FUN_800201ac(0x1db,1);
    }
    else if ((bVar1 < 4) && (bVar1 == 1)) {
      *(undefined *)(iVar8 + 0xa8d) = 0;
      FUN_800201ac(0x245,1);
      FUN_800201ac(0x27,1);
    }
    (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(iVar8 + 0xa8d),uVar3,0xffffffff);
    FUN_80014b68(0,0x100);
  }
  FUN_80286878();
  return;
}

