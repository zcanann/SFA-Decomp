// Function: FUN_802b7d28
// Entry: 802b7d28
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x802b80e8) */

void FUN_802b7d28(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined2 uVar6;
  undefined4 uVar5;
  int iVar7;
  int iVar8;
  undefined2 *puVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 extraout_f1;
  double dVar12;
  undefined8 in_f31;
  undefined8 uVar13;
  double local_48;
  double local_38;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar13 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  iVar7 = (int)uVar13;
  iVar10 = *(int *)(*(int *)(iVar2 + 0xb8) + 0x40c);
  uVar13 = extraout_f1;
  if (*(int *)(iVar7 + 0x2d0) != 0) {
    FUN_8003b0d0(iVar2,*(int *)(iVar7 + 0x2d0),*(int *)(iVar2 + 0xb8) + 0x3ac,0x19);
  }
  if (*(int *)(iVar2 + 0xf8) == 0) {
    *(undefined2 *)(iVar10 + 0x1a) = *(undefined2 *)(iVar10 + 0x1c);
    *(undefined2 *)(iVar10 + 0x1c) = *(undefined2 *)(iVar10 + 0x18);
    *(short *)(iVar10 + 0x18) =
         *(short *)(iVar10 + 0x18) + (short)(int)(FLOAT_803e81ac * FLOAT_803db414);
  }
  if (*(ushort *)(iVar10 + 0x24) < 4) {
    local_48 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 0x18));
    dVar12 = (double)FUN_80293e80((double)((FLOAT_803e81b4 * (float)(local_48 - DOUBLE_803e81a0)) /
                                          FLOAT_803e81b8));
    iVar8 = (int)(short)(int)((double)FLOAT_803e81b0 * dVar12);
    uVar1 = (uint)((double)FLOAT_803e81b0 *
                  (double)*(float *)(&DAT_80334fd8 + (uint)*(byte *)(iVar10 + 0x2d) * 4));
    if ((*(int *)(iVar2 + 0xf8) == 0) &&
       ((int)*(short *)(iVar10 + 0x1c) * (int)*(short *)(iVar10 + 0x18) < 0)) {
      FUN_8000bb18(0,0x44c);
    }
    FUN_8011f3ec(6);
    FUN_8011f6e0(0x60,uVar1 & 0xff,iVar8);
    uVar3 = FUN_80014e70(0);
    if (((uVar3 & 0x100) != 0) && (*(int *)(iVar2 + 0xf8) == 0)) {
      if (iVar8 < 0) {
        iVar8 = -iVar8;
      }
      if ((int)(uVar1 & 0xffff) < iVar8) {
        FUN_8000bb18(0,0x487);
        *(undefined4 *)(iVar2 + 0xf8) = 3;
      }
      else {
        FUN_8000bb18(0,0x109);
        *(undefined4 *)(iVar2 + 0xf8) = 2;
      }
      FUN_8011f6d4(0);
    }
  }
  else {
    FUN_8011f6d4(0);
  }
  if ((*(char *)(iVar7 + 0x346) != '\0') || (*(char *)(iVar7 + 0x27a) != '\0')) {
    if (*(char *)(iVar7 + 0x27a) != '\0') {
      *(undefined *)(iVar10 + 0x2d) = 0;
      iVar8 = 0;
      puVar9 = &DAT_80334fc8;
      do {
        iVar4 = FUN_8001ffb4(*puVar9);
        if (iVar4 != 0) {
          *(char *)(iVar10 + 0x2d) = *(char *)(iVar10 + 0x2d) + '\x01';
        }
        puVar9 = puVar9 + 1;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 8);
      uVar6 = FUN_800221a0(0,0xffff);
      *(undefined2 *)(iVar10 + 0x18) = uVar6;
      *(undefined2 *)(iVar10 + 0x1c) = *(undefined2 *)(iVar10 + 0x18);
      *(undefined2 *)(iVar10 + 0x1a) = *(undefined2 *)(iVar10 + 0x1c);
      local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 0x18));
      dVar12 = (double)FUN_80293e80((double)((FLOAT_803e81b4 * (float)(local_38 - DOUBLE_803e81a0))
                                            / FLOAT_803e81b8));
      FUN_8011f6e0(0x60,(int)(FLOAT_803e81bc *
                             *(float *)(&DAT_80334fd8 + (uint)*(byte *)(iVar10 + 0x2d) * 4)) & 0xff,
                   (int)((double)FLOAT_803e81b0 * dVar12));
      FUN_8011f6d4(1);
      FUN_8011f3ec(6);
    }
    iVar8 = *(int *)(iVar2 + 0x4c);
    if (*(char *)(iVar7 + 0x27a) == '\0') {
      *(short *)(iVar10 + 0x24) = *(short *)(iVar10 + 0x24) + 1;
    }
    else {
      *(undefined2 *)(iVar10 + 0x24) = 0;
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
    }
    if (*(short *)(&DAT_80334f48 + (uint)*(ushort *)(iVar10 + 0x24) * 2) == -1) {
      *(undefined2 *)(iVar10 + 0x24) = 0;
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
      FUN_800200e8((int)*(short *)(iVar8 + 0x1a),1);
      FUN_800200e8((int)*(short *)(iVar8 + 0x30),0);
      uVar5 = 3;
      goto LAB_802b80e8;
    }
    FUN_80030334((double)FLOAT_803e8180,iVar2,
                 (int)*(short *)(&DAT_80334f48 + (uint)*(ushort *)(iVar10 + 0x24) * 2),0);
  }
  *(undefined4 *)(iVar7 + 0x2a0) =
       *(undefined4 *)(&DAT_80334f64 + (uint)*(ushort *)(iVar10 + 0x24) * 4);
  (**(code **)(*DAT_803dca8c + 0x20))(uVar13,iVar2,iVar7,1);
  uVar5 = 0;
LAB_802b80e8:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286124(uVar5);
  return;
}

