// Function: FUN_802b8488
// Entry: 802b8488
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x802b8848) */
/* WARNING: Removing unreachable block (ram,0x802b8498) */

void FUN_802b8488(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  short *psVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  ushort *puVar7;
  int iVar8;
  undefined8 extraout_f1;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar8 = *(int *)(*(int *)(psVar2 + 0x5c) + 0x40c);
  uVar10 = extraout_f1;
  if (*(int *)(iVar5 + 0x2d0) != 0) {
    in_r6 = 0x19;
    FUN_8003b1c8(psVar2,*(int *)(iVar5 + 0x2d0),*(int *)(psVar2 + 0x5c) + 0x3ac,0x19);
  }
  if (*(int *)(psVar2 + 0x7c) == 0) {
    *(undefined2 *)(iVar8 + 0x1a) = *(undefined2 *)(iVar8 + 0x1c);
    *(undefined2 *)(iVar8 + 0x1c) = *(undefined2 *)(iVar8 + 0x18);
    *(short *)(iVar8 + 0x18) =
         *(short *)(iVar8 + 0x18) + (short)(int)(FLOAT_803e8e44 * FLOAT_803dc074);
  }
  if (*(ushort *)(iVar8 + 0x24) < 4) {
    dVar9 = (double)FUN_802945e0();
    param_2 = (double)FLOAT_803e8e48;
    sVar1 = (short)(int)(param_2 * dVar9);
    iVar6 = (int)sVar1;
    uVar4 = (int)(param_2 * (double)*(float *)(&DAT_80335c38 + (uint)*(byte *)(iVar8 + 0x2d) * 4)) &
            0xffff;
    if ((*(int *)(psVar2 + 0x7c) == 0) &&
       ((int)*(short *)(iVar8 + 0x1c) * (int)*(short *)(iVar8 + 0x18) < 0)) {
      FUN_8000bb38(0,0x44c);
    }
    FUN_8011f6d0(6);
    FUN_8011f9c4(0x60,(char)uVar4,sVar1);
    uVar3 = FUN_80014e9c(0);
    if (((uVar3 & 0x100) != 0) && (*(int *)(psVar2 + 0x7c) == 0)) {
      if (iVar6 < 0) {
        iVar6 = -iVar6;
      }
      if ((int)uVar4 < iVar6) {
        FUN_8000bb38(0,0x487);
        psVar2[0x7c] = 0;
        psVar2[0x7d] = 3;
      }
      else {
        FUN_8000bb38(0,0x109);
        psVar2[0x7c] = 0;
        psVar2[0x7d] = 2;
      }
      FUN_8011f9b8(0);
    }
  }
  else {
    FUN_8011f9b8(0);
  }
  if ((*(char *)(iVar5 + 0x346) != '\0') || (*(char *)(iVar5 + 0x27a) != '\0')) {
    if (*(char *)(iVar5 + 0x27a) != '\0') {
      *(undefined *)(iVar8 + 0x2d) = 0;
      iVar6 = 0;
      puVar7 = &DAT_80335c28;
      do {
        uVar4 = FUN_80020078((uint)*puVar7);
        if (uVar4 != 0) {
          *(char *)(iVar8 + 0x2d) = *(char *)(iVar8 + 0x2d) + '\x01';
        }
        puVar7 = puVar7 + 1;
        iVar6 = iVar6 + 1;
      } while (iVar6 < 8);
      uVar4 = FUN_80022264(0,0xffff);
      *(short *)(iVar8 + 0x18) = (short)uVar4;
      *(undefined2 *)(iVar8 + 0x1c) = *(undefined2 *)(iVar8 + 0x18);
      *(undefined2 *)(iVar8 + 0x1a) = *(undefined2 *)(iVar8 + 0x1c);
      param_2 = (double)FLOAT_803e8e4c;
      dVar9 = (double)FUN_802945e0();
      FUN_8011f9c4(0x60,(char)(int)(FLOAT_803e8e54 *
                                   *(float *)(&DAT_80335c38 + (uint)*(byte *)(iVar8 + 0x2d) * 4)),
                   (short)(int)((double)FLOAT_803e8e48 * dVar9));
      FUN_8011f9b8(1);
      FUN_8011f6d0(6);
    }
    iVar6 = *(int *)(psVar2 + 0x26);
    if (*(char *)(iVar5 + 0x27a) == '\0') {
      *(short *)(iVar8 + 0x24) = *(short *)(iVar8 + 0x24) + 1;
    }
    else {
      *(undefined2 *)(iVar8 + 0x24) = 0;
      *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(iVar6 + 0x10);
    }
    if (*(short *)(&DAT_80335ba8 + (uint)*(ushort *)(iVar8 + 0x24) * 2) == -1) {
      *(undefined2 *)(iVar8 + 0x24) = 0;
      *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(iVar6 + 0x10);
      FUN_800201ac((int)*(short *)(iVar6 + 0x1a),1);
      FUN_800201ac((int)*(short *)(iVar6 + 0x30),0);
      goto LAB_802b8848;
    }
    FUN_8003042c((double)FLOAT_803e8e18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 psVar2,(int)*(short *)(&DAT_80335ba8 + (uint)*(ushort *)(iVar8 + 0x24) * 2),0,in_r6
                 ,in_r7,in_r8,in_r9,in_r10);
  }
  *(undefined4 *)(iVar5 + 0x2a0) =
       *(undefined4 *)(&DAT_80335bc4 + (uint)*(ushort *)(iVar8 + 0x24) * 4);
  (**(code **)(*DAT_803dd70c + 0x20))(uVar10,psVar2,iVar5,1);
LAB_802b8848:
  FUN_80286888();
  return;
}

