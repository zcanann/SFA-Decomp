// Function: FUN_80053078
// Entry: 80053078
// Size: 1156 bytes

void FUN_80053078(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  double dVar9;
  int local_a8;
  uint local_a4;
  uint local_a0;
  uint local_9c;
  uint local_98;
  uint local_94;
  uint local_90;
  undefined4 local_8c;
  undefined4 local_84;
  undefined4 local_80 [8];
  float afStack_60 [3];
  float local_54;
  float local_44;
  undefined4 local_30;
  uint uStack_2c;
  
  FUN_80286830();
  FUN_80052f3c();
  FUN_80247a7c((double)FLOAT_803df7f4,(double)FLOAT_803df800,(double)FLOAT_803df7f4,afStack_60);
  local_54 = FLOAT_803df7f4;
  local_44 = FLOAT_803df7f4;
  FUN_8025d8c4(afStack_60,0x1e,1);
  local_90 = DAT_803dc260;
  FUN_8025a2ec(4,&local_90);
  local_94 = DAT_803dc260;
  FUN_8025a2ec(5,&local_94);
  FUN_80259504(0x20,0x20,6,0);
  FUN_80089bfc(2);
  iVar6 = 0;
  piVar7 = &DAT_8037ec60;
  uVar8 = 0;
  piVar2 = piVar7;
  do {
    if (((*(short *)(*piVar2 + 0xe) != 0) && (*(char *)((int)piVar2 + 0x1b) == '\x01')) &&
       (DAT_803dda24 == *(char *)((int)piVar2 + 0x1a))) {
      local_8c = ((uint)*(byte *)(piVar2 + 3) * (uint)*(byte *)(piVar2 + 6) >> 8) << 0x18;
      local_8c = CONCAT31(CONCAT21(local_8c._0_2_,
                                   (char)((uint)*(byte *)((int)piVar2 + 0xe) *
                                          (uint)*(byte *)((int)piVar2 + 0x19) >> 8)),0xff);
      local_98 = local_8c;
      FUN_8025a454(4,&local_98);
      local_9c = local_8c;
      FUN_8025a454(5,&local_9c);
      FUN_80052d30(piVar2[1],(float *)(piVar2 + 4));
      FUN_80052a6c();
      FUN_8005009c(DAT_803dda20);
      FUN_80052a38();
      uStack_2c = uVar8 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80052af0();
      FUN_80259c0c(*piVar2 + 0x60,0);
      iVar1 = *piVar2;
      if (*(char *)(iVar1 + 0x48) != '\0') {
        FUN_8025b280(iVar1 + 0x20,*(uint **)(iVar1 + 0x40));
      }
    }
    piVar2 = piVar2 + 7;
    uVar8 = uVar8 + 0x20;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 6);
  FUN_80052a6c();
  FUN_80052668((char *)&DAT_803dc264);
  FUN_80052a38();
  local_a0 = DAT_803dc264;
  FUN_8025a454(0,&local_a0);
  iVar6 = 5;
  piVar2 = &DAT_8037ecec;
  iVar1 = 2;
  do {
    if (((((*(short *)(*piVar2 + 0xe) != 0) && (*(char *)((int)piVar2 + 0x1b) == '\0')) &&
         (iVar3 = iVar6, DAT_803dda24 == *(char *)((int)piVar2 + 0x1a))) ||
        (((iVar3 = iVar6 + -1, *(short *)(piVar2[-7] + 0xe) != 0 &&
          (*(char *)((int)piVar2 + -1) == '\0')) && (DAT_803dda24 == *(char *)((int)piVar2 + -2)))))
       || (((*(short *)(piVar2[-0xe] + 0xe) != 0 && (*(char *)((int)piVar2 + -0x1d) == '\0')) &&
           (iVar3 = iVar6 + -2, DAT_803dda24 == *(char *)((int)piVar2 + -0x1e))))) break;
    piVar2 = piVar2 + -0x15;
    iVar6 = iVar6 + -3;
    iVar1 = iVar1 + -1;
    iVar3 = 5;
  } while (iVar1 != 0);
  iVar6 = 0;
  uVar8 = 0;
  do {
    if (((*(short *)(*piVar7 + 0xe) != 0) && (*(char *)((int)piVar7 + 0x1b) == '\0')) &&
       (DAT_803dda24 == *(char *)((int)piVar7 + 0x1a))) {
      iVar1 = piVar7[1];
      FUN_80089bfc(2 - (iVar6 + -3));
      FUN_8001ed58(iVar1,local_80,8,&local_a8,4);
      FUN_8001e9b8(1);
      FUN_8001e6cc(0,0,0);
      puVar4 = local_80;
      for (iVar5 = 0; iVar5 < local_a8; iVar5 = iVar5 + 1) {
        FUN_8001e568(0,*puVar4,iVar1);
        puVar4 = puVar4 + 1;
      }
      FUN_8001e6f8();
      FUN_8001f07c(0,(undefined *)&local_84,(undefined *)((int)&local_84 + 1),
                   (undefined *)((int)&local_84 + 2));
      local_a4 = local_84;
      FUN_8025a2ec(0,&local_a4);
      uStack_2c = uVar8 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80052af0();
      FUN_80259c0c(*piVar7 + 0x60,iVar6 == iVar3);
      iVar1 = *piVar7;
      if (*(char *)(iVar1 + 0x48) != '\0') {
        FUN_8025b280(iVar1 + 0x20,*(uint **)(iVar1 + 0x40));
      }
    }
    piVar7 = piVar7 + 7;
    uVar8 = uVar8 + 0x20;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 6);
  dVar9 = (double)FLOAT_803df7e0;
  FUN_8025da64(dVar9,dVar9,(double)FLOAT_803df804,(double)FLOAT_803df808,dVar9,
               (double)FLOAT_803df7dc);
  FUN_8025da88(0,0,0x280,0x1e0);
  FUN_80259340(0,0,0x280,0x1e0);
  FUN_802594c0(0x280);
  FUN_80259400(0,0,0x280,0x1e0);
  FUN_8000f7a0();
  DAT_803dda24 = 0;
  FUN_8028687c();
  return;
}

