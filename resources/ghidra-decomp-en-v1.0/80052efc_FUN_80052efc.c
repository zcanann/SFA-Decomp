// Function: FUN_80052efc
// Entry: 80052efc
// Size: 1156 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80052efc(void)

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
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  int local_8c;
  undefined auStack136 [4];
  undefined4 local_84;
  undefined4 local_80 [8];
  undefined auStack96 [12];
  float local_54;
  float local_44;
  undefined4 local_30;
  uint uStack44;
  
  FUN_802860cc();
  FUN_80052dc0();
  FUN_80247318((double)FLOAT_803deb74,(double)FLOAT_803deb80,(double)FLOAT_803deb74,auStack96);
  local_54 = FLOAT_803deb74;
  local_44 = FLOAT_803deb74;
  FUN_8025d160(auStack96,0x1e,1);
  local_90 = DAT_803db600;
  FUN_80259b88(4,&local_90);
  local_94 = DAT_803db600;
  FUN_80259b88(5,&local_94);
  FUN_80258da0(0x20,0x20,6,0);
  FUN_80089970(2);
  iVar6 = 0;
  piVar7 = &DAT_8037e000;
  uVar8 = 0;
  piVar2 = piVar7;
  do {
    if (((*(short *)(*piVar2 + 0xe) != 0) && (*(char *)((int)piVar2 + 0x1b) == '\x01')) &&
       (DAT_803dcda4 == *(char *)((int)piVar2 + 0x1a))) {
      local_8c = ((uint)*(byte *)(piVar2 + 3) * (uint)*(byte *)(piVar2 + 6) >> 8) << 0x18;
      local_8c = CONCAT31(CONCAT21(local_8c._0_2_,
                                   (char)((uint)*(byte *)((int)piVar2 + 0xe) *
                                          (uint)*(byte *)((int)piVar2 + 0x19) >> 8)),0xff);
      local_98 = local_8c;
      FUN_80259cf0(4,&local_98);
      local_9c = local_8c;
      FUN_80259cf0(5,&local_9c);
      FUN_80052bb4(piVar2[1],piVar2 + 4);
      FUN_800528f0();
      FUN_8004ff20(DAT_803dcda0,auStack96,auStack136,0);
      FUN_800528bc();
      uStack44 = uVar8 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80052974((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803deb90),
                   (double)FLOAT_803deb60);
      FUN_802594a8(*piVar2 + 0x60,0);
      iVar1 = *piVar2;
      if (*(char *)(iVar1 + 0x48) != '\0') {
        FUN_8025ab1c(iVar1 + 0x20,*(undefined4 *)(iVar1 + 0x40));
      }
    }
    piVar2 = piVar2 + 7;
    uVar8 = uVar8 + 0x20;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 6);
  FUN_800528f0();
  FUN_800524ec(&DAT_803db604);
  FUN_800528bc();
  local_a0 = DAT_803db604;
  FUN_80259cf0(0,&local_a0);
  iVar6 = 5;
  piVar2 = &DAT_8037e08c;
  iVar1 = 2;
  do {
    if (((((*(short *)(*piVar2 + 0xe) != 0) && (*(char *)((int)piVar2 + 0x1b) == '\0')) &&
         (iVar3 = iVar6, DAT_803dcda4 == *(char *)((int)piVar2 + 0x1a))) ||
        (((iVar3 = iVar6 + -1, *(short *)(piVar2[-7] + 0xe) != 0 &&
          (*(char *)((int)piVar2 + -1) == '\0')) && (DAT_803dcda4 == *(char *)((int)piVar2 + -2)))))
       || (((*(short *)(piVar2[-0xe] + 0xe) != 0 && (*(char *)((int)piVar2 + -0x1d) == '\0')) &&
           (iVar3 = iVar6 + -2, DAT_803dcda4 == *(char *)((int)piVar2 + -0x1e))))) break;
    piVar2 = piVar2 + -0x15;
    iVar6 = iVar6 + -3;
    iVar1 = iVar1 + -1;
    iVar3 = 5;
  } while (iVar1 != 0);
  iVar6 = 0;
  uVar8 = 0;
  do {
    if (((*(short *)(*piVar7 + 0xe) != 0) && (*(char *)((int)piVar7 + 0x1b) == '\0')) &&
       (DAT_803dcda4 == *(char *)((int)piVar7 + 0x1a))) {
      iVar1 = piVar7[1];
      FUN_80089970(2 - (iVar6 + -3));
      FUN_8001ec94(iVar1,local_80,8,&local_a8,4);
      FUN_8001e8f4(1);
      FUN_8001e608(0,0,0);
      puVar4 = local_80;
      for (iVar5 = 0; iVar5 < local_a8; iVar5 = iVar5 + 1) {
        FUN_8001e4a4(0,*puVar4,iVar1);
        puVar4 = puVar4 + 1;
      }
      FUN_8001e634();
      FUN_8001efb8(0,&local_84,(int)&local_84 + 1,(int)&local_84 + 2);
      local_a4 = local_84;
      FUN_80259b88(0,&local_a4);
      uStack44 = uVar8 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80052974((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803deb90),
                   (double)FLOAT_803deb60);
      FUN_802594a8(*piVar7 + 0x60,iVar6 == iVar3);
      iVar1 = *piVar7;
      if (*(char *)(iVar1 + 0x48) != '\0') {
        FUN_8025ab1c(iVar1 + 0x20,*(undefined4 *)(iVar1 + 0x40));
      }
    }
    piVar7 = piVar7 + 7;
    uVar8 = uVar8 + 0x20;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 6);
  dVar9 = (double)FLOAT_803deb60;
  FUN_8025d300(dVar9,dVar9,(double)FLOAT_803deb84,(double)FLOAT_803deb88,dVar9,
               (double)FLOAT_803deb5c);
  FUN_8025d324(0,0,0x280,0x1e0);
  FUN_80258bdc(0,0,0x280,0x1e0);
  FUN_80258d5c(0x280,0x1e0);
  FUN_80258c9c(0,0,0x280,0x1e0);
  FUN_8000f780();
  DAT_803dcda4 = 0;
  FUN_80286118();
  return;
}

