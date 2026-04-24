// Function: FUN_80138180
// Entry: 80138180
// Size: 2776 bytes

void FUN_80138180(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  code *pcVar6;
  undefined4 uVar7;
  int in_r7;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  uint uVar13;
  undefined8 uVar14;
  
  FUN_80286834();
  piVar11 = (int *)0x0;
  iVar10 = 0;
  iVar9 = 0xb4;
  if (DAT_803de6a8 == '\0') {
    do {
      if (DAT_803de6a8 != '\0') {
        iVar9 = 0;
        iVar10 = 0;
        do {
          iVar2 = 0;
          iVar5 = 0x3c;
          do {
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0x500) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0xa00) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0xf00) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0x1400) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0x1900) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0x1e00) = 0x1080;
            *(undefined2 *)(iVar10 + DAT_803de6b0 + iVar2 + 0x2300) = 0x1080;
            iVar2 = iVar2 + 0x2800;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
          iVar10 = iVar10 + 2;
          iVar9 = iVar9 + 1;
        } while (iVar9 < 0x280);
      }
      if (DAT_803de6a8 != '\0') {
        FUN_80242114(DAT_803de6b0,0x96000);
        bVar1 = DAT_803de6b0 == DAT_803dd96c;
        DAT_803de6b0 = DAT_803dd96c;
        if (bVar1) {
          DAT_803de6b0 = DAT_803dd968;
        }
        bVar1 = DAT_803de6ac == DAT_803dd96c;
        DAT_803de6ac = DAT_803dd96c;
        if (bVar1) {
          DAT_803de6ac = DAT_803dd968;
        }
        FUN_8024ddd4(DAT_803de6ac);
        FUN_8024dcb8();
        FUN_8024d054();
      }
    } while( true );
  }
  DAT_803de6b0 = DAT_803dd96c;
  DAT_803de6ac = DAT_803dd968;
  FUN_80243e74();
  FUN_8024c8cc(0);
  FUN_8024c910(0);
  FUN_80256bc4(0);
  uVar14 = FUN_80258a94();
  FUN_80243e9c();
  do {
    if (DAT_803de6a8 != '\0') {
      iVar2 = 0;
      iVar5 = 0;
      do {
        iVar4 = 0;
        iVar12 = 0x3c;
        do {
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0x500) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0xa00) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0xf00) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0x1400) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0x1900) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0x1e00) = 0x1080;
          *(undefined2 *)(iVar5 + DAT_803de6b0 + iVar4 + 0x2300) = 0x1080;
          iVar4 = iVar4 + 0x2800;
          iVar12 = iVar12 + -1;
        } while (iVar12 != 0);
        iVar5 = iVar5 + 2;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0x280);
    }
    pcVar6 = FUN_80138180;
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,0x15,
                          s_errorThreadFunc__x_8031ddf0,FUN_80138180,in_r7,in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,0x2a,
                          s_Exception__8031de04,pcVar6,in_r7,in_r8,in_r9,in_r10);
    switch(DAT_803de6c0) {
    case 0:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,s_System_reset_8031de10,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    case 1:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,s_Machine_check_8031de20,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    case 2:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,&DAT_803dc880,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    case 3:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,&DAT_803dc884,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    default:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x9b,0x2a
                            ,s_Unknown_error_8031de84,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    case 5:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,s_Alignment_8031de30,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    case 0xb:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x9b,0x2a
                            ,s_Performance_monitor_8031de3c,pcVar6,in_r7,in_r8,in_r9,in_r10);
      break;
    case 0xd:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,s_System_management_interrupt_8031de50,pcVar6,in_r7,in_r8,in_r9,in_r10)
      ;
      break;
    case 0xf:
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xa0,0x2a
                            ,s_Memory_Protection_Error_8031de6c,pcVar6,in_r7,in_r8,in_r9,in_r10);
    }
    if (DAT_803de6a8 != '\0') {
      in_r7 = 0x9100;
      in_r8 = 0x8e80;
      iVar5 = 0x11d00;
      iVar2 = 0x12200;
      iVar4 = 0x80;
      do {
        *(undefined2 *)(DAT_803de6b0 + iVar2) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 2) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 2) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 4) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 4) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 6) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 6) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 8) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 8) = 0xc080;
        in_r7 = in_r7 + 5;
        iVar2 = iVar2 + 10;
        in_r8 = in_r8 + 5;
        iVar5 = iVar5 + 10;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,0x3f,
                          &DAT_803dc888,*(undefined4 *)(DAT_803de6bc + 0x198),in_r7,in_r8,in_r9,
                          in_r10);
    uVar7 = *(undefined4 *)(DAT_803de6bc + 4);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,0x4b,
                          &DAT_803dc890,uVar7,in_r7,in_r8,in_r9,in_r10);
    if (DAT_803de6a8 != '\0') {
      in_r7 = 0xe380;
      in_r8 = 0xe100;
      uVar7 = 0xc080;
      iVar5 = 0x1c200;
      iVar2 = 0x1c700;
      iVar4 = 0x28;
      do {
        *(undefined2 *)(DAT_803de6b0 + iVar2) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 2) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 2) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 4) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 4) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 6) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 6) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 8) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 8) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar2 + 10) = 0xc080;
        *(undefined2 *)(DAT_803de6b0 + iVar5 + 10) = 0xc080;
        in_r7 = in_r7 + 6;
        iVar2 = iVar2 + 0xc;
        in_r8 = in_r8 + 6;
        iVar5 = iVar5 + 0xc;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,0x60,
                          s_Stack_trace_8031de94,uVar7,in_r7,in_r8,in_r9,in_r10);
    iVar5 = 0x6c;
    puVar8 = (undefined4 *)**(undefined4 **)(DAT_803de6bc + 4);
    iVar2 = 0;
    while ((puVar8 != (undefined4 *)0xffffffff && (bVar1 = iVar2 != 8, iVar2 = iVar2 + 1, bVar1))) {
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,
                            iVar5,&DAT_803dc898,puVar8[1],in_r7,in_r8,in_r9,in_r10);
      iVar5 = iVar5 + 0xc;
      puVar8 = (undefined4 *)*puVar8;
    }
    iVar5 = iVar5 + (8 - iVar2) * 0xc;
    if (DAT_803de6a8 != '\0') {
      iVar2 = iVar5 + 0x4c;
      in_r8 = (iVar5 + 0x4b) * 0x280;
      if (iVar2 < 1) {
        iVar2 = iVar2 * 0x500;
        iVar4 = 0x40;
        do {
          *(undefined2 *)(DAT_803de6b0 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 4) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 6) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 8) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 10) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 0xc) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 0xe) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x10) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x12) = 0xc080;
          iVar2 = iVar2 + 0x14;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        iVar4 = (iVar5 + 0x4b) * 0x500;
        iVar2 = iVar2 * 0x500;
        iVar12 = 0x80;
        do {
          *(undefined2 *)(DAT_803de6b0 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 4) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4 + 4) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 6) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4 + 6) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 8) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4 + 8) = 0xc080;
          iVar2 = iVar2 + 10;
          in_r8 = in_r8 + 5;
          iVar4 = iVar4 + 10;
          iVar12 = iVar12 + -1;
        } while (iVar12 != 0);
      }
    }
    if (DAT_803de6a8 != '\0') {
      iVar2 = 0x12700;
      uVar3 = iVar5 + 0x11;
      if (0x3b < iVar5 + 0x4c) {
        uVar13 = uVar3 >> 3;
        if (uVar13 != 0) {
          do {
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x1e0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x6e0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0xbe0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x10e0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x15e0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x1ae0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x1fe0) = 0xc080;
            *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x24e0) = 0xc080;
            iVar2 = iVar2 + 0x2800;
            uVar13 = uVar13 - 1;
          } while (uVar13 != 0);
          uVar3 = uVar3 & 7;
          if (uVar3 == 0) goto LAB_80138804;
        }
        do {
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 0x1e0) = 0xc080;
          iVar2 = iVar2 + 0x500;
          uVar3 = uVar3 - 1;
        } while (uVar3 != 0);
      }
    }
LAB_80138804:
    iVar5 = iVar5 + 0x51;
    if (piVar11 == (int *)0x0) {
      piVar11 = *(int **)(DAT_803de6bc + 4);
      iVar10 = 0;
    }
    else {
      bVar1 = iVar9 == 0;
      iVar9 = iVar9 + -1;
      if (bVar1) {
        iVar9 = 0xb4;
        piVar11 = (int *)*piVar11;
        iVar10 = iVar10 + 1;
        if (piVar11 == (int *)0xffffffff) {
          piVar11 = *(int **)(DAT_803de6bc + 4);
          iVar10 = 0;
        }
      }
    }
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x3f,
                          s_Stack__x__depth__d_8031dea0,piVar11,iVar10,in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x4b,
                          s__08x__08x_8031deb4,piVar11[-1],piVar11[-2],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x57,
                          s__08x__08x_8031deb4,piVar11[-3],piVar11[-4],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,99,
                          s__08x__08x_8031deb4,piVar11[-5],piVar11[-6],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x6f,
                          s__08x__08x_8031deb4,piVar11[-7],piVar11[-8],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x7b,
                          s__08x__08x_8031deb4,piVar11[-9],piVar11[-10],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x87,
                          s__08x__08x_8031deb4,piVar11[-0xb],piVar11[-0xc],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x93,
                          s__08x__08x_8031deb4,piVar11[-0xd],piVar11[-0xe],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0x9f,
                          s__08x__08x_8031deb4,piVar11[-0xf],piVar11[-0x10],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xab,
                          s__08x__08x_8031deb4,piVar11[-0x11],piVar11[-0x12],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xb7,
                          s__08x__08x_8031deb4,piVar11[-0x13],piVar11[-0x14],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xc3,
                          s__08x__08x_8031deb4,piVar11[-0x15],piVar11[-0x16],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xcf,
                          s__08x__08x_8031deb4,piVar11[-0x17],piVar11[-0x18],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xdb,
                          s__08x__08x_8031deb4,piVar11[-0x19],piVar11[-0x1a],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xe7,
                          s__08x__08x_8031deb4,piVar11[-0x1b],piVar11[-0x1c],in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xf3,
                          s__08x__08x_8031deb4,piVar11[-0x1d],piVar11[-0x1e],in_r8,in_r9,in_r10);
    iVar2 = piVar11[-0x1f];
    in_r7 = piVar11[-0x20];
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x100,0xff,
                          s__08x__08x_8031deb4,iVar2,in_r7,in_r8,in_r9,in_r10);
    uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,iVar5,
                          s_General_Purpose_Registers_8031dec0,iVar2,in_r7,in_r8,in_r9,in_r10);
    for (uVar3 = 0; (uVar3 & 0xff) < 0x20; uVar3 = uVar3 + 8) {
      uVar13 = uVar3 & 0xff;
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xc,
                            iVar5 + 0xc,s__d____d_803dc89c,uVar13,uVar13 + 7,in_r8,in_r9,in_r10);
      iVar2 = DAT_803de6bc + uVar13 * 4;
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,
                            iVar5 + 0x18,s__08x__08x__08x__08x_8031dedc,
                            *(undefined4 *)(DAT_803de6bc + (uVar3 & 0xff) * 4),
                            *(undefined4 *)(iVar2 + 4),*(undefined4 *)(iVar2 + 8),
                            *(undefined4 *)(iVar2 + 0xc),in_r10);
      iVar5 = iVar5 + 0x24;
      iVar2 = DAT_803de6bc + uVar13 * 4;
      in_r7 = *(int *)(iVar2 + 0x14);
      in_r8 = *(int *)(iVar2 + 0x18);
      in_r9 = *(undefined4 *)(iVar2 + 0x1c);
      uVar14 = FUN_80137f08(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x10,
                            iVar5,s__08x__08x__08x__08x_8031dedc,*(undefined4 *)(iVar2 + 0x10),in_r7
                            ,in_r8,in_r9,in_r10);
    }
    if (DAT_803de6a8 != '\0') {
      FUN_80242114(DAT_803de6b0,0x96000);
      bVar1 = DAT_803de6b0 == DAT_803dd96c;
      DAT_803de6b0 = DAT_803dd96c;
      if (bVar1) {
        DAT_803de6b0 = DAT_803dd968;
      }
      bVar1 = DAT_803de6ac == DAT_803dd96c;
      DAT_803de6ac = DAT_803dd96c;
      if (bVar1) {
        DAT_803de6ac = DAT_803dd968;
      }
      FUN_8024ddd4(DAT_803de6ac);
      FUN_8024dcb8();
      uVar14 = FUN_8024d054();
    }
  } while( true );
}

