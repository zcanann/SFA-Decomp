// Function: FUN_80137df8
// Entry: 80137df8
// Size: 2776 bytes

void FUN_80137df8(void)

{
  bool bVar1;
  undefined uVar4;
  int iVar2;
  uint uVar3;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  uint uVar12;
  
  FUN_802860d0();
  piVar10 = (int *)0x0;
  iVar9 = 0;
  iVar8 = 0xb4;
  if (DAT_803dda28 == '\0') {
    do {
      if (DAT_803dda28 != '\0') {
        iVar8 = 0;
        iVar9 = 0;
        do {
          iVar2 = 0;
          iVar6 = 0x3c;
          do {
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0x500) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0xa00) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0xf00) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0x1400) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0x1900) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0x1e00) = 0x1080;
            *(undefined2 *)(iVar9 + DAT_803dda30 + iVar2 + 0x2300) = 0x1080;
            iVar2 = iVar2 + 0x2800;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
          iVar9 = iVar9 + 2;
          iVar8 = iVar8 + 1;
        } while (iVar8 < 0x280);
      }
      if (DAT_803dda28 != '\0') {
        FUN_80241a1c(DAT_803dda30,0x96000);
        bVar1 = DAT_803dda30 == DAT_803dccec;
        DAT_803dda30 = DAT_803dccec;
        if (bVar1) {
          DAT_803dda30 = DAT_803dcce8;
        }
        bVar1 = DAT_803dda2c == DAT_803dccec;
        DAT_803dda2c = DAT_803dccec;
        if (bVar1) {
          DAT_803dda2c = DAT_803dcce8;
        }
        FUN_8024d670();
        FUN_8024d554();
        FUN_8024c8f0();
      }
    } while( true );
  }
  DAT_803dda30 = DAT_803dccec;
  DAT_803dda2c = DAT_803dcce8;
  uVar4 = FUN_8024377c();
  FUN_8024c168(0);
  FUN_8024c1ac(0);
  FUN_80256460(0);
  FUN_80258330();
  FUN_802437a4(uVar4);
  do {
    if (DAT_803dda28 != '\0') {
      iVar2 = 0;
      iVar6 = 0;
      do {
        iVar5 = 0;
        iVar11 = 0x3c;
        do {
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0x500) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0xa00) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0xf00) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0x1400) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0x1900) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0x1e00) = 0x1080;
          *(undefined2 *)(iVar6 + DAT_803dda30 + iVar5 + 0x2300) = 0x1080;
          iVar5 = iVar5 + 0x2800;
          iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        iVar6 = iVar6 + 2;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0x280);
    }
    FUN_80137b80(0x10,0x15,s__errorThreadFunc__x_8031d1a0,FUN_80137df8);
    FUN_80137b80(0x10,0x2a,s_Exception__8031d1b4);
    switch(DAT_803dda40) {
    case 0:
      FUN_80137b80(0xa0,0x2a,s_System_reset_8031d1c0);
      break;
    case 1:
      FUN_80137b80(0xa0,0x2a,s_Machine_check_8031d1d0);
      break;
    case 2:
      FUN_80137b80(0xa0,0x2a,&DAT_803dbc18);
      break;
    case 3:
      FUN_80137b80(0xa0,0x2a,&DAT_803dbc1c);
      break;
    default:
      FUN_80137b80(0x9b,0x2a,s_Unknown_error_8031d234);
      break;
    case 5:
      FUN_80137b80(0xa0,0x2a,s_Alignment_8031d1e0);
      break;
    case 0xb:
      FUN_80137b80(0x9b,0x2a,s_Performance_monitor_8031d1ec);
      break;
    case 0xd:
      FUN_80137b80(0xa0,0x2a,s_System_management_interrupt_8031d200);
      break;
    case 0xf:
      FUN_80137b80(0xa0,0x2a,s_Memory_Protection_Error_8031d21c);
    }
    if (DAT_803dda28 != '\0') {
      iVar6 = 0x11d00;
      iVar2 = 0x12200;
      iVar5 = 0x80;
      do {
        *(undefined2 *)(DAT_803dda30 + iVar2) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 2) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 2) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 4) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 4) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 6) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 6) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 8) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 8) = 0xc080;
        iVar2 = iVar2 + 10;
        iVar6 = iVar6 + 10;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    FUN_80137b80(0x10,0x3f,&DAT_803dbc20,*(undefined4 *)(DAT_803dda3c + 0x198));
    FUN_80137b80(0x10,0x4b,&DAT_803dbc28,*(undefined4 *)(DAT_803dda3c + 4));
    if (DAT_803dda28 != '\0') {
      iVar6 = 0x1c200;
      iVar2 = 0x1c700;
      iVar5 = 0x28;
      do {
        *(undefined2 *)(DAT_803dda30 + iVar2) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 2) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 2) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 4) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 4) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 6) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 6) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 8) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 8) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar2 + 10) = 0xc080;
        *(undefined2 *)(DAT_803dda30 + iVar6 + 10) = 0xc080;
        iVar2 = iVar2 + 0xc;
        iVar6 = iVar6 + 0xc;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    FUN_80137b80(0x10,0x60,s_Stack_trace_8031d244);
    iVar6 = 0x6c;
    puVar7 = (undefined4 *)**(undefined4 **)(DAT_803dda3c + 4);
    iVar2 = 0;
    while ((puVar7 != (undefined4 *)0xffffffff && (bVar1 = iVar2 != 8, iVar2 = iVar2 + 1, bVar1))) {
      FUN_80137b80(0x10,iVar6,&DAT_803dbc30,puVar7[1]);
      iVar6 = iVar6 + 0xc;
      puVar7 = (undefined4 *)*puVar7;
    }
    iVar6 = iVar6 + (8 - iVar2) * 0xc;
    if (DAT_803dda28 != '\0') {
      iVar2 = iVar6 + 0x4c;
      if (iVar2 < 1) {
        iVar2 = iVar2 * 0x500;
        iVar5 = 0x40;
        do {
          *(undefined2 *)(DAT_803dda30 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 4) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 6) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 8) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 10) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 0xc) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 0xe) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 0x10) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 0x12) = 0xc080;
          iVar2 = iVar2 + 0x14;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      else {
        iVar5 = (iVar6 + 0x4b) * 0x500;
        iVar2 = iVar2 * 0x500;
        iVar11 = 0x80;
        do {
          *(undefined2 *)(DAT_803dda30 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5 + 2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 4) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5 + 4) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 6) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5 + 6) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar2 + 8) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5 + 8) = 0xc080;
          iVar2 = iVar2 + 10;
          iVar5 = iVar5 + 10;
          iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
      }
    }
    if (DAT_803dda28 != '\0') {
      iVar2 = 0x12700;
      uVar3 = iVar6 + 0x11;
      if (0x3b < iVar6 + 0x4c) {
        uVar12 = uVar3 >> 3;
        if (uVar12 != 0) {
          do {
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x1e0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x6e0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0xbe0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x10e0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x15e0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x1ae0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x1fe0) = 0xc080;
            *(undefined2 *)(DAT_803dda30 + iVar2 + 0x24e0) = 0xc080;
            iVar2 = iVar2 + 0x2800;
            uVar12 = uVar12 - 1;
          } while (uVar12 != 0);
          uVar3 = uVar3 & 7;
          if (uVar3 == 0) goto LAB_8013847c;
        }
        do {
          *(undefined2 *)(DAT_803dda30 + iVar2 + 0x1e0) = 0xc080;
          iVar2 = iVar2 + 0x500;
          uVar3 = uVar3 - 1;
        } while (uVar3 != 0);
      }
    }
LAB_8013847c:
    iVar6 = iVar6 + 0x51;
    if (piVar10 == (int *)0x0) {
      piVar10 = *(int **)(DAT_803dda3c + 4);
      iVar9 = 0;
    }
    else {
      bVar1 = iVar8 == 0;
      iVar8 = iVar8 + -1;
      if (bVar1) {
        iVar8 = 0xb4;
        piVar10 = (int *)*piVar10;
        iVar9 = iVar9 + 1;
        if (piVar10 == (int *)0xffffffff) {
          piVar10 = *(int **)(DAT_803dda3c + 4);
          iVar9 = 0;
        }
      }
    }
    FUN_80137b80(0x100,0x3f,s_Stack__x__depth__d_8031d250,piVar10,iVar9);
    FUN_80137b80(0x100,0x4b,s___08x__08x_8031d264,piVar10[-1],piVar10[-2]);
    FUN_80137b80(0x100,0x57,s___08x__08x_8031d264,piVar10[-3],piVar10[-4]);
    FUN_80137b80(0x100,99,s___08x__08x_8031d264,piVar10[-5],piVar10[-6]);
    FUN_80137b80(0x100,0x6f,s___08x__08x_8031d264,piVar10[-7],piVar10[-8]);
    FUN_80137b80(0x100,0x7b,s___08x__08x_8031d264,piVar10[-9],piVar10[-10]);
    FUN_80137b80(0x100,0x87,s___08x__08x_8031d264,piVar10[-0xb],piVar10[-0xc]);
    FUN_80137b80(0x100,0x93,s___08x__08x_8031d264,piVar10[-0xd],piVar10[-0xe]);
    FUN_80137b80(0x100,0x9f,s___08x__08x_8031d264,piVar10[-0xf],piVar10[-0x10]);
    FUN_80137b80(0x100,0xab,s___08x__08x_8031d264,piVar10[-0x11],piVar10[-0x12]);
    FUN_80137b80(0x100,0xb7,s___08x__08x_8031d264,piVar10[-0x13],piVar10[-0x14]);
    FUN_80137b80(0x100,0xc3,s___08x__08x_8031d264,piVar10[-0x15],piVar10[-0x16]);
    FUN_80137b80(0x100,0xcf,s___08x__08x_8031d264,piVar10[-0x17],piVar10[-0x18]);
    FUN_80137b80(0x100,0xdb,s___08x__08x_8031d264,piVar10[-0x19],piVar10[-0x1a]);
    FUN_80137b80(0x100,0xe7,s___08x__08x_8031d264,piVar10[-0x1b],piVar10[-0x1c]);
    FUN_80137b80(0x100,0xf3,s___08x__08x_8031d264,piVar10[-0x1d],piVar10[-0x1e]);
    FUN_80137b80(0x100,0xff,s___08x__08x_8031d264,piVar10[-0x1f],piVar10[-0x20]);
    FUN_80137b80(0x10,iVar6,s_General_Purpose_Registers_8031d270);
    for (uVar3 = 0; (uVar3 & 0xff) < 0x20; uVar3 = uVar3 + 8) {
      uVar12 = uVar3 & 0xff;
      FUN_80137b80(0xc,iVar6 + 0xc,s__d____d_803dbc34,uVar12,uVar12 + 7);
      iVar2 = DAT_803dda3c + uVar12 * 4;
      FUN_80137b80(0x10,iVar6 + 0x18,s___08x__08x__08x__08x_8031d28c,
                   *(undefined4 *)(DAT_803dda3c + (uVar3 & 0xff) * 4),*(undefined4 *)(iVar2 + 4),
                   *(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc));
      iVar6 = iVar6 + 0x24;
      iVar2 = DAT_803dda3c + uVar12 * 4;
      FUN_80137b80(0x10,iVar6,s___08x__08x__08x__08x_8031d28c,*(undefined4 *)(iVar2 + 0x10),
                   *(undefined4 *)(iVar2 + 0x14),*(undefined4 *)(iVar2 + 0x18),
                   *(undefined4 *)(iVar2 + 0x1c));
    }
    if (DAT_803dda28 != '\0') {
      FUN_80241a1c(DAT_803dda30,0x96000);
      bVar1 = DAT_803dda30 == DAT_803dccec;
      DAT_803dda30 = DAT_803dccec;
      if (bVar1) {
        DAT_803dda30 = DAT_803dcce8;
      }
      bVar1 = DAT_803dda2c == DAT_803dccec;
      DAT_803dda2c = DAT_803dccec;
      if (bVar1) {
        DAT_803dda2c = DAT_803dcce8;
      }
      FUN_8024d670();
      FUN_8024d554();
      FUN_8024c8f0();
    }
  } while( true );
}

