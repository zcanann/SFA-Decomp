// Function: FUN_8024e864
// Entry: 8024e864
// Size: 940 bytes

uint FUN_8024e864(ushort *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  undefined *puVar8;
  uint local_3c [3];
  
  uVar1 = FUN_8024377c();
  iVar6 = 0;
  puVar8 = &DAT_803ae1c0;
  uVar5 = 0;
  do {
    uVar7 = 0x80000000 >> iVar6;
    if ((DAT_803ddfc8 & uVar7) == 0) {
      if ((DAT_803ddfb8 & uVar7) == 0) {
        if (DAT_803dc588 != iVar6) {
          if ((DAT_803ddfb4 & uVar7) == 0) {
            *(undefined *)(param_1 + 5) = 0xff;
            FUN_800033a8(param_1,0,10);
          }
          else {
            iVar3 = FUN_802519c0(iVar6);
            if (iVar3 == 0) {
              uVar4 = FUN_80252544(iVar6);
              if ((uVar4 & 8) == 0) {
                uVar4 = FUN_80252d80(iVar6);
                if ((uVar4 & 0x20000000) == 0) {
                  uVar5 = uVar5 | uVar7;
                }
                iVar3 = FUN_8025282c(iVar6,local_3c);
                if (iVar3 == 0) {
                  *(undefined *)(param_1 + 5) = 0xfd;
                  FUN_800033a8(param_1,0,10);
                }
                else if ((local_3c[0] & 0x80000000) == 0) {
                  (*DAT_803dc598)(iVar6,param_1,local_3c);
                  if ((*param_1 & 0x2000) == 0) {
                    *(undefined *)(param_1 + 5) = 0;
                    *param_1 = *param_1 & 0xff7f;
                  }
                  else {
                    *(undefined *)(param_1 + 5) = 0xfd;
                    FUN_800033a8(param_1,0,10);
                    FUN_8025297c(iVar6,&DAT_803dc59c,1,puVar8,10,&LAB_8024de58,0,0);
                  }
                }
                else {
                  *(undefined *)(param_1 + 5) = 0xfd;
                  FUN_800033a8(param_1,0,10);
                }
              }
              else {
                FUN_8025282c(iVar6,local_3c);
                if ((DAT_803ddfc0 & uVar7) == 0) {
                  uVar2 = FUN_8024377c();
                  FUN_802526ec(uVar7);
                  uVar7 = ~uVar7;
                  DAT_803ddfb4 = DAT_803ddfb4 & uVar7;
                  DAT_803ddfc0 = DAT_803ddfc0 & uVar7;
                  DAT_803ddfc4 = DAT_803ddfc4 & uVar7;
                  DAT_803ddfc8 = DAT_803ddfc8 & uVar7;
                  FUN_80245980(iVar6,0);
                  FUN_802437a4(uVar2);
                  *(undefined *)(param_1 + 5) = 0xff;
                  FUN_800033a8(param_1,0,10);
                }
                else {
                  *(undefined *)(param_1 + 5) = 0;
                  FUN_800033a8(param_1,0,10);
                  if ((DAT_803ddfc4 & uVar7) == 0) {
                    DAT_803ddfc4 = DAT_803ddfc4 | uVar7;
                    FUN_80252f44(iVar6,&LAB_8024e31c);
                  }
                }
              }
            }
            else {
              *(undefined *)(param_1 + 5) = 0xfd;
              FUN_800033a8(param_1,0,10);
            }
          }
          goto LAB_8024ebdc;
        }
      }
      *(undefined *)(param_1 + 5) = 0xfe;
      FUN_800033a8(param_1,0,10);
    }
    else {
      uVar2 = FUN_8024377c();
      uVar4 = DAT_803ddfc8 & ~(DAT_803ddfc0 | DAT_803ddfc4);
      DAT_803ddfb8 = DAT_803ddfb8 | uVar4;
      DAT_803ddfc8 = 0;
      uVar7 = DAT_803ddfb8 & DAT_803ddfb4;
      if (DAT_803dc594 == 4) {
        DAT_803ddfbc = DAT_803ddfbc | uVar4;
      }
      DAT_803ddfb4 = DAT_803ddfb4 & ~uVar4;
      FUN_802526ec(uVar7);
      if (DAT_803dc588 == 0x20) {
        DAT_803dc588 = countLeadingZeros(DAT_803ddfb8);
        if (DAT_803dc588 != 0x20) {
          DAT_803ddfb8 = DAT_803ddfb8 & ~(0x80000000U >> DAT_803dc588);
          FUN_800033a8(&DAT_803ae1c0 + DAT_803dc588 * 0xc,0,0xc);
          FUN_80252f44(DAT_803dc588,&LAB_8024dff0);
        }
      }
      FUN_802437a4(uVar2);
      *(undefined *)(param_1 + 5) = 0xfe;
      FUN_800033a8(param_1,0,10);
    }
LAB_8024ebdc:
    iVar6 = iVar6 + 1;
    puVar8 = puVar8 + 0xc;
    param_1 = param_1 + 6;
    if (3 < iVar6) {
      FUN_802437a4(uVar1);
      return uVar5;
    }
  } while( true );
}

