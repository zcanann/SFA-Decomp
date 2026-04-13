// Function: FUN_8024efc8
// Entry: 8024efc8
// Size: 940 bytes

uint FUN_8024efc8(ushort *param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined *puVar6;
  uint local_3c [3];
  
  FUN_80243e74();
  uVar4 = 0;
  puVar6 = &DAT_803aee20;
  uVar3 = 0;
  do {
    uVar5 = 0x80000000 >> uVar4;
    if ((DAT_803dec48 & uVar5) == 0) {
      if ((DAT_803dec38 & uVar5) == 0) {
        if (DAT_803dd1f0 != uVar4) {
          if ((DAT_803dec34 & uVar5) == 0) {
            *(undefined *)(param_1 + 5) = 0xff;
            FUN_800033a8((int)param_1,0,10);
          }
          else {
            iVar1 = FUN_80252124(uVar4);
            if (iVar1 == 0) {
              uVar2 = FUN_80252ca8(uVar4);
              if ((uVar2 & 8) == 0) {
                uVar2 = FUN_802534e4(uVar4);
                if ((uVar2 & 0x20000000) == 0) {
                  uVar3 = uVar3 | uVar5;
                }
                iVar1 = FUN_80252f90(uVar4,local_3c);
                if (iVar1 == 0) {
                  *(undefined *)(param_1 + 5) = 0xfd;
                  FUN_800033a8((int)param_1,0,10);
                }
                else if ((local_3c[0] & 0x80000000) == 0) {
                  (*DAT_803dd200)(uVar4,param_1,local_3c);
                  if ((*param_1 & 0x2000) == 0) {
                    *(undefined *)(param_1 + 5) = 0;
                    *param_1 = *param_1 & 0xff7f;
                  }
                  else {
                    *(undefined *)(param_1 + 5) = 0xfd;
                    FUN_800033a8((int)param_1,0,10);
                    FUN_802530e0(uVar4,(undefined4 *)&DAT_803dd204,1,puVar6,10,-0x7fdb1a44,0,0);
                  }
                }
                else {
                  *(undefined *)(param_1 + 5) = 0xfd;
                  FUN_800033a8((int)param_1,0,10);
                }
              }
              else {
                FUN_80252f90(uVar4,local_3c);
                if ((DAT_803dec40 & uVar5) == 0) {
                  FUN_80243e74();
                  FUN_80252e50(uVar5);
                  uVar5 = ~uVar5;
                  DAT_803dec34 = DAT_803dec34 & uVar5;
                  DAT_803dec40 = DAT_803dec40 & uVar5;
                  DAT_803dec44 = DAT_803dec44 & uVar5;
                  DAT_803dec48 = DAT_803dec48 & uVar5;
                  FUN_802460e4(uVar4,0);
                  FUN_80243e9c();
                  *(undefined *)(param_1 + 5) = 0xff;
                  FUN_800033a8((int)param_1,0,10);
                }
                else {
                  *(undefined *)(param_1 + 5) = 0;
                  FUN_800033a8((int)param_1,0,10);
                  if ((DAT_803dec44 & uVar5) == 0) {
                    DAT_803dec44 = DAT_803dec44 | uVar5;
                    FUN_802536a8(uVar4,&LAB_8024ea80);
                  }
                }
              }
            }
            else {
              *(undefined *)(param_1 + 5) = 0xfd;
              FUN_800033a8((int)param_1,0,10);
            }
          }
          goto LAB_8024f340;
        }
      }
      *(undefined *)(param_1 + 5) = 0xfe;
      FUN_800033a8((int)param_1,0,10);
    }
    else {
      FUN_80243e74();
      uVar2 = DAT_803dec48 & ~(DAT_803dec40 | DAT_803dec44);
      DAT_803dec38 = DAT_803dec38 | uVar2;
      DAT_803dec48 = 0;
      uVar5 = DAT_803dec38 & DAT_803dec34;
      if (DAT_803dd1fc == 4) {
        DAT_803dec3c = DAT_803dec3c | uVar2;
      }
      DAT_803dec34 = DAT_803dec34 & ~uVar2;
      FUN_80252e50(uVar5);
      if (DAT_803dd1f0 == 0x20) {
        DAT_803dd1f0 = countLeadingZeros(DAT_803dec38);
        if (DAT_803dd1f0 != 0x20) {
          DAT_803dec38 = DAT_803dec38 & ~(0x80000000U >> DAT_803dd1f0);
          FUN_800033a8((int)(&DAT_803aee20 + DAT_803dd1f0 * 0xc),0,0xc);
          FUN_802536a8(DAT_803dd1f0,&LAB_8024e754);
        }
      }
      FUN_80243e9c();
      *(undefined *)(param_1 + 5) = 0xfe;
      FUN_800033a8((int)param_1,0,10);
    }
LAB_8024f340:
    uVar4 = uVar4 + 1;
    puVar6 = puVar6 + 0xc;
    param_1 = param_1 + 6;
    if (3 < (int)uVar4) {
      FUN_80243e9c();
      return uVar3;
    }
  } while( true );
}

