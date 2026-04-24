// Function: FUN_80025420
// Entry: 80025420
// Size: 944 bytes

void FUN_80025420(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  short sVar2;
  short *psVar3;
  int iVar4;
  char *pcVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  int iVar15;
  undefined8 uVar16;
  char *local_38;
  undefined4 local_34;
  undefined auStack48 [4];
  char *local_2c;
  undefined4 local_28 [10];
  
  uVar16 = FUN_802860d8();
  psVar3 = DAT_803dcb60;
  iVar6 = (int)((ulonglong)uVar16 >> 0x20);
  uVar8 = (uint)uVar16;
  uVar13 = 0;
  FUN_80048f48(0x2d,DAT_803dcb60,uVar8 << 1,0x10);
  sVar2 = *psVar3;
  if (*(ushort *)(iVar6 + 0xec) == 0) {
    uVar7 = 0;
  }
  else {
    uVar14 = (uint)*(ushort *)(iVar6 + 0xec) * 2 + 8;
    if (0x800 < uVar14) {
      FUN_801378a8(s_Warning__Model_animation_buffer_o_802cabc4,uVar14);
    }
    FUN_80048f48(0x31,DAT_803dcb60,(uVar8 & 0xfffffffc) << 2,0x20);
    uVar8 = uVar8 & 3;
    *(undefined4 *)(iVar6 + 0x80) = *(undefined4 *)(DAT_803dcb60 + uVar8 * 2);
    iVar9 = *(int *)(DAT_803dcb60 + uVar8 * 2);
    iVar4 = *(int *)(DAT_803dcb60 + uVar8 * 2 + 2);
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      FUN_80048f48(0x2e,DAT_803dcb64,(int)sVar2,uVar14);
      *(int *)(iVar6 + 0x6c) = DAT_803dcb64;
    }
    else {
      *(int *)(iVar6 + 0x6c) = param_3;
      for (uVar13 = uVar14; (uVar13 & 7) != 0; uVar13 = uVar13 + 1) {
      }
      param_3 = param_3 + uVar13;
      FUN_80048f48(0x2e,*(undefined4 *)(iVar6 + 0x6c),(int)sVar2,uVar13);
    }
    iVar10 = 0;
    *(undefined2 *)(iVar6 + 0x70) = 0;
    iVar15 = 1;
    for (iVar12 = 0; iVar12 < (int)(uint)*(ushort *)(iVar6 + 0xec); iVar12 = iVar12 + 1) {
      iVar11 = iVar15;
      if (*(short *)(*(int *)(iVar6 + 0x6c) + iVar10) == -1) {
        iVar11 = iVar15 + 1;
        *(short *)(iVar6 + iVar15 * 2 + 0x70) = (short)iVar12 + 1;
      }
      iVar10 = iVar10 + 2;
      iVar15 = iVar11;
    }
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      *(undefined4 *)(iVar6 + 0x6c) = 0;
      *(int *)(iVar6 + 100) = param_3;
      iVar15 = (uint)*(ushort *)(iVar6 + 0xec) * 4;
      param_3 = param_3 + iVar15;
      for (uVar13 = uVar13 + iVar15; (uVar13 & 7) != 0; uVar13 = uVar13 + 1) {
        param_3 = param_3 + 1;
      }
      *(int *)(iVar6 + 0x68) = param_3;
      FUN_80048f48(0x32,*(undefined4 *)(iVar6 + 0x68),*(undefined4 *)(iVar6 + 0x80),iVar4 - iVar9);
      iVar4 = 0;
      iVar15 = 0;
      iVar9 = 0;
      do {
        iVar10 = (int)*(short *)(DAT_803dcb64 + iVar15);
        if (iVar10 == -1) {
          *(undefined4 *)(*(int *)(iVar6 + 100) + iVar9) = 0;
        }
        else {
          uVar8 = FUN_800430ac(0);
          if ((((uVar8 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
             (*(short *)(iVar6 + 4) == 3)) {
            iVar12 = FUN_80013c10(DAT_803dcb50,iVar10,&local_38);
            if (iVar12 == 0) {
              uVar7 = *(undefined4 *)(DAT_803dcb4c + iVar10 * 4);
              FUN_800464c8(0x30,0,uVar7,0,&local_34,iVar10,1);
              local_38 = (char *)FUN_80023cc8(local_34,10,0);
              FUN_800464c8(0x30,local_38,uVar7,local_34,auStack48,iVar10,0);
              *local_38 = '\x01';
              FUN_80013ce8(DAT_803dcb50,iVar10,&local_38);
              pcVar5 = local_38;
            }
            else {
              *local_38 = *local_38 + '\x01';
              pcVar5 = local_38;
            }
          }
          else {
            pcVar5 = (char *)0x0;
          }
          *(char **)(*(int *)(iVar6 + 100) + iVar9) = pcVar5;
          if (*(int *)(*(int *)(iVar6 + 100) + iVar9) == 0) {
            iVar9 = 0;
            for (iVar15 = 0; iVar15 < iVar4; iVar15 = iVar15 + 1) {
              local_2c = *(char **)(*(int *)(iVar6 + 100) + iVar9);
              if ((local_2c != (char *)0x0) &&
                 (cVar1 = *local_2c, *local_2c = cVar1 + -1, (char)(cVar1 + -1) < '\x01')) {
                FUN_80013b7c(DAT_803dcb50,&local_2c,local_28);
                FUN_80013c78(DAT_803dcb50,local_28[0]);
                FUN_80023800(local_2c);
              }
              iVar9 = iVar9 + 4;
            }
            *(undefined4 *)(iVar6 + 100) = 0;
            uVar7 = 1;
            goto LAB_800257b8;
          }
        }
        iVar15 = iVar15 + 2;
        iVar9 = iVar9 + 4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < (int)(uint)*(ushort *)(iVar6 + 0xec));
    }
    else {
      *(undefined4 *)(iVar6 + 100) = 0;
    }
    uVar7 = 0;
  }
LAB_800257b8:
  FUN_80286124(uVar7);
  return;
}

