// Function: FUN_8001a6a4
// Entry: 8001a6a4
// Size: 684 bytes

void FUN_8001a6a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar8;
  byte *pbVar9;
  byte *pbVar10;
  undefined *puVar11;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar12;
  
  uVar4 = FUN_8028683c();
  uVar5 = FUN_80022e00(0);
  iVar6 = FUN_800206e4();
  uVar12 = extraout_f1;
  if ((iVar6 == 0) || (iVar6 = FUN_800206e4(), uVar12 = extraout_f1_00, iVar6 == 1)) {
    DAT_803dd658 = DAT_803dd65c;
    DAT_803dd660 = DAT_803dd664;
    if ((DAT_803dd65c < 0) || (((0x48 < DAT_803dd65c || (DAT_803dd664 < 0)) || (5 < DAT_803dd664))))
    {
      FUN_80022e00(uVar5);
    }
    else {
      piVar8 = (int *)&DAT_8033bc40;
      iVar6 = 7;
      do {
        if (*(byte *)((int)piVar8 + 0x4b) == uVar4) {
          if (piVar8[0x11] == 1) {
            piVar8[0x11] = 4;
            FUN_8024bb8c(piVar8,&LAB_8001b450);
          }
          if ((piVar8[0x11] == 3) && (*(char *)((int)piVar8 + 0x4a) != '\0')) {
            FUN_800238f8(0);
            if (piVar8[0xf] != 0) {
              uVar12 = FUN_800238c4(piVar8[0xf]);
            }
            FUN_800238f8(2);
            piVar8[0xf] = 0;
            piVar8[0x10] = 0;
            *(undefined *)((int)piVar8 + 0x4a) = 0;
          }
        }
        piVar8 = piVar8 + 0x13;
        bVar1 = iVar6 != 0;
        iVar6 = iVar6 + -1;
      } while (bVar1);
      iVar6 = uVar4 * 0x28;
      *(undefined4 *)(&DAT_8033bbbc + iVar6) = 1;
      pbVar10 = &DAT_8033bbc4 + iVar6;
      *pbVar10 = (byte)DAT_803dd65c;
      pbVar9 = &DAT_8033bbc5 + iVar6;
      *pbVar9 = (byte)DAT_803dd664;
      puVar11 = &DAT_8033bc40;
      if (((DAT_8033bc8a != '\0') && (puVar11 = &DAT_8033bc8c, DAT_8033bcd6 != '\0')) &&
         ((puVar11 = (undefined *)0x8033bcd8, DAT_8033bd22 != '\0' &&
          ((((puVar11 = (undefined *)0x8033bd24, DAT_8033bd6e != '\0' &&
             (puVar11 = (undefined *)0x8033bd70, DAT_8033bdba != '\0')) &&
            (puVar11 = (undefined *)0x8033bdbc, DAT_8033be06 != '\0')) &&
           ((puVar11 = (undefined *)0x8033be08, DAT_8033be52 != '\0' &&
            (puVar11 = (undefined *)0x8033be54, DAT_8033be9e != '\0')))))))) {
        puVar11 = (undefined *)0x0;
      }
      if (puVar11 != (undefined *)0x0) {
        bVar2 = *pbVar10;
        bVar3 = *pbVar9;
        *(undefined4 *)(puVar11 + 0x44) = 1;
        puVar11[0x48] = bVar2;
        puVar11[0x49] = bVar3;
        puVar11[0x4a] = 1;
        puVar11[0x4b] = (char)uVar4;
        FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc56a0,
                     s_gametext__s__s_bin_802ca9f4,(&PTR_s_Animtest_802c7a1c)[bVar2],
                     (&PTR_s_English_802c7b50)[(uint)bVar3 * 2],in_r7,in_r8,in_r9,in_r10);
        uVar12 = FUN_80015994(puVar11);
        uVar7 = FUN_8001599c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        *(undefined4 *)(puVar11 + 0x3c) = uVar7;
        FUN_80015994(0);
        *pbVar10 = 0xff;
        *pbVar9 = 6;
      }
      FUN_80022e00(uVar5);
    }
  }
  else {
    FUN_80022e00(uVar5);
  }
  FUN_80286888();
  return;
}

