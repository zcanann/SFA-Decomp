// Function: FUN_8001a458
// Entry: 8001a458
// Size: 588 bytes

void FUN_8001a458(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar6;
  undefined *puVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar8;
  undefined5 uVar9;
  
  uVar9 = FUN_80286834();
  iVar2 = DAT_803dd664;
  uVar3 = FUN_80022e00(0);
  iVar4 = FUN_800206e4();
  uVar8 = extraout_f1;
  if ((iVar4 == 0) || (iVar4 = FUN_800206e4(), uVar8 = extraout_f1_00, iVar4 == 1)) {
    DAT_803dd650 = DAT_803dd654;
    if ((DAT_803dd664 < 0) || (5 < DAT_803dd664)) {
      FUN_80022e00(uVar3);
    }
    else {
      piVar6 = (int *)&DAT_8033bc40;
      iVar4 = 7;
      do {
        if (*(char *)((int)piVar6 + 0x4b) == '\x01') {
          if (piVar6[0x11] == 1) {
            piVar6[0x11] = 4;
            FUN_8024bb8c(piVar6,&LAB_8001b450);
          }
          if ((piVar6[0x11] == 3) && (*(char *)((int)piVar6 + 0x4a) != '\0')) {
            FUN_800238f8(0);
            uVar8 = FUN_800238c4(piVar6[0xf]);
            FUN_800238f8(2);
            piVar6[0xf] = 0;
            piVar6[0x10] = 0;
            *(undefined *)((int)piVar6 + 0x4a) = 0;
          }
        }
        piVar6 = piVar6 + 0x13;
        bVar1 = iVar4 != 0;
        iVar4 = iVar4 + -1;
      } while (bVar1);
      DAT_8033bbe4 = 1;
      puVar7 = &DAT_8033bc40;
      if (((((DAT_8033bc8a != '\0') && (puVar7 = &DAT_8033bc8c, DAT_8033bcd6 != '\0')) &&
           (puVar7 = (undefined *)0x8033bcd8, DAT_8033bd22 != '\0')) &&
          ((puVar7 = (undefined *)0x8033bd24, DAT_8033bd6e != '\0' &&
           (puVar7 = (undefined *)0x8033bd70, DAT_8033bdba != '\0')))) &&
         ((puVar7 = (undefined *)0x8033bdbc, DAT_8033be06 != '\0' &&
          ((puVar7 = (undefined *)0x8033be08, DAT_8033be52 != '\0' &&
           (puVar7 = (undefined *)0x8033be54, DAT_8033be9e != '\0')))))) {
        puVar7 = (undefined *)0x0;
      }
      *(undefined4 *)(puVar7 + 0x44) = 1;
      puVar7[0x48] = (char)((uint5)uVar9 >> 0x20);
      puVar7[0x49] = (char)DAT_803dd664;
      puVar7[0x4a] = 1;
      puVar7[0x4b] = 1;
      FUN_8028fde8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc56a0,
                   s_gametext_Sequences__d__s_bin_802caa48,(int)uVar9,
                   (&PTR_s_English_802c7b50)[iVar2 * 2],in_r7,in_r8,in_r9,in_r10);
      uVar8 = FUN_80015994(puVar7);
      uVar5 = FUN_8001599c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *(undefined4 *)(puVar7 + 0x3c) = uVar5;
      FUN_80015994(0);
      FUN_80022e00(uVar3);
    }
  }
  else {
    FUN_80022e00(uVar3);
  }
  FUN_80286880();
  return;
}

