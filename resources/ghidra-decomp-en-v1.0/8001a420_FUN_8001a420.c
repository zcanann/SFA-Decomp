// Function: FUN_8001a420
// Entry: 8001a420
// Size: 588 bytes

void FUN_8001a420(void)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined *puVar6;
  undefined5 uVar7;
  
  uVar7 = FUN_802860d0();
  iVar2 = DAT_803dc9e4;
  uVar3 = FUN_80022d3c(0);
  iVar4 = FUN_80020620();
  if ((iVar4 == 0) || (iVar4 = FUN_80020620(), iVar4 == 1)) {
    DAT_803dc9d0 = DAT_803dc9d4;
    if ((DAT_803dc9e4 < 0) || (5 < DAT_803dc9e4)) {
      FUN_80022d3c(uVar3);
    }
    else {
      puVar6 = &DAT_8033afe0;
      iVar4 = 7;
      do {
        if (puVar6[0x4b] == '\x01') {
          if (*(int *)(puVar6 + 0x44) == 1) {
            *(undefined4 *)(puVar6 + 0x44) = 4;
            FUN_8024b428(puVar6,&LAB_8001b39c);
          }
          if ((*(int *)(puVar6 + 0x44) == 3) && (puVar6[0x4a] != '\0')) {
            FUN_80023834(0);
            FUN_80023800(*(undefined4 *)(puVar6 + 0x3c));
            FUN_80023834(2);
            *(undefined4 *)(puVar6 + 0x3c) = 0;
            *(undefined4 *)(puVar6 + 0x40) = 0;
            puVar6[0x4a] = 0;
          }
        }
        puVar6 = puVar6 + 0x4c;
        bVar1 = iVar4 != 0;
        iVar4 = iVar4 + -1;
      } while (bVar1);
      DAT_8033af84 = 1;
      puVar6 = &DAT_8033afe0;
      if (((((DAT_8033b02a != '\0') && (puVar6 = &DAT_8033b02c, DAT_8033b076 != '\0')) &&
           (puVar6 = (undefined *)0x8033b078, DAT_8033b0c2 != '\0')) &&
          ((puVar6 = (undefined *)0x8033b0c4, DAT_8033b10e != '\0' &&
           (puVar6 = (undefined *)0x8033b110, DAT_8033b15a != '\0')))) &&
         ((puVar6 = (undefined *)0x8033b15c, DAT_8033b1a6 != '\0' &&
          ((puVar6 = (undefined *)0x8033b1a8, DAT_8033b1f2 != '\0' &&
           (puVar6 = (undefined *)0x8033b1f4, DAT_8033b23e != '\0')))))) {
        puVar6 = (undefined *)0x0;
      }
      *(undefined4 *)(puVar6 + 0x44) = 1;
      puVar6[0x48] = (char)((uint5)uVar7 >> 0x20);
      puVar6[0x49] = (char)DAT_803dc9e4;
      puVar6[0x4a] = 1;
      puVar6[0x4b] = 1;
      FUN_8028f688(&DAT_80339d00,s_gametext_Sequences__d__s_bin_802c9ec4,(int)uVar7,
                   (&PTR_s_English_802c73d0)[iVar2 * 2]);
      FUN_8001595c(puVar6);
      uVar5 = FUN_80015964(&DAT_80339d00,puVar6 + 0x40,1,&LAB_8001b3d0);
      *(undefined4 *)(puVar6 + 0x3c) = uVar5;
      FUN_8001595c(0);
      FUN_80022d3c(uVar3);
    }
  }
  else {
    FUN_80022d3c(uVar3);
  }
  FUN_8028611c();
  return;
}

