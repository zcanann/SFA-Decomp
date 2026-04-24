// Function: FUN_8001a66c
// Entry: 8001a66c
// Size: 684 bytes

void FUN_8001a66c(void)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 uVar7;
  undefined *puVar8;
  byte *pbVar9;
  byte *pbVar10;
  
  uVar4 = FUN_802860d8();
  uVar5 = FUN_80022d3c(0);
  iVar6 = FUN_80020620();
  if ((iVar6 == 0) || (iVar6 = FUN_80020620(), iVar6 == 1)) {
    DAT_803dc9d8 = DAT_803dc9dc;
    DAT_803dc9e0 = DAT_803dc9e4;
    if ((DAT_803dc9dc < 0) || (((0x48 < DAT_803dc9dc || (DAT_803dc9e4 < 0)) || (5 < DAT_803dc9e4))))
    {
      FUN_80022d3c(uVar5);
    }
    else {
      puVar8 = &DAT_8033afe0;
      iVar6 = 7;
      do {
        if ((byte)puVar8[0x4b] == uVar4) {
          if (*(int *)(puVar8 + 0x44) == 1) {
            *(undefined4 *)(puVar8 + 0x44) = 4;
            FUN_8024b428(puVar8,&LAB_8001b39c);
          }
          if ((*(int *)(puVar8 + 0x44) == 3) && (puVar8[0x4a] != '\0')) {
            FUN_80023834(0);
            if (*(int *)(puVar8 + 0x3c) != 0) {
              FUN_80023800();
            }
            FUN_80023834(2);
            *(undefined4 *)(puVar8 + 0x3c) = 0;
            *(undefined4 *)(puVar8 + 0x40) = 0;
            puVar8[0x4a] = 0;
          }
        }
        puVar8 = puVar8 + 0x4c;
        bVar1 = iVar6 != 0;
        iVar6 = iVar6 + -1;
      } while (bVar1);
      iVar6 = uVar4 * 0x28;
      *(undefined4 *)(&DAT_8033af5c + iVar6) = 1;
      pbVar10 = &DAT_8033af64 + iVar6;
      *pbVar10 = (byte)DAT_803dc9dc;
      pbVar9 = &DAT_8033af65 + iVar6;
      *pbVar9 = (byte)DAT_803dc9e4;
      puVar8 = &DAT_8033afe0;
      if (((DAT_8033b02a != '\0') && (puVar8 = &DAT_8033b02c, DAT_8033b076 != '\0')) &&
         ((puVar8 = (undefined *)0x8033b078, DAT_8033b0c2 != '\0' &&
          ((((puVar8 = (undefined *)0x8033b0c4, DAT_8033b10e != '\0' &&
             (puVar8 = (undefined *)0x8033b110, DAT_8033b15a != '\0')) &&
            (puVar8 = (undefined *)0x8033b15c, DAT_8033b1a6 != '\0')) &&
           ((puVar8 = (undefined *)0x8033b1a8, DAT_8033b1f2 != '\0' &&
            (puVar8 = (undefined *)0x8033b1f4, DAT_8033b23e != '\0')))))))) {
        puVar8 = (undefined *)0x0;
      }
      if (puVar8 != (undefined *)0x0) {
        bVar2 = *pbVar10;
        bVar3 = *pbVar9;
        *(undefined4 *)(puVar8 + 0x44) = 1;
        puVar8[0x48] = bVar2;
        puVar8[0x49] = bVar3;
        puVar8[0x4a] = 1;
        puVar8[0x4b] = (char)uVar4;
        FUN_8028f688(&DAT_80339d00,s_gametext__s__s_bin_802c9e70,(&PTR_s_Animtest_802c729c)[bVar2],
                     (&PTR_s_English_802c73d0)[(uint)bVar3 * 2]);
        FUN_8001595c(puVar8);
        uVar7 = FUN_80015964(&DAT_80339d00,puVar8 + 0x40,1,&LAB_8001b3d0);
        *(undefined4 *)(puVar8 + 0x3c) = uVar7;
        FUN_8001595c(0);
        *pbVar10 = 0xff;
        *pbVar9 = 6;
      }
      FUN_80022d3c(uVar5);
    }
  }
  else {
    FUN_80022d3c(uVar5);
  }
  FUN_80286124();
  return;
}

