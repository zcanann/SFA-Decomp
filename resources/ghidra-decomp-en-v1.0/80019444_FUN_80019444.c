// Function: FUN_80019444
// Entry: 80019444
// Size: 300 bytes

undefined2 * FUN_80019444(void)

{
  int iVar1;
  undefined2 *puVar2;
  
  if (*(int *)(DAT_803dc9ec + 0x1c) == 2) {
    iVar1 = FUN_80019570();
    puVar2 = (undefined2 *)**(undefined4 **)(iVar1 + 8);
  }
  else {
    DAT_803dc97c = DAT_803dc97c + 1;
    if (7 < DAT_803dc97c) {
      DAT_803dc97c = 0;
    }
    DAT_803dc974 = (undefined2 *)(&DAT_803399c0 + DAT_803dc97c * 0xc);
    DAT_803dc978 = *(undefined4 *)(&DAT_803399c8)[DAT_803dc97c * 3];
    *DAT_803dc974 = 0xffff;
    DAT_803dc970 = DAT_803dc97c * 4 + -0x7fcc6660;
    iVar1 = *(int *)(DAT_803dc9ec + 0x1c);
    puVar2 = DAT_803dc974;
    if (iVar1 != 2) {
      if (iVar1 < 2) {
        if (iVar1 == 0) {
          FUN_8028f688(DAT_803dc978,s__uninitialised__802c9e04);
          puVar2 = DAT_803dc974;
        }
        else if (-1 < iVar1) {
          FUN_8028f688(DAT_803dc978,s__loading__802c9e14);
          puVar2 = DAT_803dc974;
        }
      }
      else if (iVar1 == 4) {
        FUN_8028f688(DAT_803dc978,s__no_file___802c9e30);
        puVar2 = DAT_803dc974;
      }
      else if (iVar1 < 4) {
        FUN_8028f688(DAT_803dc978,s__file_empty___802c9e20);
        puVar2 = DAT_803dc974;
      }
    }
  }
  return puVar2;
}

