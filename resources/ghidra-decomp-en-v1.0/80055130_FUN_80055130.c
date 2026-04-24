// Function: FUN_80055130
// Entry: 80055130
// Size: 440 bytes

void FUN_80055130(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)(**(code **)(*DAT_803dcaac + 0x90))();
  if ((DAT_803dceb8 != -1) && (DAT_803dcde0 = DAT_803dcde0 + -1, DAT_803dcde0 < '\0')) {
    if ((-1 < DAT_803dceb8) && (DAT_803dcebc != '\0')) {
      (**(code **)(*DAT_803dca4c + 0xc))(3,1);
    }
    DAT_803dceb8 = -1;
    FUN_8012fdb8(0);
  }
  if ((DAT_803dcebd != '\0') &&
     ((iVar2 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar2 != 0 || (DAT_803dcebc == '\0')))) {
    (**(code **)(*DAT_803dca64 + 0x14))();
    (**(code **)(*DAT_803dca64 + 8))();
    (**(code **)(*DAT_803dca5c + 8))();
    (**(code **)(*DAT_803dca58 + 8))();
    (**(code **)(*DAT_803dca60 + 8))();
    FUN_8011f250();
    DAT_803dcebd = '\0';
    *puVar1 = DAT_803879a0;
    puVar1[1] = DAT_803879a4;
    puVar1[2] = DAT_803879a8;
    *(char *)((int)puVar1 + 0xd) = (char)DAT_803879ac;
    *(char *)(puVar1 + 3) = (char)DAT_803879ae;
    FUN_80020748();
    DAT_803dceb8 = DAT_803dceba;
    DAT_803dceba = -1;
    DAT_803dcde0 = '\b';
    DAT_803dca40 = 1;
    FUN_8001fec0(1);
  }
  return;
}

