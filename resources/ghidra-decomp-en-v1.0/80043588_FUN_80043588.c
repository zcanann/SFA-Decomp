// Function: FUN_80043588
// Entry: 80043588
// Size: 348 bytes

undefined4 FUN_80043588(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  undefined *puVar4;
  
  iVar1 = 0;
  puVar3 = (undefined *)0x0;
  puVar4 = puVar3;
  if (param_1 != 0x25) {
    if (param_1 < 0x25) {
      if (param_1 == 0x1a) {
        iVar1 = 0x800;
        puVar4 = &DAT_8034e010;
      }
      else if (param_1 < 0x1a) {
        if (param_1 == 0xe) {
          iVar1 = 0x1fd0;
          puVar4 = &DAT_803460d0;
        }
      }
      else if (param_1 == 0x21) {
        iVar1 = 0x1000;
        puVar4 = &DAT_80352010;
      }
      else if ((0x20 < param_1) && (0x23 < param_1)) {
        iVar1 = 0x1000;
        puVar4 = &DAT_80356010;
      }
    }
    else if (param_1 == 0x2f) {
      iVar1 = 3000;
      puVar4 = &DAT_8035a010;
    }
    else if (param_1 < 0x2f) {
      if (param_1 == 0x2a) {
        iVar1 = 0x800;
        puVar4 = &DAT_8035cef0;
      }
      else if ((param_1 < 0x2a) && (param_1 < 0x27)) {
        iVar1 = 0x800;
        puVar4 = &DAT_80350010;
      }
    }
    else {
      puVar4 = DAT_8035f528;
      if (param_1 != 0x50) {
        puVar4 = puVar3;
      }
    }
  }
  if ((param_2 < 0) || (iVar1 <= param_2)) {
    FUN_80137b80(0x14,0x28,s_ERROR__asset_index_overflow_802cc110);
    uVar2 = 0;
  }
  else if (puVar4 == (undefined *)0x0) {
    uVar2 = 0;
  }
  else {
    *param_3 = *(undefined4 *)(puVar4 + param_2 * 4);
    uVar2 = 1;
  }
  return uVar2;
}

