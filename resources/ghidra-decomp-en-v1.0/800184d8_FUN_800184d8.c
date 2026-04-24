// Function: FUN_800184d8
// Entry: 800184d8
// Size: 304 bytes

void FUN_800184d8(int param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  int iVar4;
  int local_18 [3];
  
  iVar3 = 0;
  if (param_1 != 0) {
    while( true ) {
      uVar1 = FUN_80015cb8((char *)(param_1 + iVar3),local_18);
      if (uVar1 == 0) break;
      if ((uVar1 < 0xe000) || (0xf8ff < uVar1)) {
        if ((uVar1 < 0x61) || (0x7a < uVar1)) {
          if ((uVar1 < 0x41) || (0x5a < uVar1)) {
            iVar4 = 0;
          }
          else {
            iVar4 = 0x41;
          }
        }
        else {
          iVar4 = 0x61;
        }
        if (iVar4 != 0) {
          *(char *)(param_1 + iVar3) =
               s_urstovwxazbcmdefghtkilnpoq_802c9db8[uVar1 - iVar4] + (char)iVar4 + -0x61;
        }
      }
      else {
        puVar2 = &DAT_802c86f0;
        iVar4 = 0x17;
        do {
          if (*puVar2 == uVar1) {
            uVar1 = puVar2[1];
            goto LAB_80018568;
          }
          if (puVar2[2] == uVar1) {
            uVar1 = puVar2[3];
            goto LAB_80018568;
          }
          puVar2 = puVar2 + 4;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        uVar1 = 0;
LAB_80018568:
        iVar3 = iVar3 + uVar1 * 2;
      }
      iVar3 = iVar3 + local_18[0];
    }
  }
  return;
}

