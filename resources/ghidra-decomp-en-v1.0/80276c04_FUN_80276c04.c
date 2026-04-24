// Function: FUN_80276c04
// Entry: 80276c04
// Size: 564 bytes

void FUN_80276c04(int param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 extraout_r4;
  byte bVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 uVar8;
  
  uVar1 = param_2[1] >> 8 & 0x1f;
  if (uVar1 < 0x10) {
    uVar7 = *(undefined4 *)(param_1 + uVar1 * 4 + 0xac);
  }
  else {
    uVar7 = *(undefined4 *)(&DAT_803bd9f4 + uVar1 * 4);
  }
  if ((*param_2 >> 8 & 0xff) == 0) {
    uVar1 = *param_2 >> 0x10;
    if (uVar1 == 0xffff) {
      if (DAT_803de26c != (code *)0x0) {
        (*DAT_803de26c)(*(undefined4 *)(*(int *)(param_1 + 0xf8) + 8));
      }
    }
    else {
      iVar6 = 0;
      uVar4 = uVar7;
      for (bVar5 = 0; bVar5 < DAT_803bd360; bVar5 = bVar5 + 1) {
        iVar2 = DAT_803de268 + iVar6;
        if ((*(int *)(iVar2 + 0x34) != 0) && (uVar1 == *(ushort *)(iVar2 + 0x102))) {
          uVar8 = FUN_8027949c(*(undefined4 *)(*(int *)(iVar2 + 0xf8) + 8),uVar4);
          uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
          uVar4 = (undefined4)uVar8;
          if (uVar3 != 0xffffffff) {
            iVar2 = DAT_803de268 + (uVar3 & 0xff) * 0x404;
            if (*(byte *)(iVar2 + 0x3ec) < 4) {
              *(byte *)(iVar2 + 0x3ec) = *(byte *)(iVar2 + 0x3ec) + 1;
              *(undefined4 *)(iVar2 + (uint)*(byte *)(iVar2 + 0x3ee) * 4 + 0x3f0) = uVar7;
              *(byte *)(iVar2 + 0x3ee) = *(char *)(iVar2 + 0x3ee) + 1U & 3;
              if ((*(char *)(iVar2 + 0x68) != '\0') && (*(int *)(iVar2 + 0x58) != 0)) {
                *(undefined4 *)(iVar2 + 0x38) = *(undefined4 *)(iVar2 + 100);
                *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(iVar2 + 0x58);
                *(undefined4 *)(iVar2 + 0x58) = 0;
                FUN_80278990(iVar2);
                uVar4 = extraout_r4;
              }
            }
          }
        }
        iVar6 = iVar6 + 0x404;
      }
    }
  }
  else {
    uVar1 = param_2[1] & 0x1f;
    if (uVar1 < 0x10) {
      uVar4 = *(undefined4 *)(param_1 + uVar1 * 4 + 0xac);
    }
    else {
      uVar4 = *(undefined4 *)(&DAT_803bd9f4 + uVar1 * 4);
    }
    uVar1 = FUN_8027949c(uVar4,uVar7);
    if (uVar1 != 0xffffffff) {
      iVar6 = DAT_803de268 + (uVar1 & 0xff) * 0x404;
      if (*(byte *)(iVar6 + 0x3ec) < 4) {
        *(byte *)(iVar6 + 0x3ec) = *(byte *)(iVar6 + 0x3ec) + 1;
        *(undefined4 *)(iVar6 + (uint)*(byte *)(iVar6 + 0x3ee) * 4 + 0x3f0) = uVar7;
        *(byte *)(iVar6 + 0x3ee) = *(char *)(iVar6 + 0x3ee) + 1U & 3;
        if ((*(char *)(iVar6 + 0x68) != '\0') && (*(int *)(iVar6 + 0x58) != 0)) {
          *(undefined4 *)(iVar6 + 0x38) = *(undefined4 *)(iVar6 + 100);
          *(undefined4 *)(iVar6 + 0x34) = *(undefined4 *)(iVar6 + 0x58);
          *(undefined4 *)(iVar6 + 0x58) = 0;
          FUN_80278990(iVar6);
        }
      }
    }
  }
  return;
}

