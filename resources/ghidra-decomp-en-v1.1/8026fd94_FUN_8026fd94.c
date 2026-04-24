// Function: FUN_8026fd94
// Entry: 8026fd94
// Size: 648 bytes

uint FUN_8026fd94(byte param_1,char param_2,char param_3,int param_4,undefined4 *param_5)

{
  uint uVar1;
  bool bVar3;
  int iVar2;
  undefined4 uVar4;
  int unaff_r23;
  int iVar5;
  uint unaff_r25;
  uint unaff_r26;
  uint uVar6;
  uint uVar7;
  int iVar8;
  
  uVar7 = 0;
  iVar8 = 0;
  uVar4 = 0;
  uVar6 = 0xffffffff;
  iVar5 = DAT_803deee8;
  do {
    if (DAT_803bdfc0 <= uVar7) {
      if (uVar6 == 0xffffffff) {
        *param_5 = uVar4;
      }
      else {
        FUN_8027a9bc(unaff_r23);
        FUN_8028274c((uint)*(byte *)(unaff_r23 + 0x121),(uint)*(byte *)(unaff_r23 + 0x122),
                     (char)*(undefined2 *)(unaff_r23 + 300));
        *param_5 = 0;
      }
      return unaff_r26;
    }
    if ((((*(char *)(iVar5 + 0x11c) == '\0') && (*(int *)(iVar5 + 0xf4) != -1)) &&
        (*(char *)(iVar5 + 0x121) == param_2)) && (*(char *)(iVar5 + 0x122) == param_3)) {
      uVar1 = *(uint *)(iVar5 + 0x118);
      if ((uVar1 & 2) != 0) {
        uVar4 = 1;
      }
      if ((((uVar1 & 0x10) != 0) && ((uVar1 & 8) != 8 || (*(uint *)(iVar5 + 0x114) & 0x100) != 0))
         && (bVar3 = FUN_802839b8(uVar7), bVar3)) {
        if ((uVar6 == 0xffffffff) && ((*(uint *)(iVar5 + 0x118) & 0x20002) == 0x20002)) {
          *param_5 = 1;
          return unaff_r26;
        }
        uVar1 = (int)*(char *)(iVar5 + 0x12e) << 0x10;
        iVar2 = (int)uVar1 / 100 +
                ((int)(uVar1 | (uint)(int)*(char *)(iVar5 + 0x12e) >> 0x10) >> 0x1f);
        *(uint *)(iVar5 + 0x138) =
             (uint)*(ushort *)(iVar5 + 300) * 0x10000 + (iVar2 - (iVar2 >> 0x1f));
        *(char *)(iVar5 + 0x130) = (char)*(undefined2 *)(iVar5 + 300);
        *(ushort *)(iVar5 + 300) =
             (ushort)param_1 +
             ((*(ushort *)(iVar5 + 300) & 0xff) - (ushort)*(byte *)(iVar5 + 0x12f));
        *(byte *)(iVar5 + 0x12f) = param_1;
        *(undefined *)(iVar5 + 0x12e) = 0;
        *(undefined4 *)(iVar5 + 0x13c) = 0;
        *(uint *)(iVar5 + 0x118) = *(uint *)(iVar5 + 0x118) | 0x20000;
        FUN_8027979c(DAT_803deee8 + iVar8);
        unaff_r23 = iVar5;
        if (uVar6 == 0xffffffff) {
          *(undefined4 *)(iVar5 + 0xec) = 0xffffffff;
          *(undefined4 *)(iVar5 + 0xf0) = 0xffffffff;
          uVar6 = FUN_80279b04(DAT_803deee8 + iVar8,param_4);
          unaff_r25 = *(uint *)(iVar5 + 0xf4);
        }
        else {
          *(undefined4 *)(DAT_803deee8 + (unaff_r25 & 0xff) * 0x404 + 0xec) =
               *(undefined4 *)(iVar5 + 0xf4);
          *(uint *)(iVar5 + 0xf0) = unaff_r25;
          unaff_r25 = *(uint *)(iVar5 + 0xf4);
          FUN_80279b04(DAT_803deee8 + iVar8,0);
        }
      }
    }
    iVar8 = iVar8 + 0x404;
    uVar7 = uVar7 + 1;
    iVar5 = iVar5 + 0x404;
  } while( true );
}

