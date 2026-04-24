// Function: FUN_8026f630
// Entry: 8026f630
// Size: 648 bytes

int FUN_8026f630(byte param_1,char param_2,char param_3,undefined4 param_4,undefined4 *param_5)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int unaff_r23;
  int iVar4;
  uint unaff_r25;
  int iVar5;
  uint uVar6;
  int iVar7;
  
  uVar6 = 0;
  iVar7 = 0;
  uVar3 = 0;
  iVar5 = -1;
  iVar4 = DAT_803de268;
  do {
    if (DAT_803bd360 <= uVar6) {
      if (iVar5 == -1) {
        *param_5 = uVar3;
      }
      else {
        FUN_8027a258(unaff_r23);
        FUN_80281fe8(*(undefined *)(unaff_r23 + 0x121),*(undefined *)(unaff_r23 + 0x122),
                     *(ushort *)(unaff_r23 + 300) & 0xff);
        *param_5 = 0;
      }
      return iVar5;
    }
    if ((((*(char *)(iVar4 + 0x11c) == '\0') && (*(int *)(iVar4 + 0xf4) != -1)) &&
        (*(char *)(iVar4 + 0x121) == param_2)) && (*(char *)(iVar4 + 0x122) == param_3)) {
      uVar1 = *(uint *)(iVar4 + 0x118);
      if ((uVar1 & 2) != 0) {
        uVar3 = 1;
      }
      if ((((uVar1 & 0x10) != 0) && ((uVar1 & 8 ^ 8 | *(uint *)(iVar4 + 0x114) & 0x100) != 0)) &&
         (iVar2 = FUN_80283254(uVar6), iVar2 != 0)) {
        if ((iVar5 == -1) && ((*(uint *)(iVar4 + 0x118) & 0x20002) == 0x20002)) {
          *param_5 = 1;
          return -1;
        }
        uVar1 = (int)*(char *)(iVar4 + 0x12e) << 0x10;
        iVar2 = (int)uVar1 / 100 +
                ((int)(uVar1 | (uint)(int)*(char *)(iVar4 + 0x12e) >> 0x10) >> 0x1f);
        *(uint *)(iVar4 + 0x138) =
             (uint)*(ushort *)(iVar4 + 300) * 0x10000 + (iVar2 - (iVar2 >> 0x1f));
        *(char *)(iVar4 + 0x130) = (char)*(undefined2 *)(iVar4 + 300);
        *(ushort *)(iVar4 + 300) =
             (ushort)param_1 +
             ((*(ushort *)(iVar4 + 300) & 0xff) - (ushort)*(byte *)(iVar4 + 0x12f));
        *(byte *)(iVar4 + 0x12f) = param_1;
        *(undefined *)(iVar4 + 0x12e) = 0;
        *(undefined4 *)(iVar4 + 0x13c) = 0;
        *(uint *)(iVar4 + 0x118) = *(uint *)(iVar4 + 0x118) | 0x20000;
        FUN_80279038(DAT_803de268 + iVar7);
        unaff_r23 = iVar4;
        if (iVar5 == -1) {
          *(undefined4 *)(iVar4 + 0xec) = 0xffffffff;
          *(undefined4 *)(iVar4 + 0xf0) = 0xffffffff;
          iVar5 = FUN_802793a0(DAT_803de268 + iVar7,param_4);
          unaff_r25 = *(uint *)(iVar4 + 0xf4);
        }
        else {
          *(undefined4 *)(DAT_803de268 + (unaff_r25 & 0xff) * 0x404 + 0xec) =
               *(undefined4 *)(iVar4 + 0xf4);
          *(uint *)(iVar4 + 0xf0) = unaff_r25;
          unaff_r25 = *(uint *)(iVar4 + 0xf4);
          FUN_802793a0(DAT_803de268 + iVar7,0);
        }
      }
    }
    iVar7 = iVar7 + 0x404;
    uVar6 = uVar6 + 1;
    iVar4 = iVar4 + 0x404;
  } while( true );
}

