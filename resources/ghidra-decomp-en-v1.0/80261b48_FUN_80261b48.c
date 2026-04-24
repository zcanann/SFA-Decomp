// Function: FUN_80261b48
// Entry: 80261b48
// Size: 380 bytes

undefined4 FUN_80261b48(int param_1,uint *param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  uint local_1c [2];
  
  if ((-1 < param_1) && (param_1 < 2)) {
    if ((DAT_800030e3 & 0x80) != 0) {
      return 0xfffffffd;
    }
    uVar1 = FUN_8024377c();
    iVar2 = FUN_80253b54(param_1);
    if (iVar2 == -1) {
      uVar4 = 0xfffffffd;
    }
    else if (iVar2 == 0) {
      uVar4 = 0xffffffff;
    }
    else if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
      uVar3 = FUN_802546a0(param_1);
      if ((uVar3 & 8) == 0) {
        iVar2 = FUN_802546e0(param_1,0,local_1c);
        if (iVar2 == 0) {
          uVar4 = 0xffffffff;
        }
        else {
          iVar2 = FUN_80261a7c(local_1c[0]);
          if (iVar2 == 0) {
            uVar4 = 0xfffffffe;
          }
          else {
            if (param_2 != (uint *)0x0) {
              *param_2 = local_1c[0] & 0xfc;
            }
            if (param_3 != (undefined4 *)0x0) {
              *param_3 = *(undefined4 *)(&DAT_8032ed40 + (local_1c[0] >> 9 & 0x1c));
            }
            uVar4 = 0;
          }
        }
      }
      else {
        uVar4 = 0xfffffffe;
      }
    }
    else if ((int)(&DAT_803af204)[param_1 * 0x44] < 1) {
      uVar4 = 0xffffffff;
    }
    else {
      if (param_2 != (uint *)0x0) {
        *param_2 = (uint)*(ushort *)(&DAT_803af1e8 + param_1 * 0x110);
      }
      if (param_3 != (undefined4 *)0x0) {
        *param_3 = *(undefined4 *)(&DAT_803af1ec + param_1 * 0x110);
      }
      uVar4 = 0;
    }
    FUN_802437a4(uVar1);
    return uVar4;
  }
  return 0xffffff80;
}

