// Function: FUN_80225ddc
// Entry: 80225ddc
// Size: 1100 bytes

void FUN_80225ddc(undefined4 param_1,int param_2)

{
  byte bVar3;
  short *psVar1;
  uint uVar2;
  
  if ((*(ushort *)(param_2 + 0x1e) & 2) != 0) {
    return;
  }
  *(undefined *)(param_2 + 0x11) = *(undefined *)(param_2 + 0x10);
  bVar3 = *(byte *)(param_2 + 0x10);
  if (bVar3 == 3) {
    uVar2 = FUN_80020078(0xcac);
    if (uVar2 != 0) {
      FUN_800201ac(0xda9,0);
      FUN_800201ac(0xc37,1);
      psVar1 = (short *)FUN_8002bac4();
      (**(code **)(*DAT_803dd72c + 0x1c))(psVar1 + 6,(int)*psVar1,1,0);
      *(undefined *)(param_2 + 0x10) = 7;
    }
    goto LAB_80226200;
  }
  if (bVar3 < 3) {
    if (bVar3 == 1) {
      if ((*(ushort *)(param_2 + 0x1e) & 1) == 0) {
        uVar2 = FUN_80020078(0x7f9);
        if (uVar2 == 0) {
          bVar3 = FUN_8001469c();
          if (bVar3 != 0) {
            FUN_800201ac(0x7ef,0);
            FUN_800201ac(0x7ed,0);
            FUN_800201ac(0xba6,0);
            FUN_800201ac(0xedd,0);
            *(undefined *)(param_2 + 0x10) = 0;
          }
        }
        else {
          *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 4;
          FUN_800146a8();
          uVar2 = FUN_80020078(0x7fa);
          if (uVar2 == 0) {
            FUN_8000bb38(0,0x109);
          }
          else {
            FUN_8000bb38(0,0x7e);
          }
          FUN_800201ac(0xba6,0);
          FUN_800201ac(0xedd,0);
          uVar2 = FUN_80020078(0x7fa);
          if (uVar2 == 0) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
            *(undefined *)(param_2 + 0x10) = 0;
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
            *(undefined *)(param_2 + 0x10) = 3;
          }
          *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 2;
        }
      }
      else {
        FUN_800146e8(0x1d,0x3c);
        FUN_800146c8();
        FUN_800201ac(0xba6,1);
        FUN_800201ac(0xedd,1);
      }
      goto LAB_80226200;
    }
    if (bVar3 != 0) {
      if ((*(ushort *)(param_2 + 0x1e) & 1) == 0) {
        uVar2 = FUN_80020078(0x7fa);
        if (uVar2 == 0) {
          bVar3 = FUN_8001469c();
          if (bVar3 != 0) {
            FUN_800201ac(0x7f0,0);
            FUN_800201ac(0x7ee,0);
            FUN_800201ac(0xba6,0);
            FUN_800201ac(0xedc,0);
            *(undefined *)(param_2 + 0x10) = 0;
          }
        }
        else {
          *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 8;
          FUN_800146a8();
          uVar2 = FUN_80020078(0x7f9);
          if (uVar2 == 0) {
            FUN_8000bb38(0,0x109);
          }
          else {
            FUN_8000bb38(0,0x7e);
          }
          FUN_800201ac(0xba6,0);
          FUN_800201ac(0xedc,0);
          uVar2 = FUN_80020078(0x7f9);
          if (uVar2 == 0) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
            *(undefined *)(param_2 + 0x10) = 0;
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
            *(undefined *)(param_2 + 0x10) = 3;
          }
          *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 2;
        }
      }
      else {
        FUN_800146e8(0x1d,0x50);
        FUN_800146c8();
        FUN_800201ac(0xba6,1);
        FUN_800201ac(0xedc,1);
      }
      goto LAB_80226200;
    }
  }
  else if (bVar3 == 7) goto LAB_80226200;
  if (((*(ushort *)(param_2 + 0x1e) & 4) == 0) && (uVar2 = FUN_80020078(0x7ed), uVar2 != 0)) {
    FUN_800201ac(0x7ef,1);
    *(float *)(param_2 + 4) = FLOAT_803e7a48;
    *(undefined *)(param_2 + 0x10) = 1;
    *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 2;
  }
  else if (((*(ushort *)(param_2 + 0x1e) & 8) == 0) && (uVar2 = FUN_80020078(0x7ee), uVar2 != 0)) {
    FUN_800201ac(0x7f0,1);
    *(float *)(param_2 + 4) = FLOAT_803e7a48;
    *(undefined *)(param_2 + 0x10) = 2;
    *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 2;
  }
LAB_80226200:
  *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) & 0xfffe;
  return;
}

