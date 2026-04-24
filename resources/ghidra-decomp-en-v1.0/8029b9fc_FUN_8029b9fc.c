// Function: FUN_8029b9fc
// Entry: 8029b9fc
// Size: 524 bytes

int FUN_8029b9fc(undefined8 param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_2 + 0xb8);
  if ((*(char *)(param_3 + 0x349) == '\x01') || (*(short *)(param_3 + 0x274) == 0x26)) {
    iVar1 = FUN_802ac7dc(param_1,param_2,param_3,iVar3);
    if (iVar1 == 0) {
      if ((*(short *)(param_3 + 0x274) == 0x26) || ((*(byte *)(iVar3 + 0x3f6) >> 5 & 1) != 0)) {
        iVar1 = 0;
      }
      else if ((*(short *)(param_3 + 0x274) == 0x39) ||
              (uVar2 = FUN_80014dd8(0), (uVar2 & 0x20) == 0)) {
        if (*(short *)(param_3 + 0x274) == 0x39) {
          iVar1 = 0;
        }
        else {
          if ((((*(uint *)(param_3 + 0x31c) & 0x100) != 0) && (DAT_803de44c != 0)) &&
             ((*(byte *)(iVar3 + 0x3f4) >> 6 & 1) != 0)) {
            *(undefined *)(iVar3 + 0x8b4) = 4;
            *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0xf7 | 8;
          }
          iVar1 = FUN_80299e44(param_1,param_2,param_3);
          if (iVar1 == 0) {
            iVar1 = 0;
          }
        }
      }
      else {
        *(byte *)(iVar3 + 0x3f6) = *(byte *)(iVar3 + 0x3f6) & 0xdf | 0x20;
        *(undefined **)(param_3 + 0x308) = &LAB_8029782c;
        iVar1 = 0x3a;
      }
    }
    else {
      if ((DAT_803de44c != 0) && ((*(byte *)(iVar3 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar3 + 0x8b4) = 1;
        *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0xf7 | 8;
      }
      *(undefined4 *)(param_3 + 0x2d0) = 0;
      *(undefined *)(param_3 + 0x349) = 0;
      (**(code **)(*DAT_803dca50 + 0x48))(0);
    }
  }
  else {
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar3 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar3 + 0x8b4) = 0;
      *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0xf7;
    }
    *(code **)(param_3 + 0x308) = FUN_802a514c;
    iVar1 = 2;
  }
  return iVar1;
}

