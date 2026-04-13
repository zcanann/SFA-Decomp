// Function: FUN_80134d50
// Entry: 80134d50
// Size: 500 bytes

void FUN_80134d50(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  undefined8 uVar5;
  
  uVar3 = (uint)DAT_803de618;
  if (uVar3 < DAT_803dc872) {
    if (DAT_803de628 < 1) {
      uVar2 = (uint)DAT_803de616;
      if (uVar2 < 0x14) {
        bVar4 = (byte)((uVar2 * 0xff) / 0x14);
      }
      else if ((int)uVar2 < (int)(*(ushort *)(&DAT_8031dae2 + uVar3 * 4) - 0x14)) {
        bVar4 = 0xff;
      }
      else {
        if ((uVar3 == DAT_803dc872 - 1) && (DAT_803de624 == 0)) {
          FUN_8000a3a0(3,2,4000);
          DAT_803de624 = 1;
        }
        iVar1 = ((uint)DAT_803de616 - (uint)*(ushort *)(&DAT_8031dae2 + (uint)DAT_803de618 * 4)) *
                0xff;
        iVar1 = iVar1 / 0x14 + (iVar1 >> 0x1f);
        bVar4 = -((char)iVar1 - (char)(iVar1 >> 0x1f)) - 1;
      }
      uVar5 = FUN_80019940(0xff,0xff,0xff,bVar4);
      FUN_80016848(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031dae0 + (uint)DAT_803de618 * 4),0,0);
      DAT_803de614 = DAT_803de614 + (ushort)DAT_803dc071;
      DAT_803de616 = DAT_803de616 + DAT_803dc071;
      if (*(ushort *)(&DAT_8031dae2 + (uint)DAT_803de618 * 4) <= DAT_803de616) {
        uVar3 = DAT_803de618 + 1;
        DAT_803de618 = (ushort)uVar3;
        DAT_803de628 = 0x3c;
        if ((uVar3 & 0xffff) < (uint)DAT_803dc872) {
          DAT_803de616 = 0;
        }
      }
    }
    else {
      DAT_803de628 = DAT_803de628 - (ushort)DAT_803dc071;
      if (DAT_803de628 < 0) {
        DAT_803de628 = 0;
      }
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x57) {
      DAT_803de613 = 0;
      FUN_80014974(4);
      FUN_801171ec(4);
    }
  }
  return;
}

