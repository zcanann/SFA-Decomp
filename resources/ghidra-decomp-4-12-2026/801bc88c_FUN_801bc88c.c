// Function: FUN_801bc88c
// Entry: 801bc88c
// Size: 1292 bytes

void FUN_801bc88c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r7;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  undefined8 uVar8;
  int local_40;
  uint uStack_3c;
  int local_38;
  undefined4 local_34;
  int local_30;
  int local_2c;
  undefined4 local_28;
  
  uVar8 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar6 = (int)uVar8;
  iVar7 = *(int *)(uVar3 + 0xb8);
  FUN_8002bac4();
  bVar1 = false;
  local_34 = DAT_802c2ac8;
  local_30 = DAT_802c2acc;
  local_2c = DAT_802c2ad0;
  local_28 = DAT_802c2ad4;
  if (DAT_803de80c != 0) {
    DAT_803de80c = DAT_803de80c + -1;
  }
  iVar4 = FUN_80036974(uVar3,&local_40,&local_38,&uStack_3c);
  if (iVar4 != 0) {
    uVar2 = DAT_803de800 & 0xffffffbf;
    if (*(short *)(iVar7 + 0x402) == 1) {
      if (((DAT_803de800 & 8) == 0) || (local_38 != 2)) {
        bVar1 = true;
      }
    }
    else if ((*(short *)(iVar7 + 0x402) == 2) &&
            (((local_38 != 4 || (*(float *)(uVar3 + 0x98) < FLOAT_803e58a8)) ||
             (*(short *)(uVar3 + 0xa0) != 0x12)))) {
      bVar1 = true;
    }
    DAT_803de800 = uVar2;
    if (bVar1) {
      if (DAT_803de80c == 0) {
        FUN_8000bb38(uVar3,0x4b2);
        iVar6 = *(int *)(*(int *)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4) + 0x50) +
                local_38 * 0x10;
        DAT_803ad600 = FLOAT_803dda58 + *(float *)(iVar6 + 4);
        DAT_803ad604 = *(float *)(iVar6 + 8);
        DAT_803ad608 = FLOAT_803dda5c + *(float *)(iVar6 + 0xc);
        (**(code **)(*DAT_803dd708 + 8))(uVar3,0x328,&DAT_803ad5f4,0x200001,0xffffffff,0);
        DAT_803ad600 = DAT_803ad600 - *(float *)(uVar3 + 0x18);
        DAT_803ad604 = DAT_803ad604 - *(float *)(uVar3 + 0x1c);
        DAT_803ad608 = DAT_803ad608 - *(float *)(uVar3 + 0x20);
        DAT_803ad5fc = FLOAT_803e58dc;
        DAT_803ad5f4 = 0;
        DAT_803ad5f6 = 0;
        DAT_803ad5f8 = 0;
        uVar2 = FUN_80022264(0,0x9b);
        local_30 = local_30 + uVar2;
        uVar2 = FUN_80022264(0,0x9b);
        local_2c = local_2c + uVar2;
        (**(code **)(*DAT_803de808 + 4))(uVar3,0,&DAT_803ad5f4,1,0xffffffff,&local_34);
        DAT_803de80c = 0x1e;
      }
    }
    else {
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        iVar5 = FUN_8002bac4();
        uVar2 = FUN_80296164(iVar5,1);
        if (uVar2 != 0) {
          in_r7 = 0;
          in_r8 = 2;
          in_r9 = 10;
          in_r10 = 0xffffffff;
          (**(code **)(*DAT_803dd738 + 0x28))
                    (uVar3,iVar6,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4));
          *(int *)(iVar6 + 0x2d0) = iVar5;
          *(undefined *)(iVar6 + 0x349) = 0;
        }
      }
      if (*(short *)(iVar7 + 0x402) == 1) {
        if (*(char *)(iVar6 + 0x354) == '\x03') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x68,0,0);
        }
        else if (*(char *)(iVar6 + 0x354) == '\x02') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x6c,0,0);
        }
      }
      else if (*(short *)(iVar7 + 0x402) == 2) {
        if (*(char *)(iVar6 + 0x354) == '\x03') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x77,0,0);
        }
        else if (*(char *)(iVar6 + 0x354) == '\x02') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x78,0,0);
        }
      }
      *(undefined *)(iVar6 + 0x346) = 0;
      *(char *)(iVar6 + 0x34f) = (char)iVar4;
      *(char *)(iVar6 + 0x354) = *(char *)(iVar6 + 0x354) + -1;
      FUN_8000bb38(uVar3,0x4b1);
      if (*(char *)(iVar6 + 0x354) < '\x01') {
        *(undefined *)(iVar6 + 0x354) = 0;
        *(undefined *)(iVar6 + 0x349) = 0;
        (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,0);
        *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & 0xfffe;
        *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) | 8;
        *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) & 0x7f;
        uVar8 = FUN_800201ac(0x20e,1);
        if (*(short *)(iVar7 + 0x402) == 1) {
          uVar8 = FUN_800201ac(0x20b,1);
        }
        else if (*(short *)(iVar7 + 0x402) == 2) {
          uVar8 = FUN_800201ac(0x266,1);
        }
      }
      else if (*(short *)(iVar7 + 0x402) == 1) {
        uVar8 = (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,10);
      }
      else {
        uVar8 = (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,0xb);
      }
      FUN_800379bc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_40,0xe0001,
                   uVar3,0,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

