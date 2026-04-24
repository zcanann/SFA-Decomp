// Function: FUN_801bc2d8
// Entry: 801bc2d8
// Size: 1292 bytes

void FUN_801bc2d8(void)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  undefined4 local_40;
  undefined auStack60 [4];
  int local_38;
  undefined4 local_34;
  int local_30;
  int local_2c;
  undefined4 local_28;
  
  uVar9 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  iVar7 = (int)uVar9;
  iVar8 = *(int *)(iVar3 + 0xb8);
  FUN_8002b9ec();
  bVar1 = false;
  local_34 = DAT_802c2348;
  local_30 = DAT_802c234c;
  local_2c = DAT_802c2350;
  local_28 = DAT_802c2354;
  if (DAT_803ddb8c != 0) {
    DAT_803ddb8c = DAT_803ddb8c + -1;
  }
  iVar4 = FUN_8003687c(iVar3,&local_40,&local_38,auStack60);
  if (iVar4 != 0) {
    uVar2 = DAT_803ddb80 & 0xffffffbf;
    if (*(short *)(iVar8 + 0x402) == 1) {
      if (((DAT_803ddb80 & 8) == 0) || (local_38 != 2)) {
        bVar1 = true;
      }
    }
    else if ((*(short *)(iVar8 + 0x402) == 2) &&
            (((local_38 != 4 || (*(float *)(iVar3 + 0x98) < FLOAT_803e4c10)) ||
             (*(short *)(iVar3 + 0xa0) != 0x12)))) {
      bVar1 = true;
    }
    DAT_803ddb80 = uVar2;
    if (bVar1) {
      if (DAT_803ddb8c == 0) {
        FUN_8000bb18(iVar3,0x4b2);
        iVar7 = *(int *)(*(int *)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4) + 0x50) +
                local_38 * 0x10;
        DAT_803ac9a0 = FLOAT_803dcdd8 + *(float *)(iVar7 + 4);
        DAT_803ac9a4 = *(float *)(iVar7 + 8);
        DAT_803ac9a8 = FLOAT_803dcddc + *(float *)(iVar7 + 0xc);
        (**(code **)(*DAT_803dca88 + 8))(iVar3,0x328,&DAT_803ac994,0x200001,0xffffffff,0);
        DAT_803ac9a0 = DAT_803ac9a0 - *(float *)(iVar3 + 0x18);
        DAT_803ac9a4 = DAT_803ac9a4 - *(float *)(iVar3 + 0x1c);
        DAT_803ac9a8 = DAT_803ac9a8 - *(float *)(iVar3 + 0x20);
        DAT_803ac99c = FLOAT_803e4c44;
        DAT_803ac994 = 0;
        DAT_803ac996 = 0;
        DAT_803ac998 = 0;
        iVar7 = FUN_800221a0(0,0x9b);
        local_30 = local_30 + iVar7;
        iVar7 = FUN_800221a0(0,0x9b);
        local_2c = local_2c + iVar7;
        (**(code **)(*DAT_803ddb88 + 4))(iVar3,0,&DAT_803ac994,1,0xffffffff,&local_34);
        DAT_803ddb8c = 0x1e;
      }
    }
    else {
      if (*(int *)(iVar7 + 0x2d0) == 0) {
        uVar5 = FUN_8002b9ec();
        iVar6 = FUN_80295a04(uVar5,1);
        if (iVar6 != 0) {
          (**(code **)(*DAT_803dcab8 + 0x28))
                    (iVar3,iVar7,iVar8 + 0x35c,(int)*(short *)(iVar8 + 0x3f4),0,2,10,0xffffffff,
                     0xffffffff);
          *(undefined4 *)(iVar7 + 0x2d0) = uVar5;
          *(undefined *)(iVar7 + 0x349) = 0;
        }
      }
      if (*(short *)(iVar8 + 0x402) == 1) {
        if (*(char *)(iVar7 + 0x354) == '\x03') {
          (**(code **)(*DAT_803dca74 + 4))(iVar3,0x68,0,0,0);
        }
        else if (*(char *)(iVar7 + 0x354) == '\x02') {
          (**(code **)(*DAT_803dca74 + 4))(iVar3,0x6c,0,0,0);
        }
      }
      else if (*(short *)(iVar8 + 0x402) == 2) {
        if (*(char *)(iVar7 + 0x354) == '\x03') {
          (**(code **)(*DAT_803dca74 + 4))(iVar3,0x77,0,0,0);
        }
        else if (*(char *)(iVar7 + 0x354) == '\x02') {
          (**(code **)(*DAT_803dca74 + 4))(iVar3,0x78,0,0,0);
        }
      }
      *(undefined *)(iVar7 + 0x346) = 0;
      *(char *)(iVar7 + 0x34f) = (char)iVar4;
      *(char *)(iVar7 + 0x354) = *(char *)(iVar7 + 0x354) + -1;
      FUN_8000bb18(iVar3,0x4b1);
      if (*(char *)(iVar7 + 0x354) < '\x01') {
        *(undefined *)(iVar7 + 0x354) = 0;
        *(undefined *)(iVar7 + 0x349) = 0;
        (**(code **)(*DAT_803dca8c + 0x14))(iVar3,iVar7,0);
        *(ushort *)(*(int *)(iVar3 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(iVar3 + 0x54) + 0x60) & 0xfffe;
        *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) | 8;
        *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) & 0x7f;
        FUN_800200e8(0x20e,1);
        if (*(short *)(iVar8 + 0x402) == 1) {
          FUN_800200e8(0x20b,1);
        }
        else if (*(short *)(iVar8 + 0x402) == 2) {
          FUN_800200e8(0x266,1);
        }
      }
      else if (*(short *)(iVar8 + 0x402) == 1) {
        (**(code **)(*DAT_803dca8c + 0x14))(iVar3,iVar7,10);
      }
      else {
        (**(code **)(*DAT_803dca8c + 0x14))(iVar3,iVar7,0xb);
      }
      FUN_800378c4(local_40,0xe0001,iVar3,0);
    }
  }
  FUN_80286128();
  return;
}

