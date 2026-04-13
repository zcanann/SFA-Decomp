// Function: FUN_8012dca8
// Entry: 8012dca8
// Size: 936 bytes

void FUN_8012dca8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  ushort uVar6;
  char cVar7;
  char cVar8;
  byte bVar9;
  int iVar10;
  byte *pbVar11;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar12;
  undefined8 extraout_f1_01;
  
  uVar6 = DAT_803de3f6;
  if ((DAT_803de3f6 != 0) && ((DAT_803de3f6 < 0x78 || (0x82 < DAT_803de3f6)))) {
    DAT_803de3f6 = 0x78;
    if ((short)uVar6 < 0x1e) {
      iVar10 = 0;
      pbVar11 = &DAT_803dc6fc;
      do {
        uVar2 = FUN_80020078((uint)*(ushort *)(&DAT_8031bcda + (uint)*pbVar11 * 0x1c));
        if (uVar2 != 0) {
          cVar8 = (&DAT_803dc6fc)[iVar10];
          goto LAB_8012dd48;
        }
        pbVar11 = pbVar11 + 1;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 5);
      cVar8 = -1;
LAB_8012dd48:
      uVar2 = FUN_80020078(0x63c);
      uVar3 = FUN_80020078(0x4e9);
      uVar4 = FUN_80020078(0x5f3);
      uVar5 = FUN_80020078(0x5f4);
      iVar10 = uVar3 + uVar2 + uVar4 + uVar5;
      uVar2 = FUN_80020078(0x123);
      if (uVar2 != 0) {
        iVar10 = iVar10 + 1;
      }
      uVar2 = FUN_80020078(0x2e8);
      if (uVar2 != 0) {
        iVar10 = iVar10 + 1;
      }
      uVar2 = FUN_80020078(0x83b);
      if (uVar2 != 0) {
        iVar10 = iVar10 + 1;
      }
      uVar2 = FUN_80020078(0x83c);
      if (uVar2 != 0) {
        iVar10 = iVar10 + 1;
      }
      bVar9 = DAT_803dc6fc;
      if ((((iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)DAT_803dc6fc * 0x1c]) &&
           (bVar9 = bRam803dc6fd,
           iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc6fd * 0x1c])) &&
          (bVar9 = bRam803dc6fe,
          iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc6fe * 0x1c])) &&
         ((bVar9 = bRam803dc6ff,
          iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc6ff * 0x1c] &&
          (bVar9 = bRam803dc700,
          iVar10 < (int)(uint)(byte)(&DAT_8031bcdc)[(uint)bRam803dc700 * 0x1c])))) {
        bVar9 = 0xff;
      }
      uVar6 = FUN_800ea540();
      bVar1 = 0xad < uVar6;
      uVar2 = (uint)DAT_803de3fa;
      uVar12 = extraout_f1;
      if ((uVar2 == 2) && (bVar1)) {
        iVar10 = 0x51e4;
      }
      else if (((int)cVar8 == uVar2) && ((int)(char)bVar9 != uVar2)) {
        iVar10 = *(int *)(&DAT_8031bccc + uVar2 * 0x1c);
      }
      else if (uVar2 == 2) {
        cVar7 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
        uVar12 = extraout_f1_00;
        if ((cVar7 != '\x02') || (bVar1)) {
          if ((int)cVar8 == (int)(char)bVar9) {
            iVar10 = (char)bVar9 * 0x1c;
            uVar2 = FUN_80020078((uint)*(ushort *)(&DAT_8031bcde + iVar10));
            if (uVar2 == 0) {
              iVar10 = *(int *)(&DAT_8031bcd4 + iVar10);
            }
            else {
              iVar10 = 0x51e6;
            }
          }
          else {
            iVar10 = *(int *)(&DAT_8031bcd0 + (uint)DAT_803de3fa * 0x1c);
          }
        }
        else {
          iVar10 = 0x51e5;
        }
      }
      else if (((uVar2 != 0) ||
               (cVar8 = (**(code **)(*DAT_803dd72c + 0x40))(0xd), uVar12 = extraout_f1_01,
               cVar8 != '\x02')) || (bVar1)) {
        iVar10 = *(int *)(&DAT_8031bcd0 + (uint)DAT_803de3fa * 0x1c);
      }
      else {
        iVar10 = 0x51e2;
      }
      if (iVar10 != 0) {
        FUN_8000d220(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
    if (0xff < DAT_803de3f6) {
      DAT_803de3f6 = 0;
    }
  }
  return;
}

