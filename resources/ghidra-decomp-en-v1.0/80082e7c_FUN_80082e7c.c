// Function: FUN_80082e7c
// Entry: 80082e7c
// Size: 2176 bytes

void FUN_80082e7c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,char param_5)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  byte *pbVar7;
  int iVar8;
  uint uVar9;
  double dVar10;
  undefined8 uVar11;
  undefined4 local_38;
  undefined4 local_34;
  double local_30;
  
  uVar11 = FUN_802860d0();
  iVar8 = (int)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  uVar9 = param_4 >> 8 & 0xff;
  switch(param_4 & 0xff) {
  case 2:
    if (param_5 == '\0') {
      local_38 = 0x19;
      local_34 = 0x15;
      if (*(int *)(param_3 + 0x28) < 0) {
        uVar6 = (**(code **)(*DAT_803dca9c + 0x14))
                          ((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10),
                           (double)*(float *)(iVar8 + 0x14),&local_38,2,uVar9);
        *(undefined4 *)(param_3 + 0x28) = uVar6;
        if (-1 < *(int *)(param_3 + 0x28)) {
          if (*(int *)(param_3 + 0x2c) != 0) {
            FUN_80023800();
            *(undefined4 *)(param_3 + 0x2c) = 0;
          }
          uVar6 = FUN_80023cc8(0x2c,0x11,0);
          *(undefined4 *)(param_3 + 0x2c) = uVar6;
          if (*(int *)(param_3 + 0x2c) == 0) {
            *(undefined4 *)(param_3 + 0x28) = 0xffffffff;
          }
          else {
            FUN_800843c4(*(int *)(param_3 + 0x2c),*(undefined4 *)(param_3 + 0x28));
          }
        }
      }
    }
    break;
  case 9:
    if (param_5 == '\0') {
      *(byte *)(param_3 + 0x7f) = *(byte *)(param_3 + 0x7f) | 1;
    }
    break;
  case 0xe:
    if ((param_5 == '\0') && ((&DAT_8039a358)[*(char *)(param_3 + 0x57)] == '\0')) {
      (**(code **)(*DAT_803dca4c + 8))(uVar9,1);
    }
    break;
  case 0xf:
    if ((param_5 == '\0') && ((&DAT_8039a358)[*(char *)(param_3 + 0x57)] == '\0')) {
      (**(code **)(*DAT_803dca4c + 0xc))(uVar9,1);
    }
    break;
  case 0x12:
    if (param_5 == '\0') {
      pbVar7 = &DAT_80399e50 + *(char *)(param_3 + 0x57);
      bVar1 = *pbVar7;
      if ((bVar1 & 0x10) == 0) {
        *pbVar7 = bVar1 | 0x10;
      }
      else {
        *pbVar7 = bVar1 & 0xef;
      }
    }
    break;
  case 0x14:
    DAT_803dd10c = 0x47;
    DAT_803dd108 = param_4 >> 8 & 0x7f;
    DAT_803dd104 = 1;
    DAT_803dd100 = 0x78;
    break;
  case 0x17:
    if ((param_5 == '\0') && ((int)uVar9 < (int)*(char *)(*(int *)(iVar5 + 0x50) + 0x55))) {
      if (*(short *)(iVar5 + 0x44) == 1) {
        if ((&DAT_8039a3b0)[*(char *)(param_3 + 0x57)] == 0x46) {
          if (uVar9 == 1) {
            uVar9 = 0;
          }
          FUN_80295e90(iVar5,uVar9);
        }
      }
      else {
        FUN_8002b884(iVar5,uVar9);
      }
    }
    break;
  case 0x18:
    if (*(short *)(iVar5 + 0x44) == 1) {
      FUN_802967e0(iVar5,uVar9);
    }
    break;
  case 0x19:
    if (*(short *)(iVar5 + 0x44) == 1) {
      FUN_8029672c(iVar5,uVar9);
    }
    break;
  case 0x1a:
    DAT_803dd10c = 0x42;
    DAT_803dd108 = 4;
    DAT_803dd104 = 0;
    DAT_803dd100 = 0;
    break;
  case 0x21:
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 0x400;
    *(byte *)(param_3 + 0x136) = (byte)(uVar9 << 4) | *(byte *)(param_3 + 0x136) & 0xf;
    break;
  case 0x22:
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfbff;
    *(byte *)(param_3 + 0x136) = *(byte *)(param_3 + 0x136) & 0xf;
    break;
  case 0x23:
    *(byte *)(param_3 + 0x136) = *(byte *)(param_3 + 0x136) & 0xfb | 4;
    break;
  case 0x24:
    uVar6 = FUN_800571e4();
    (**(code **)(*DAT_803dcaac + 0x1c))(0,0,1,uVar6);
    break;
  case 0x26:
    uVar6 = FUN_8002b9ec();
    FUN_80296bf4(uVar6,uVar9);
    break;
  case 0x2c:
    local_30 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
    FUN_800550c4((double)((float)(local_30 - DOUBLE_803defb8) / FLOAT_803df004),1);
    break;
  case 0x2d:
    FUN_800550c4((double)FLOAT_803defb0,0);
    break;
  case 0x2e:
    FUN_800550b4(1);
    break;
  case 0x2f:
    FUN_800550b4(0);
    break;
  case 0x30:
    FUN_800200e8(0x3b0,1);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x134,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x135,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x142,0);
    break;
  case 0x31:
    FUN_800200e8(0x3b0,1);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x136,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x137,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x143,0);
    break;
  case 0x32:
    FUN_800200e8(0x3b0,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x134,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x135,0);
    uVar6 = FUN_8002b9ec();
    uVar4 = FUN_8002b9ec();
    FUN_80008cbc(uVar4,uVar6,0x142,0);
    FUN_800887cc();
  }
  switch(param_4 & 0xff) {
  case 0:
    DAT_803dd0da = 1;
    uVar6 = 0;
    goto LAB_800836e4;
  case 7:
    if (param_5 == '\0') {
      FUN_8000fad8();
      iVar5 = FUN_8002b9ec();
      if (iVar5 != 0) {
        dVar10 = (double)FUN_80021690(iVar5 + 0x18,iVar8 + 0x18);
        local_30 = (double)CONCAT44(0x43300000,uVar9 - 7 ^ 0x80000000);
        fVar2 = FLOAT_803df008 * (float)(local_30 - DOUBLE_803defb8) + FLOAT_803defc8;
        if (dVar10 < (double)FLOAT_803df00c) {
          if ((double)FLOAT_803df010 < dVar10) {
            fVar2 = fVar2 * (FLOAT_803defc8 -
                            (float)(dVar10 - (double)FLOAT_803df010) / FLOAT_803df014);
          }
          FUN_8000e650((double)(FLOAT_803db730 * fVar2),(double)(FLOAT_803db730 * fVar2));
        }
      }
    }
    break;
  case 10:
    FUN_800146bc(0x12,uVar9);
    break;
  case 0xb:
    FUN_800146bc(0x11,uVar9);
    break;
  case 0xc:
    FUN_8001469c();
    break;
  case 0xd:
    FUN_8000b7bc(iVar5,0x7f);
    break;
  case 0x10:
    *(char *)(param_3 + 0x7d) = (char)uVar9;
    break;
  case 0x13:
    if (param_5 == '\0') {
      (&DAT_80399e50)[*(char *)(param_3 + 0x57)] = (&DAT_80399e50)[*(char *)(param_3 + 0x57)] & 0xef
      ;
    }
    break;
  case 0x15:
    DAT_803dd10c = 0x48;
    DAT_803dd108 = uVar9 & 0x7f;
    DAT_803dd104 = 1;
    DAT_803dd100 = 0x78;
    break;
  case 0x17:
    if (((param_5 == '\0') && (*(short *)(iVar5 + 0x44) != 1)) &&
       ((int)uVar9 < (int)*(char *)(*(int *)(iVar5 + 0x50) + 0x55))) {
      FUN_8002b884(iVar5,uVar9);
    }
    break;
  case 0x1b:
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar5 + 0xac),uVar9,1);
    break;
  case 0x1c:
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar5 + 0xac),uVar9,0);
    break;
  case 0x1d:
    (**(code **)(*DAT_803dcaac + 0x44))((int)*(char *)(iVar5 + 0xac),uVar9);
    break;
  case 0x1e:
    if (param_5 == '\0') {
      (&DAT_80399e50)[*(char *)(param_3 + 0x57)] = (&DAT_80399e50)[*(char *)(param_3 + 0x57)] | 0x10
      ;
    }
    break;
  case 0x1f:
    (**(code **)(*DAT_803dcaac + 0x2c))();
    break;
  case 0x20:
    (**(code **)(*DAT_803dcaac + 0x28))();
    break;
  case 0x25:
    FUN_8001467c();
    break;
  case 0x27:
    if (DAT_803db720 == *(char *)(param_3 + 0x57)) {
      DAT_803db728 = (int)(float)(&DAT_8039a1ac)[*(char *)(param_3 + 0x57)];
      local_30 = (double)(longlong)DAT_803db728;
      uVar6 = FUN_8008023c((int)*(char *)(param_3 + 0x57));
      uVar9 = countLeadingZeros(uVar6);
      DAT_803dd070 = (undefined2)(uVar9 >> 5);
    }
    break;
  case 0x28:
    iVar8 = (int)*(char *)(param_3 + 0x57);
    if ((&DAT_80399c4c)[iVar8] == '\0') {
      uVar3 = (int)(short)(&DAT_8039a3b0)[iVar8] - 1U & 0x3fff;
      DAT_803dd068 = uVar3;
      iVar5 = FUN_8007fff8(&DAT_8030eca8,5,uVar3);
      if (iVar5 != 0) {
        iVar5 = FUN_8000d200(*(undefined4 *)(iVar5 + uVar9 * 4),FUN_80080384);
        if (iVar5 != 0) {
          DAT_803db720 = iVar8;
        }
        iVar8 = FUN_8007fff8(&DAT_8030ecd0,5,uVar3);
        if (iVar8 != 0) {
          DAT_803db718 = *(undefined4 *)(iVar8 + uVar9 * 4);
        }
      }
    }
    break;
  case 0x33:
    DAT_803dd100 = uVar9;
  }
  uVar6 = 1;
LAB_800836e4:
  FUN_8028611c(uVar6);
  return;
}

