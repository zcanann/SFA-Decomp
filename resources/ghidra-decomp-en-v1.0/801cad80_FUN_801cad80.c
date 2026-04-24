// Function: FUN_801cad80
// Entry: 801cad80
// Size: 2228 bytes

/* WARNING: Removing unreachable block (ram,0x801cb614) */

void FUN_801cad80(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  short *psVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack104 [4];
  int local_64;
  undefined4 local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  double local_40;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860d0();
  psVar8 = *(short **)(iVar1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  local_5c = FLOAT_803e515c;
  *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(iVar1 + 0xc);
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(iVar1 + 0x10);
  *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(iVar1 + 0x14);
  iVar7 = *(int *)(iVar1 + 0xb8);
  local_60 = 0;
  while (iVar3 = FUN_800374ec(iVar1,&local_64,auStack104,&local_60), iVar3 != 0) {
    if (local_64 == 0x30006) {
      *(undefined2 *)(iVar7 + 6) = 0x10;
    }
    else if ((local_64 < 0x30006) && (0x30004 < local_64)) {
      *(undefined2 *)(iVar7 + 6) = 0xfffd;
    }
  }
  FUN_800200e8(0x127,1);
  if (psVar8[3] != 0) {
    psVar8[2] = psVar8[2] + psVar8[3];
    if (psVar8[2] < 0xd) {
      psVar8[2] = 0xc;
      psVar8[3] = 0;
    }
    else if (0x45 < psVar8[2]) {
      psVar8[2] = 0x46;
      psVar8[3] = 0;
    }
    (**(code **)(*DAT_803dca70 + 0x38))(2,psVar8[2] & 0xff);
  }
  if (psVar8[5] != 0) {
    psVar8[4] = psVar8[4] + psVar8[5];
    if ((psVar8[4] < 2) && (psVar8[5] < 1)) {
      psVar8[4] = 1;
      psVar8[5] = 0;
    }
    else if ((0x45 < psVar8[4]) && (-1 < psVar8[5])) {
      psVar8[4] = 0x46;
      psVar8[5] = 0;
    }
    (**(code **)(*DAT_803dca70 + 0x38))(3,psVar8[4] & 0xff);
  }
  if (psVar8[1] < 1) {
    iVar7 = FUN_80036e58(0xe,iVar2,&local_5c);
    if (((iVar7 != 0) && (local_5c < FLOAT_803e5160)) && (FLOAT_803e5164 < local_5c)) {
      dVar10 = (double)(*(float *)(iVar7 + 0x14) - *(float *)(iVar2 + 0x14));
      if (dVar10 <= (double)FLOAT_803e5168) {
        if (dVar10 < (double)FLOAT_803e5168) {
          dVar10 = (double)(float)(dVar10 * (double)FLOAT_803e516c);
        }
        if (psVar8[4] != 0x1e) {
          psVar8[4] = 0x1e;
        }
        uStack84 = (int)psVar8[4] ^ 0x80000000;
        local_58 = 0x43300000;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e5178) *
                      ((float)(dVar10 - (double)FLOAT_803e5164) / FLOAT_803e5170));
        local_50 = (longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dca70 + 0x38))(3,uVar6 & 0xff);
        uStack68 = (int)psVar8[2] ^ 0x80000000;
        local_48 = 0x43300000;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e5178) *
                      ((FLOAT_803e5170 - (float)(dVar10 - (double)FLOAT_803e5164)) / FLOAT_803e5170)
                      );
        local_40 = (double)(longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dca70 + 0x38))(2,uVar6 & 0xff);
      }
    }
    switch(*(undefined *)((int)psVar8 + 0xf)) {
    case 0:
      iVar7 = FUN_8001ffb4(0x5b5);
      if ((iVar7 == 0) && (iVar7 = FUN_8001ffb4(0x594), iVar7 != 0)) {
        FUN_800200e8(0x5b5,1);
      }
      FUN_800200e8(0x5b9,0);
      dVar10 = (double)FUN_80021704(iVar1 + 0x18,iVar2 + 0x18);
      local_40 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
      if (dVar10 < (double)(float)(local_40 - DOUBLE_803e5178)) {
        *(undefined *)((int)psVar8 + 0xf) = 1;
        FUN_800200e8(0x129,0);
        (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0xffffffff);
        piVar4 = (int *)FUN_80013ec8(0x83,1);
        (**(code **)(*piVar4 + 4))(iVar1,0,0,1,0xffffffff,0);
        FUN_80013e2c(piVar4);
        piVar4 = (int *)FUN_80013ec8(0x84,1);
        (**(code **)(*piVar4 + 4))(iVar1,0,0,1,0xffffffff,0);
        FUN_80013e2c(piVar4);
        FUN_800200e8(0x126,0);
        (**(code **)(*DAT_803dca7c + 0x20))(psVar8 + 6);
      }
      break;
    case 1:
      if (*(char *)(psVar8 + 8) == '\x01') {
        *(undefined *)((int)psVar8 + 0xf) = 2;
        psVar8[1] = 0xa0;
      }
      break;
    case 2:
      if ((*(char *)(psVar8 + 7) == '\0') && (iVar2 = FUN_8001ffb4(0x1cd), iVar2 == 0)) {
        FUN_800200e8(0x1cd,1);
      }
      iVar2 = FUN_8001ffb4(0x5b2);
      if (iVar2 != 0) {
        *(char *)(psVar8 + 7) = *(char *)(psVar8 + 7) + '\x01';
        psVar8[1] = 100;
        if (*(char *)(psVar8 + 7) == '\x01') {
          (**(code **)(*DAT_803dca54 + 0x48))(3,iVar1,0xffffffff);
        }
      }
      break;
    case 3:
      local_5c = FLOAT_803e5174;
      iVar2 = FUN_80036e58(3,iVar1,&local_5c);
      if (iVar2 != 0) {
        FUN_8002cbc4();
      }
      iVar2 = FUN_8001ffb4(0x1ce);
      if (iVar2 == 0) {
        FUN_800200e8(0x126,0);
        (**(code **)(*DAT_803dca70 + 0x18))(3,0x2a,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        (**(code **)(*DAT_803dca54 + 0x48))(1,iVar1,0xffffffff);
      }
      else {
        psVar8[4] = 1;
        (**(code **)(*DAT_803dca70 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        FUN_800200e8(0x129,1);
        *(undefined *)((int)psVar8 + 0xf) = 5;
      }
      break;
    case 4:
      iVar1 = FUN_8001ffb4(0xfd);
      if (iVar1 == 0) {
        FUN_800200e8(0xfd,1);
      }
      FUN_800200e8(0x1cf,0);
      FUN_800200e8(0x127,0);
      *(undefined *)((int)psVar8 + 0xf) = 5;
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
      FUN_800200e8(0x1ce,1);
      (**(code **)(*DAT_803dcaac + 0x44))(0xb,6);
      break;
    case 6:
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x35,0x50,psVar8[4] & 0xff,0);
      psVar8[5] = 1;
      (**(code **)(*DAT_803dca54 + 0x48))(2,iVar1,0xffffffff);
      local_5c = FLOAT_803e5174;
      iVar2 = FUN_80036e58(3,iVar1,&local_5c);
      if (iVar2 != 0) {
        FUN_8002cbc4();
      }
      *(undefined *)((int)psVar8 + 0xf) = 0;
      psVar8[1] = 400;
      FUN_800200e8(0x129,1);
      FUN_800200e8(0x126,1);
      FUN_800200e8(0x127,1);
      FUN_800200e8(0x5b2,0);
      FUN_800200e8(0x5b9,1);
      piVar4 = (int *)FUN_80013ec8(0x6a,1);
      sVar5 = (**(code **)(*piVar4 + 4))(iVar1,0,0,0x402,0xffffffff,0);
      psVar8[6] = sVar5;
      FUN_80013e2c(piVar4);
      FUN_800200e8(0x1cd,0);
      *(undefined *)(psVar8 + 7) = 0;
      *(undefined *)(psVar8 + 8) = 0;
      break;
    case 7:
      (**(code **)(*DAT_803dca54 + 0x48))(5,iVar1,0xffffffff);
      *(undefined *)((int)psVar8 + 0xf) = 3;
      psVar8[1] = 0;
      psVar8[5] = -3;
      break;
    case 8:
      (**(code **)(*DAT_803dca54 + 0x48))(4,iVar1,0xffffffff);
      *(undefined *)((int)psVar8 + 0xf) = 6;
      psVar8[1] = 0;
      psVar8[5] = -3;
    }
  }
  else {
    psVar8[1] = psVar8[1] - (ushort)DAT_803db410;
    if ((psVar8[1] < 1) && (psVar8[1] = 0, *(char *)(psVar8 + 9) == '\0')) {
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x2c,0x50,(int)psVar8[4],0);
      *(undefined *)(psVar8 + 9) = 1;
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_8028611c();
  return;
}

