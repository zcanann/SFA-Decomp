// Function: FUN_801cbd88
// Entry: 801cbd88
// Size: 2032 bytes

/* WARNING: Removing unreachable block (ram,0x801cc558) */

void FUN_801cbd88(void)

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
  local_5c = FLOAT_803e518c;
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
    if (((iVar7 != 0) && (local_5c < FLOAT_803e5190)) && (FLOAT_803e5194 < local_5c)) {
      dVar10 = (double)(*(float *)(iVar7 + 0x14) - *(float *)(iVar2 + 0x14));
      if (dVar10 <= (double)FLOAT_803e5198) {
        if (dVar10 < (double)FLOAT_803e5198) {
          dVar10 = (double)(float)(dVar10 * (double)FLOAT_803e519c);
        }
        if (psVar8[4] != 0x1e) {
          psVar8[4] = 0x1e;
        }
        uStack84 = (int)psVar8[4] ^ 0x80000000;
        local_58 = 0x43300000;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e51a8) *
                      ((float)(dVar10 - (double)FLOAT_803e5194) / FLOAT_803e51a0));
        local_50 = (longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dca70 + 0x38))(3,uVar6 & 0xff);
        uStack68 = (int)psVar8[2] ^ 0x80000000;
        local_48 = 0x43300000;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e51a8) *
                      ((FLOAT_803e51a0 - (float)(dVar10 - (double)FLOAT_803e5194)) / FLOAT_803e51a0)
                      );
        local_40 = (double)(longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dca70 + 0x38))(2,uVar6 & 0xff);
      }
    }
    switch(*(undefined *)((int)psVar8 + 0x13)) {
    case 0:
      dVar10 = (double)FUN_80021704(iVar1 + 0x18,iVar2 + 0x18);
      local_40 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
      if (dVar10 < (double)(float)(local_40 - DOUBLE_803e51a8)) {
        *(undefined *)((int)psVar8 + 0x13) = 1;
        FUN_800200e8(0x129,0);
        (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0xffffffff);
        piVar4 = (int *)FUN_80013ec8(0x83,1);
        (**(code **)(*piVar4 + 4))(iVar1,1,0,1,0xffffffff,0);
        FUN_80013e2c(piVar4);
        piVar4 = (int *)FUN_80013ec8(0x84,1);
        (**(code **)(*piVar4 + 4))(iVar1,0,0,1,0xffffffff,0);
        FUN_80013e2c(piVar4);
        FUN_800200e8(0x126,0);
        (**(code **)(*DAT_803dca7c + 0x20))(psVar8 + 6);
      }
      break;
    case 1:
      if (*(char *)(psVar8 + 10) == '\x01') {
        *(undefined *)((int)psVar8 + 0x13) = 2;
        psVar8[1] = 0xa0;
      }
      break;
    case 2:
      if ((*(char *)(psVar8 + 9) == '\0') && (iVar2 = FUN_8001ffb4(0x1d3), iVar2 == 0)) {
        FUN_800200e8(0x1d3,1);
      }
      iVar2 = FUN_8001ffb4(0x1d8);
      if (iVar2 != 0) {
        *(char *)(psVar8 + 9) = *(char *)(psVar8 + 9) + '\x01';
        FUN_800200e8(0x1d8,0);
      }
      local_40 = (double)(longlong)(int)FLOAT_803db414;
      psVar8[7] = psVar8[7] - (short)(int)FLOAT_803db414;
      FUN_80137948(s_time__d_80326680,(int)psVar8[7]);
      if (psVar8[7] < 1) {
        FUN_800200e8(0x1d4,1);
        (**(code **)(*DAT_803dca54 + 0x48))(2,iVar1,0xffffffff);
        psVar8[1] = 10;
        *(undefined *)((int)psVar8 + 0x13) = 6;
        (**(code **)(*DAT_803dca70 + 0x18))(3,0x35,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        FUN_800200e8(0x1d3,0);
      }
      else if (*(char *)(psVar8 + 9) == '\x01') {
        *(undefined *)((int)psVar8 + 0x13) = 3;
        psVar8[1] = 200;
        psVar8[5] = -3;
      }
      break;
    case 3:
      iVar7 = FUN_8001ffb4(0x1d1);
      if (iVar7 == 0) {
        FUN_80296b78(iVar2,0xffffffff);
        FUN_800200e8(0x126,0);
        (**(code **)(*DAT_803dca70 + 0x18))(3,0x2a,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        (**(code **)(*DAT_803dca54 + 0x48))(1,iVar1,0xffffffff);
        *(undefined *)((int)psVar8 + 0x13) = 4;
      }
      else {
        psVar8[4] = 1;
        (**(code **)(*DAT_803dca70 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        FUN_800200e8(0x129,1);
        *(undefined *)((int)psVar8 + 0x13) = 5;
      }
      break;
    case 4:
      iVar1 = FUN_8001ffb4(0xfd);
      if (iVar1 == 0) {
        FUN_800200e8(0xfd,1);
      }
      FUN_800200e8(0x1d2,0);
      FUN_800200e8(0x127,0);
      *(undefined *)((int)psVar8 + 0x13) = 5;
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
      break;
    case 6:
      *(undefined *)((int)psVar8 + 0x13) = 0;
      *(undefined *)(psVar8 + 10) = 0;
      psVar8[1] = 400;
      FUN_800200e8(0x129,1);
      FUN_800200e8(0x126,1);
      FUN_800200e8(0x127,1);
      piVar4 = (int *)FUN_80013ec8(0x6a,1);
      sVar5 = (**(code **)(*piVar4 + 4))(iVar1,2,0,0x402,0xffffffff,0);
      psVar8[6] = sVar5;
      FUN_80013e2c(piVar4);
      FUN_800200e8(0x1d8,0);
      *(undefined *)(psVar8 + 9) = 0;
      psVar8[7] = 4000;
      FUN_800200e8(0x1d4,0);
    }
  }
  else {
    psVar8[1] = psVar8[1] - (ushort)DAT_803db410;
    if ((psVar8[1] < 1) && (psVar8[1] = 0, *(char *)(psVar8 + 0xb) == '\0')) {
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x2c,0x50,(int)psVar8[4],0);
      *(undefined *)(psVar8 + 0xb) = 1;
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_8028611c();
  return;
}

