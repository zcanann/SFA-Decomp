// Function: FUN_8006ef38
// Entry: 8006ef38
// Size: 1104 bytes

/* WARNING: Removing unreachable block (ram,0x8006f368) */

void FUN_8006ef38(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7)

{
  short sVar1;
  int iVar2;
  undefined2 *puVar3;
  uint uVar4;
  char cVar5;
  int iVar6;
  float *pfVar7;
  byte bVar8;
  uint uVar9;
  uint uVar10;
  uint in_LR;
  undefined4 uVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  float local_58;
  float local_54;
  float local_50;
  undefined2 local_4c;
  undefined2 local_4a;
  undefined2 local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar13 = FUN_802860d4();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  puVar3 = &DAT_8030e8b0;
  switch(param_5 & 0xff) {
  default:
    puVar3 = &DAT_8030e8d8;
    break;
  case 1:
    break;
  case 3:
    puVar3 = &DAT_8030e8c4;
    break;
  case 4:
    puVar3 = &DAT_8030e8ec;
    break;
  case 5:
    puVar3 = &DAT_8030e914;
    break;
  case 6:
    puVar3 = &DAT_8030e900;
    break;
  case 7:
    puVar3 = &DAT_8030e8d8;
    break;
  case 8:
    puVar3 = &DAT_8030e928;
    break;
  case 9:
    puVar3 = &DAT_8030e950;
    break;
  case 10:
    puVar3 = &DAT_8030e93c;
  }
  uVar9 = 0;
  for (bVar8 = 0; (int)(uint)bVar8 < (int)*(char *)((int)uVar13 + 0x1b); bVar8 = bVar8 + 1) {
    cVar5 = *(char *)((int)uVar13 + bVar8 + 0x13);
    if (cVar5 == '\x03') {
      uVar9 = uVar9 | 4;
      in_LR = 2;
    }
    else if (cVar5 < '\x03') {
      if (cVar5 == '\x01') {
        uVar9 = uVar9 | 1;
        in_LR = 0;
      }
      else if ('\0' < cVar5) {
        uVar9 = uVar9 | 2;
        in_LR = 1;
      }
    }
    else if (cVar5 < '\x05') {
      uVar9 = uVar9 | 8;
      in_LR = 3;
    }
  }
  if ((uVar9 == 0) ||
     (((*(byte *)(param_7 + 0x260) & 0x10) == 0 && (*(char *)(param_7 + 0x25b) != '\0'))))
  goto LAB_8006f368;
  iVar6 = (int)*(char *)(param_7 + 0xb8);
  if ((iVar6 < 0) || (0x22 < iVar6)) {
    uVar4 = 0;
  }
  else {
    uVar4 = (uint)(byte)(&DAT_8030e964)[iVar6];
  }
  if (*(int *)(param_7 + 0xc4) == 0) goto LAB_8006f110;
  sVar1 = *(short *)(*(int *)(param_7 + 0xc4) + 0x46);
  if (sVar1 == 0x1db) {
LAB_8006f10c:
    uVar4 = 4;
  }
  else if (sVar1 < 0x1db) {
    if ((sVar1 == 0x99) || ((sVar1 < 0x99 && (sVar1 == 0x5d)))) goto LAB_8006f10c;
  }
  else if (sVar1 == 0x223) goto LAB_8006f10c;
LAB_8006f110:
  if (puVar3 != (undefined2 *)0x0) {
    pfVar7 = (float *)(param_6 + (in_LR & 0xff) * 0xc);
    if (FLOAT_803dee20 < *(float *)(param_7 + 0x1b4)) {
      (**(code **)(*DAT_803dca98 + 8))(iVar2,uVar9,param_6,param_7);
      uVar4 = 5;
    }
    iVar6 = FUN_8002b9ec();
    if (iVar2 == iVar6) {
      if (*(short *)(*(int *)(iVar2 + 0xb8) + 0x81a) == 1) {
        FUN_8000bb18(0,0x3c2);
      }
      FUN_8000bb18(0,puVar3[uVar4]);
    }
    else {
      FUN_8000bae0((double)*pfVar7,(double)pfVar7[1],(double)pfVar7[2],iVar2,puVar3[uVar4]);
    }
  }
  if (bVar8 != 5) {
    uVar10 = 0;
    dVar12 = (double)(float)((double)FLOAT_803dee24 * param_2);
    for (; uVar9 != 0; uVar9 = (int)uVar9 >> 1) {
      pfVar7 = (float *)(param_6 + (uVar10 & 0xff) * 0xc);
      local_58 = *pfVar7;
      local_54 = pfVar7[1];
      local_50 = pfVar7[2];
      if ((uVar9 & 1) != 0) {
        if ((*(short *)(iVar2 + 0x44) == 1) || (*(short *)(iVar2 + 0x46) == 0x416)) {
          FUN_8006f950(iVar2,&local_58,uVar10 & 1,uVar4);
        }
        local_40 = *pfVar7;
        local_3c = pfVar7[1];
        local_38 = pfVar7[2];
        local_44 = (float)dVar12;
        local_4c = (undefined2)uVar4;
        local_48 = 0;
        local_4a = 0;
        local_58 = FLOAT_803dee28 * *(float *)(iVar2 + 0x24);
        local_54 = FLOAT_803dee28 * *(float *)(iVar2 + 0x28);
        local_50 = FLOAT_803dee28 * *(float *)(iVar2 + 0x2c);
        if ((uVar4 == 6) || (uVar4 == 3)) {
          for (cVar5 = FUN_800221a0(2,4); cVar5 != '\0'; cVar5 = cVar5 + -1) {
            (**(code **)(*DAT_803dca88 + 8))(iVar2,0x7e6,&local_4c,0x200001,0xffffffff,&local_58);
          }
        }
        else if (uVar4 == 2) {
          for (cVar5 = FUN_800221a0(4,8); cVar5 != '\0'; cVar5 = cVar5 + -1) {
            (**(code **)(*DAT_803dca88 + 8))(iVar2,0x7e6,&local_4c,0x200001,0xffffffff,&local_58);
          }
        }
      }
      uVar10 = uVar10 + 1;
    }
  }
LAB_8006f368:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286120();
  return;
}

