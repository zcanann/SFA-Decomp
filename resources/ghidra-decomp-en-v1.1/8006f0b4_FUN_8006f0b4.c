// Function: FUN_8006f0b4
// Entry: 8006f0b4
// Size: 1104 bytes

/* WARNING: Removing unreachable block (ram,0x8006f4e4) */
/* WARNING: Removing unreachable block (ram,0x8006f0c4) */

void FUN_8006f0b4(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7)

{
  char cVar1;
  short sVar2;
  uint uVar3;
  undefined2 *puVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  float *pfVar8;
  uint uVar9;
  byte bVar10;
  uint in_LR;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  undefined8 uVar12;
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
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar12 = FUN_80286838();
  uVar3 = (uint)((ulonglong)uVar12 >> 0x20);
  puVar4 = &DAT_8030f470;
  switch(param_5 & 0xff) {
  default:
    puVar4 = &DAT_8030f498;
    break;
  case 1:
    break;
  case 3:
    puVar4 = &DAT_8030f484;
    break;
  case 4:
    puVar4 = &DAT_8030f4ac;
    break;
  case 5:
    puVar4 = &DAT_8030f4d4;
    break;
  case 6:
    puVar4 = &DAT_8030f4c0;
    break;
  case 7:
    puVar4 = &DAT_8030f498;
    break;
  case 8:
    puVar4 = &DAT_8030f4e8;
    break;
  case 9:
    puVar4 = &DAT_8030f510;
    break;
  case 10:
    puVar4 = &DAT_8030f4fc;
  }
  uVar9 = 0;
  for (bVar10 = 0; (int)(uint)bVar10 < (int)*(char *)((int)uVar12 + 0x1b); bVar10 = bVar10 + 1) {
    cVar1 = *(char *)((int)uVar12 + bVar10 + 0x13);
    if (cVar1 == '\x03') {
      uVar9 = uVar9 | 4;
      in_LR = 2;
    }
    else if (cVar1 < '\x03') {
      if (cVar1 == '\x01') {
        uVar9 = uVar9 | 1;
        in_LR = 0;
      }
      else if ('\0' < cVar1) {
        uVar9 = uVar9 | 2;
        in_LR = 1;
      }
    }
    else if (cVar1 < '\x05') {
      uVar9 = uVar9 | 8;
      in_LR = 3;
    }
  }
  if ((uVar9 == 0) ||
     (((*(byte *)(param_7 + 0x260) & 0x10) == 0 && (*(char *)(param_7 + 0x25b) != '\0'))))
  goto LAB_8006f4e4;
  iVar7 = (int)*(char *)(param_7 + 0xb8);
  if ((iVar7 < 0) || (0x22 < iVar7)) {
    uVar5 = 0;
  }
  else {
    uVar5 = (uint)(byte)(&DAT_8030f524)[iVar7];
  }
  if (*(int *)(param_7 + 0xc4) == 0) goto LAB_8006f28c;
  sVar2 = *(short *)(*(int *)(param_7 + 0xc4) + 0x46);
  if (sVar2 == 0x1db) {
LAB_8006f288:
    uVar5 = 4;
  }
  else if (sVar2 < 0x1db) {
    if ((sVar2 == 0x99) || ((sVar2 < 0x99 && (sVar2 == 0x5d)))) goto LAB_8006f288;
  }
  else if (sVar2 == 0x223) goto LAB_8006f288;
LAB_8006f28c:
  if (puVar4 != (undefined2 *)0x0) {
    pfVar8 = (float *)(param_6 + (in_LR & 0xff) * 0xc);
    if (FLOAT_803dfaa0 < *(float *)(param_7 + 0x1b4)) {
      (**(code **)(*DAT_803dd718 + 8))(uVar3,uVar9,param_6,param_7);
      uVar5 = 5;
    }
    uVar6 = FUN_8002bac4();
    if (uVar3 == uVar6) {
      if (*(short *)(*(int *)(uVar3 + 0xb8) + 0x81a) == 1) {
        FUN_8000bb38(0,0x3c2);
      }
      FUN_8000bb38(0,puVar4[uVar5]);
    }
    else {
      FUN_8000bb00((double)*pfVar8,(double)pfVar8[1],(double)pfVar8[2],uVar3,puVar4[uVar5]);
    }
  }
  if (bVar10 != 5) {
    bVar10 = 0;
    dVar11 = (double)(float)((double)FLOAT_803dfaa4 * param_2);
    for (; uVar9 != 0; uVar9 = (int)uVar9 >> 1) {
      pfVar8 = (float *)(param_6 + (uint)bVar10 * 0xc);
      local_58 = *pfVar8;
      local_54 = pfVar8[1];
      local_50 = pfVar8[2];
      if ((uVar9 & 1) != 0) {
        if ((*(short *)(uVar3 + 0x44) == 1) || (*(short *)(uVar3 + 0x46) == 0x416)) {
          FUN_8006facc(uVar3,&local_58,bVar10 & 1,uVar5);
        }
        local_40 = *pfVar8;
        local_3c = pfVar8[1];
        local_38 = pfVar8[2];
        local_44 = (float)dVar11;
        local_4c = (undefined2)uVar5;
        local_48 = 0;
        local_4a = 0;
        local_58 = FLOAT_803dfaa8 * *(float *)(uVar3 + 0x24);
        local_54 = FLOAT_803dfaa8 * *(float *)(uVar3 + 0x28);
        local_50 = FLOAT_803dfaa8 * *(float *)(uVar3 + 0x2c);
        if ((uVar5 == 6) || (uVar5 == 3)) {
          uVar6 = FUN_80022264(2,4);
          for (uVar6 = uVar6 & 0xff; (uVar6 & 0xff) != 0; uVar6 = uVar6 - 1) {
            (**(code **)(*DAT_803dd708 + 8))(uVar3,0x7e6,&local_4c,0x200001,0xffffffff,&local_58);
          }
        }
        else if (uVar5 == 2) {
          uVar6 = FUN_80022264(4,8);
          for (uVar6 = uVar6 & 0xff; (uVar6 & 0xff) != 0; uVar6 = uVar6 - 1) {
            (**(code **)(*DAT_803dd708 + 8))(uVar3,0x7e6,&local_4c,0x200001,0xffffffff,&local_58);
          }
        }
      }
      bVar10 = bVar10 + 1;
    }
  }
LAB_8006f4e4:
  FUN_80286884();
  return;
}

