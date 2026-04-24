// Function: FUN_80172824
// Entry: 80172824
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x80172aa4) */

void FUN_80172824(void)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  undefined8 uVar10;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar10 >> 0x20);
  pfVar6 = (float *)uVar10;
  iVar7 = *(int *)(iVar3 + 0x4c);
  iVar4 = FUN_8002b9ec();
  if ((iVar4 == 0) || ((*(byte *)((int)pfVar6 + 0x37) & 1) != 0)) goto LAB_80172aa4;
  iVar5 = FUN_802972a8();
  if (iVar5 == 0) {
    iVar5 = iVar4;
  }
  dVar9 = (double)FUN_80021690(iVar3 + 0x18,iVar5 + 0x18);
  fVar2 = *(float *)(iVar5 + 0x1c) - *(float *)(iVar3 + 0x1c);
  if (fVar2 < FLOAT_803e345c) {
    fVar2 = -fVar2;
  }
  if (((fVar2 < FLOAT_803e3490) && (dVar9 < (double)pfVar6[1])) &&
     (iVar5 = FUN_8029622c(iVar4), iVar5 != 0)) {
    *(undefined2 *)(pfVar6 + 0x12) = 0xffff;
    sVar1 = *(short *)(iVar3 + 0x46);
    if (sVar1 == 0x319) {
      FUN_80171e5c(iVar3);
      *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
    }
    else if (sVar1 < 0x319) {
      if (sVar1 == 0x49) {
LAB_80172998:
        iVar7 = FUN_8001ffb4(0x90f);
        if (iVar7 == 0) {
          FUN_800378c4(iVar4,0x7000a,iVar3,pfVar6 + 0x12);
          FUN_800200e8(0x90f,1);
        }
        else {
          FUN_80171e5c(iVar3);
        }
        *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
      }
      else {
        if (sVar1 < 0x49) {
          if (sVar1 == 0xb) {
            iVar7 = FUN_8001ffb4(0x90e);
            if (iVar7 == 0) {
              FUN_800378c4(iVar4,0x7000a,iVar3,pfVar6 + 0x12);
              FUN_800200e8(0x90e,1);
            }
            else {
              FUN_80171e5c(iVar3);
            }
            *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
            goto LAB_80172aa0;
          }
        }
        else if (sVar1 == 0x2da) goto LAB_80172998;
LAB_80172a40:
        iVar5 = FUN_80038024(iVar3);
        if (iVar5 != 0) {
          FUN_800200e8(0xa7b,1);
          *(undefined2 *)(pfVar6 + 0x12) = *(undefined2 *)(iVar7 + 0x1e);
          FUN_800378c4(iVar4,0x7000a,iVar3,pfVar6 + 0x12);
          *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
          if (*(int *)(iVar3 + 100) != 0) {
            *(undefined4 *)(*(int *)(iVar3 + 100) + 0x30) = 0x1000;
          }
        }
      }
    }
    else {
      if (sVar1 != 0x6a6) {
        if ((0x6a5 < sVar1) || (sVar1 != 0x3cd)) goto LAB_80172a40;
        goto LAB_80172998;
      }
      iVar7 = FUN_8001ffb4(0x9a8);
      if (iVar7 == 0) {
        FUN_800378c4(iVar4,0x7000a,iVar3,pfVar6 + 0x12);
        FUN_800200e8(0x9a8,1);
      }
      else {
        FUN_80171e5c(iVar3);
      }
      *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
    }
  }
LAB_80172aa0:
  *pfVar6 = (float)dVar9;
LAB_80172aa4:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286128();
  return;
}

