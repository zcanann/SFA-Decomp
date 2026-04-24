// Function: FUN_802aef34
// Entry: 802aef34
// Size: 1244 bytes

/* WARNING: Removing unreachable block (ram,0x802af3f0) */

void FUN_802aef34(void)

{
  byte bVar1;
  short sVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860dc();
  iVar5 = (int)((ulonglong)uVar11 >> 0x20);
  iVar8 = (int)uVar11;
  iVar6 = FUN_8002b588();
  iVar6 = *(int *)(iVar6 + 0x30);
  if (*(short *)(iVar8 + 0x806) != 3) {
    if (*(char *)(iVar8 + 0x8b4) == '\x01') {
      FUN_8016e6d4(DAT_803de44c,0,*(byte *)(iVar8 + 0x3f4) >> 3 & 1,0);
      *(undefined *)(iVar8 + 0x8b3) = 0;
      if ((*(short *)(iVar8 + 0x806) != 0) && (*(short *)(iVar8 + 0x806) != 0xf)) {
        *(undefined2 *)(iVar8 + 0x806) = 3;
      }
    }
    else if (*(char *)(iVar8 + 0x8b4) == '\x04') {
      FUN_8016e6d4(DAT_803de44c,1,*(byte *)(iVar8 + 0x3f4) >> 3 & 1,0);
      *(undefined *)(iVar8 + 0x8b3) = 1;
      if ((*(short *)(iVar8 + 0x806) != 0) && (*(short *)(iVar8 + 0x806) != 0xf)) {
        *(undefined2 *)(iVar8 + 0x806) = 3;
      }
    }
  }
  dVar10 = -(double)FLOAT_803e7f20;
  bVar3 = false;
  do {
    bVar4 = false;
    sVar2 = *(short *)(iVar8 + 0x806);
    if (sVar2 == 3) {
      if ((int)*(short *)(iVar5 + 0xa2) != (int)*(short *)(iVar5 + 0xa0)) {
        FUN_8002f23c((double)*(float *)(iVar5 + 0x98),iVar5,(int)*(short *)(iVar5 + 0xa0),0);
      }
      if (*(short *)(iVar6 + 0x58) == 0) {
        *(undefined2 *)(iVar5 + 0xa2) = 0xffff;
        *(undefined2 *)(iVar8 + 0x806) = 0;
      }
      else {
        FUN_8002edc0((double)FLOAT_803e7ea4,(double)FLOAT_803db414,iVar5,0);
        FUN_8002f20c((double)*(float *)(iVar5 + 0x98),iVar5);
      }
    }
    else if (sVar2 < 3) {
      if (sVar2 == 1) {
        if (bVar3) {
          FUN_8002f23c((double)*(float *)(iVar5 + 0x98),iVar5,(int)*(short *)(iVar5 + 0xa0),0);
          if ((*(int *)(iVar8 + 0x4b8) == 0) ||
             ((sVar2 = *(short *)(*(int *)(iVar8 + 0x4b8) + 0x44), sVar2 != 0x1c && (sVar2 != 0x2a))
             )) {
            FUN_8002f23c((double)FLOAT_803e7f68,iVar5,0x8d,0);
          }
          else {
            FUN_8002f23c((double)FLOAT_803e7f68,iVar5,0x82,0);
          }
          FUN_8002f574(iVar5,0xc);
        }
        if (*(float *)(iVar5 + 0x9c) <= FLOAT_803e8130) {
          *(undefined *)(iVar8 + 0x8b3) = 0;
        }
        if (FLOAT_803e7eb4 < *(float *)(iVar5 + 0x9c)) {
          FUN_8002edc0(dVar10,(double)FLOAT_803e7ee0,iVar5,0);
        }
        else {
          *(undefined2 *)(iVar8 + 0x806) = 3;
          bVar4 = true;
        }
      }
      else {
        if (sVar2 < 1) goto LAB_802af370;
        if (bVar3) {
          FUN_8002f23c((double)*(float *)(iVar5 + 0x98),iVar5,(int)*(short *)(iVar5 + 0xa0),0);
          if ((*(int *)(iVar8 + 0x4b8) == 0) ||
             ((sVar2 = *(short *)(*(int *)(iVar8 + 0x4b8) + 0x44), sVar2 != 0x1c && (sVar2 != 0x2a))
             )) {
            FUN_8002f23c((double)FLOAT_803e7ea4,iVar5,0x8d,0);
          }
          else {
            FUN_8002f23c((double)FLOAT_803e7ea4,iVar5,0x82,0);
          }
          FUN_8002f574(iVar5,0xc);
        }
        if (FLOAT_803e8130 <= *(float *)(iVar5 + 0x9c)) {
          *(undefined *)(iVar8 + 0x8b3) = 1;
        }
        if (*(float *)(iVar5 + 0x9c) < FLOAT_803e7f1c) {
          FUN_8002edc0((double)FLOAT_803e7f20,(double)FLOAT_803e7ee0,iVar5,0);
        }
        else {
          FUN_8016e6d4(DAT_803de44c,1,0,0);
          *(undefined2 *)(iVar8 + 0x806) = 3;
          bVar4 = true;
        }
      }
    }
    else if (sVar2 == 0xf) {
      if (bVar3) {
        FUN_8002f23c((double)*(float *)(iVar5 + 0x98),iVar5,(int)*(short *)(iVar5 + 0xa0),0);
        FUN_8002f23c((double)FLOAT_803e7ea4,iVar5,
                     (int)*(short *)(&DAT_8033366c + (uint)*(byte *)(iVar8 + 0x8a2) * 2),0);
        FUN_8002f574(iVar5,0xc);
      }
      if (*(float *)(iVar5 + 0x9c) < FLOAT_803e7ee0) {
        bVar1 = *(byte *)(iVar8 + 0x3f0);
        if (((((bVar1 >> 4 & 1) == 0) && ((bVar1 >> 2 & 1) == 0)) && ((bVar1 >> 3 & 1) == 0)) &&
           (((bVar1 >> 5 & 1) == 0 && (iVar7 = (int)*(short *)(iVar8 + 0x274), iVar7 != 0x36)))) {
          if ((((iVar7 - 1U & 0xffff) < 2) || ((iVar7 - 0x24U & 0xffff) < 2)) ||
             (*(int *)(iVar8 + 0x2d0) != 0)) {
            bVar3 = true;
          }
          else {
            bVar3 = false;
          }
        }
        else {
          bVar3 = false;
        }
        if (bVar3) {
          FUN_8002edc0((double)*(float *)(&DAT_8033369c + (uint)*(byte *)(iVar8 + 0x8a2) * 4),
                       (double)FLOAT_803db414,iVar5,0);
          goto LAB_802af3e4;
        }
      }
      *(undefined2 *)(iVar8 + 0x806) = 3;
      *(undefined *)(iVar8 + 0x8a2) = 0xff;
      bVar4 = true;
    }
    else {
LAB_802af370:
      if (*(char *)(iVar8 + 0x8b3) == '\0') {
        if (*(char *)(iVar8 + 0x8b4) == '\x02') {
          *(undefined2 *)(iVar8 + 0x806) = 2;
          bVar4 = true;
        }
      }
      else if (*(char *)(iVar8 + 0x8b4) == '\0') {
        FUN_8016e6d4(DAT_803de44c,0,0,0);
        *(undefined2 *)(iVar8 + 0x806) = 1;
        bVar4 = true;
      }
      if ((*(char *)(iVar8 + 0x8a2) == '\x05') || (*(char *)(iVar8 + 0x8a2) == '\a')) {
        *(undefined2 *)(iVar8 + 0x806) = 0xf;
        bVar4 = true;
      }
    }
LAB_802af3e4:
    bVar3 = bVar4;
    if (!bVar4) {
      __psq_l0(auStack8,uVar9);
      __psq_l1(auStack8,uVar9);
      FUN_80286128();
      return;
    }
  } while( true );
}

