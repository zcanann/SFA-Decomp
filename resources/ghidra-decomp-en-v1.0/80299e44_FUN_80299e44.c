// Function: FUN_80299e44
// Entry: 80299e44
// Size: 1500 bytes

/* WARNING: Removing unreachable block (ram,0x8029a400) */

void FUN_80299e44(void)

{
  char cVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 extraout_f1;
  undefined8 in_f31;
  undefined8 uVar10;
  undefined auStack72 [6];
  undefined2 local_42;
  float local_40;
  undefined auStack60 [4];
  undefined auStack56 [4];
  undefined auStack52 [44];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar8 = *(int *)(iVar3 + 0xb8);
  uVar10 = extraout_f1;
  if (DAT_803de42c != '\0') {
    FUN_8000da58(iVar3,0x382);
    fVar2 = *(float *)(iVar8 + 0x854) - FLOAT_803db414;
    *(float *)(iVar8 + 0x854) = fVar2;
    if (fVar2 <= FLOAT_803e7ea4) {
      iVar6 = *(int *)(*(int *)(iVar3 + 0xb8) + 0x35c);
      iVar4 = *(short *)(iVar6 + 4) + -1;
      if (iVar4 < 0) {
        iVar4 = 0;
      }
      else if (*(short *)(iVar6 + 6) < iVar4) {
        iVar4 = (int)*(short *)(iVar6 + 6);
      }
      *(short *)(iVar6 + 4) = (short)iVar4;
      *(float *)(iVar8 + 0x854) = FLOAT_803e7f58;
    }
    FUN_8003842c(DAT_803de44c,5,auStack60,auStack56,auStack52,0);
    local_40 = FLOAT_803e7f9c;
    local_42 = 0;
    (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack72,0x200001,0xffffffff,0);
    local_42 = 1;
    (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack72,0x200001,0xffffffff,0);
    if ((((*(ushort *)(iVar8 + 0x6e0) & DAT_803de4b4) == 0) ||
        (*(short *)(*(int *)(*(int *)(iVar3 + 0xb8) + 0x35c) + 4) == 0)) ||
       (iVar4 = FUN_80080204(), iVar4 != 0)) {
      DAT_803de42c = '\0';
      iVar4 = 0;
      piVar7 = &DAT_80332ed4;
      do {
        if (*piVar7 != 0) {
          FUN_8002cbc4();
          *piVar7 = 0;
        }
        piVar7 = piVar7 + 1;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 7);
      if (DAT_803de454 != 0) {
        FUN_80013e2c();
        DAT_803de454 = 0;
      }
    }
  }
  if ((*(short *)(iVar8 + 0x80e) != -1) || ((*(uint *)(iVar5 + 0x31c) & 0x800) != 0)) {
    iVar4 = FUN_8029abd8(uVar10,iVar3,iVar5);
    if (iVar4 != 0) goto LAB_8029a400;
    *(undefined2 *)(iVar8 + 0x80e) = 0xffff;
  }
  if ((*(uint *)(iVar5 + 0x31c) & 0x400) == 0) {
    if ((*(uint *)(iVar5 + 0x31c) & 0x100) == 0) {
      iVar4 = 0;
    }
    else {
      cVar1 = *(char *)(iVar5 + 0x34b);
      if ((cVar1 != '\x02') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e7eac)) {
        if ((cVar1 != '\x03') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e7eac)) {
          if ((cVar1 != '\x01') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e7eac)) {
            if ((cVar1 != '\x04') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e7eac)) {
              *(undefined *)(iVar8 + 0x8a9) = 0;
              FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                           (int)*(short *)(&DAT_803336bc +
                                          *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                     (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2)
                           ,0);
              *(code **)(iVar5 + 0x308) = FUN_8029bc08;
              iVar4 = 0x27;
            }
            else {
              *(undefined *)(iVar8 + 0x8a9) = 2;
              FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                           (int)*(short *)(&DAT_803336bc +
                                          *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                     (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2)
                           ,0);
              *(code **)(iVar5 + 0x308) = FUN_8029bc08;
              iVar4 = 0x27;
            }
          }
          else {
            *(undefined *)(iVar8 + 0x8a9) = 3;
            FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                         (int)*(short *)(&DAT_803336bc +
                                        *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                   (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0
                        );
            *(code **)(iVar5 + 0x308) = FUN_8029bc08;
            iVar4 = 0x27;
          }
        }
        else {
          *(undefined *)(iVar8 + 0x8a9) = 4;
          FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                       (int)*(short *)(&DAT_803336bc +
                                      *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                 (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
          *(code **)(iVar5 + 0x308) = FUN_8029bc08;
          iVar4 = 0x27;
        }
      }
      else {
        *(undefined *)(iVar8 + 0x8a9) = 1;
        FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                     (int)*(short *)(&DAT_803336bc +
                                    *(short *)(*(int *)(iVar8 + 0x3dc) +
                                               (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
        *(code **)(iVar5 + 0x308) = FUN_8029bc08;
        iVar4 = 0x27;
      }
    }
  }
  else {
    cVar1 = *(char *)(iVar5 + 0x34b);
    if (cVar1 == '\x01') {
      *(undefined *)(iVar8 + 0x8a9) = 8;
      FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                   (int)*(short *)(&DAT_803336bc +
                                  *(short *)(*(int *)(iVar8 + 0x3dc) +
                                             (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
      *(code **)(iVar5 + 0x308) = FUN_8029bc08;
      iVar4 = 0x27;
    }
    else if (cVar1 == '\x03') {
      *(undefined *)(iVar8 + 0x8a9) = 9;
      FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                   (int)*(short *)(&DAT_803336bc +
                                  *(short *)(*(int *)(iVar8 + 0x3dc) +
                                             (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
      *(code **)(iVar5 + 0x308) = FUN_8029bc08;
      iVar4 = 0x27;
    }
    else if (cVar1 == '\x04') {
      *(undefined *)(iVar8 + 0x8a9) = 7;
      FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                   (int)*(short *)(&DAT_803336bc +
                                  *(short *)(*(int *)(iVar8 + 0x3dc) +
                                             (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
      *(code **)(iVar5 + 0x308) = FUN_8029bc08;
      iVar4 = 0x27;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar8 + 0x8a9) = 6;
      FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                   (int)*(short *)(&DAT_803336bc +
                                  *(short *)(*(int *)(iVar8 + 0x3dc) +
                                             (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
      *(code **)(iVar5 + 0x308) = FUN_8029bc08;
      iVar4 = 0x27;
    }
    else {
      *(undefined *)(iVar8 + 0x8a9) = 5;
      FUN_80030334((double)FLOAT_803e7ea4,iVar3,
                   (int)*(short *)(&DAT_803336bc +
                                  *(short *)(*(int *)(iVar8 + 0x3dc) +
                                             (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0);
      *(code **)(iVar5 + 0x308) = FUN_8029bc08;
      iVar4 = 0x27;
    }
  }
LAB_8029a400:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286124(iVar4);
  return;
}

