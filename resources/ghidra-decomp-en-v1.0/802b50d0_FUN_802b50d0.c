// Function: FUN_802b50d0
// Entry: 802b50d0
// Size: 1904 bytes

/* WARNING: Removing unreachable block (ram,0x802b5818) */
/* WARNING: Removing unreachable block (ram,0x802b5810) */
/* WARNING: Removing unreachable block (ram,0x802b5820) */

void FUN_802b50d0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short *psVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  char cVar6;
  byte bVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double in_f29;
  double in_f30;
  double in_f31;
  undefined8 uVar11;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84 [4];
  float local_74;
  float local_70;
  ushort local_6c [4];
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  uVar11 = FUN_802860d4();
  psVar1 = (short *)((ulonglong)uVar11 >> 0x20);
  uVar5 = (undefined4)uVar11;
  iVar9 = *(int *)(psVar1 + 0x5c);
  if ((param_6 == -1) || ((*(uint *)(iVar9 + 0x360) & 0x4001) == 0)) {
    if ((*(int *)(iVar9 + 0x7f0) != 0) &&
       (((psVar1[0x58] & 0x1000U) != 0 ||
        (iVar2 = FUN_8007fe74(&DAT_803dc6c4,2,(int)*(short *)(iVar9 + 0x274)), iVar2 != -1)))) {
      FUN_802a9d0c(psVar1,iVar9,*(undefined4 *)(iVar9 + 0x7f0),uVar5,param_3,param_4,param_5,1);
    }
    if (*(char *)(iVar9 + 0x8ca) == '\x01') {
      FUN_802aad44(psVar1);
    }
    (**(code **)(*DAT_803dca84 + 8))(psVar1);
    if ((*(int *)(iVar9 + 0x7f0) != 0) &&
       (((psVar1[0x58] & 0x1000U) != 0 ||
        (iVar2 = FUN_8007fe74(&DAT_803dc6c4,2,(int)*(short *)(iVar9 + 0x274)), iVar2 != -1)))) {
      (**(code **)(**(int **)(*(int *)(iVar9 + 0x7f0) + 0x68) + 0x50))
                ((double)*(float *)(*(int *)(psVar1 + 0x28) + 4));
    }
    if ((*(uint *)(iVar9 + 0x360) & 0x8000000) != 0) {
      in_f31 = (double)*(float *)(psVar1 + 6);
      in_f30 = (double)*(float *)(psVar1 + 8);
      in_f29 = (double)*(float *)(psVar1 + 10);
      *(undefined4 *)(psVar1 + 6) = *(undefined4 *)(*(int *)(psVar1 + 0x32) + 0x20);
      *(undefined4 *)(psVar1 + 8) = *(undefined4 *)(*(int *)(psVar1 + 0x32) + 0x24);
      *(undefined4 *)(psVar1 + 10) = *(undefined4 *)(*(int *)(psVar1 + 0x32) + 0x28);
    }
    *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) + *(float *)(iVar9 + 0x7c8);
    FUN_8003b8f4((double)FLOAT_803e7ee0,psVar1,uVar5,param_3,param_4,param_5);
    *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - *(float *)(iVar9 + 0x7c8);
    if ((*(uint *)(iVar9 + 0x360) & 0x8000000) != 0) {
      *(float *)(psVar1 + 6) = (float)in_f31;
      *(float *)(psVar1 + 8) = (float)in_f30;
      *(float *)(psVar1 + 10) = (float)in_f29;
    }
    if (param_6 != '\0') {
      FUN_802aaf80(psVar1,iVar9,uVar5,param_3,param_4);
    }
    FUN_80038280(psVar1,6,2,iVar9 + 0x3c4);
    FUN_8003842c(psVar1,0xb,iVar9 + 0x768,iVar9 + 0x76c,iVar9 + 0x770,0);
    iVar2 = FUN_800e7da0(1,0);
    if (iVar2 == 0) {
      if (DAT_803de428 != 0) {
        *(uint *)(DAT_803de428 + 0x3c) = *(uint *)(DAT_803de428 + 0x3c) & 0xffefffff;
        DAT_803de428 = 0;
      }
    }
    else if (DAT_803de428 == 0) {
      piVar3 = (int *)FUN_8002b588(psVar1);
      iVar8 = *piVar3;
      for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar8 + 0xf8); iVar2 = iVar2 + 1) {
        iVar4 = FUN_80028424(iVar8,iVar2);
        if (*(char *)(iVar4 + 0x41) == '\x02') {
          FUN_8004c250(iVar4,1);
          DAT_803de428 = iVar4;
          *(uint *)(iVar4 + 0x3c) = *(uint *)(iVar4 + 0x3c) | 0x100000;
          break;
        }
      }
    }
    iVar2 = *(int *)(psVar1 + 0x5c);
    if ((*(int *)(iVar2 + 0x7f8) != 0) && (*(int *)(*(int *)(iVar2 + 0x7f8) + 0xf8) == 1)) {
      FUN_8003842c(psVar1,8,&local_98,&local_94,&local_90,0);
      FUN_8003842c(psVar1,9,&local_8c,&local_88,local_84,0);
      local_98 = FLOAT_803e7e98 * (local_98 + local_8c);
      local_94 = FLOAT_803e7e98 * (local_94 + local_88);
      local_90 = FLOAT_803e7e98 * (local_90 + local_84[0]);
      if (*(short *)(*(int *)(iVar2 + 0x7f8) + 0x46) == 0x112) {
        local_94 = local_94 + FLOAT_803e7ed4;
      }
      *(float *)(*(int *)(iVar2 + 0x7f8) + 0x18) = local_98;
      *(float *)(*(int *)(iVar2 + 0x7f8) + 0xc) = local_98;
      *(float *)(*(int *)(iVar2 + 0x7f8) + 0x1c) = local_94;
      *(float *)(*(int *)(iVar2 + 0x7f8) + 0x10) = local_94;
      *(float *)(*(int *)(iVar2 + 0x7f8) + 0x20) = local_90;
      *(float *)(*(int *)(iVar2 + 0x7f8) + 0x14) = local_90;
      if (*(short **)(psVar1 + 0x18) == (short *)0x0) {
        **(undefined2 **)(iVar2 + 0x7f8) = *(undefined2 *)(iVar2 + 0x478);
      }
      else {
        **(short **)(iVar2 + 0x7f8) = **(short **)(psVar1 + 0x18) + *psVar1;
      }
      (**(code **)(**(int **)(*(int *)(iVar2 + 0x7f8) + 0x68) + 0x10))
                (*(int *)(iVar2 + 0x7f8),0,0,0,0,0xffffffff);
    }
    if ((FLOAT_803e7ea4 < *(float *)(iVar9 + 0x79c)) || ((*(ushort *)(iVar9 + 0x8d8) & 2) != 0)) {
      local_84[1] = (float)DAT_803e7e68;
      local_84[2] = (float)DAT_803e7e6c;
      FUN_80099d84((double)FLOAT_803e7e9c,(double)FLOAT_803e7ee0,psVar1,
                   (uint)local_84[*(byte *)(iVar9 + 0x7a8) >> 5] & 0xff,0);
    }
    if ((*(ushort *)(iVar9 + 0x8d8) & 1) != 0) {
      FUN_80099d84((double)FLOAT_803e7e9c,(double)FLOAT_803e7ee0,psVar1,8,0);
    }
    if (*(float *)(iVar9 + 0x838) <= FLOAT_803e7ea4) {
      if (((&DAT_8033322c)[*(byte *)(iVar9 + 0x86c)] == '\x06') ||
         ((&DAT_8033322c)[*(byte *)(iVar9 + 0x86c)] == '\x03')) {
        if ((*(ushort *)(iVar9 + 0x8d8) & 8) != 0) {
          local_84[3] = FLOAT_803e7f6c * *(float *)(psVar1 + 0x12);
          local_74 = FLOAT_803e7f6c * *(float *)(psVar1 + 0x14);
          local_70 = FLOAT_803e7f6c * *(float *)(psVar1 + 0x16);
          local_60 = FLOAT_803e8018 * *(float *)(psVar1 + 0x12) + *(float *)(iVar9 + 0x3c4);
          local_5c = FLOAT_803e8018 * *(float *)(psVar1 + 0x14) + *(float *)(iVar9 + 0x3c8);
          local_58 = FLOAT_803e8018 * *(float *)(psVar1 + 0x16) + *(float *)(iVar9 + 0x3cc);
          local_64 = FLOAT_803e7f18;
          local_6c[0] = (ushort)(byte)(&DAT_8033322c)[*(byte *)(iVar9 + 0x86c)];
          for (cVar6 = '\x05'; cVar6 != '\0'; cVar6 = cVar6 + -1) {
            (**(code **)(*DAT_803dca88 + 8))(psVar1,0x7e6,local_6c,0x200001,0xffffffff,local_84 + 3)
            ;
          }
          local_60 = FLOAT_803e8018 * *(float *)(psVar1 + 0x12) + *(float *)(iVar9 + 0x3d0);
          local_5c = FLOAT_803e8018 * *(float *)(psVar1 + 0x14) + *(float *)(iVar9 + 0x3d4);
          local_58 = FLOAT_803e8018 * *(float *)(psVar1 + 0x16) + *(float *)(iVar9 + 0x3d8);
          local_64 = FLOAT_803e7f18;
          local_6c[0] = (ushort)(byte)(&DAT_8033322c)[*(byte *)(iVar9 + 0x86c)];
          for (cVar6 = '\x05'; cVar6 != '\0'; cVar6 = cVar6 + -1) {
            (**(code **)(*DAT_803dca88 + 8))(psVar1,0x7e6,local_6c,0x200001,0xffffffff,local_84 + 3)
            ;
          }
          *(ushort *)(iVar9 + 0x8d8) = *(ushort *)(iVar9 + 0x8d8) & 0xfff7;
        }
        if ((*(ushort *)(iVar9 + 0x8d8) & 4) != 0) {
          local_84[3] = FLOAT_803e7f44 * *(float *)(psVar1 + 0x12);
          local_74 = FLOAT_803e7f44 * *(float *)(psVar1 + 0x14);
          local_70 = FLOAT_803e7f44 * *(float *)(psVar1 + 0x16);
          local_60 = *(float *)(psVar1 + 0xc);
          local_5c = FLOAT_803e7f10 + *(float *)(psVar1 + 0xe);
          local_58 = *(float *)(psVar1 + 0x10);
          local_64 = FLOAT_803e7ee0;
          local_6c[0] = (ushort)(byte)(&DAT_8033322c)[*(byte *)(iVar9 + 0x86c)];
          for (bVar7 = 0; bVar7 < 10; bVar7 = bVar7 + 1) {
            (**(code **)(*DAT_803dca88 + 8))(psVar1,0x7e6,local_6c,0x200001,0xffffffff,local_84 + 3)
            ;
          }
          *(ushort *)(iVar9 + 0x8d8) = *(ushort *)(iVar9 + 0x8d8) & 0xfffb;
        }
      }
    }
    else if ((*(ushort *)(iVar9 + 0x8d8) & 4) != 0) {
      *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x20000;
      *(ushort *)(iVar9 + 0x8d8) = *(ushort *)(iVar9 + 0x8d8) & 0xfffb;
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  FUN_80286120();
  return;
}

