// Function: FUN_802b5830
// Entry: 802b5830
// Size: 1904 bytes

/* WARNING: Removing unreachable block (ram,0x802b5f80) */
/* WARNING: Removing unreachable block (ram,0x802b5f78) */
/* WARNING: Removing unreachable block (ram,0x802b5f70) */
/* WARNING: Removing unreachable block (ram,0x802b5850) */
/* WARNING: Removing unreachable block (ram,0x802b5848) */
/* WARNING: Removing unreachable block (ram,0x802b5840) */

void FUN_802b5830(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short *psVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  char cVar6;
  byte bVar7;
  int iVar8;
  int iVar9;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
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
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar10 = FUN_80286838();
  psVar1 = (short *)((ulonglong)uVar10 >> 0x20);
  iVar9 = *(int *)(psVar1 + 0x5c);
  if ((param_6 == -1) || ((*(uint *)(iVar9 + 0x360) & 0x4001) == 0)) {
    if ((*(int *)(iVar9 + 0x7f0) != 0) &&
       (((psVar1[0x58] & 0x1000U) != 0 ||
        (iVar2 = FUN_80080100((int *)&DAT_803dd32c,2,(int)*(short *)(iVar9 + 0x274)), iVar2 != -1)))
       ) {
      FUN_802aa46c(psVar1,iVar9,*(undefined2 **)(iVar9 + 0x7f0),(int)uVar10,param_3,param_4,param_5,
                   1);
    }
    if (*(char *)(iVar9 + 0x8ca) == '\x01') {
      FUN_802ab4a4((int)psVar1);
    }
    (**(code **)(*DAT_803dd704 + 8))(psVar1);
    if ((*(int *)(iVar9 + 0x7f0) != 0) &&
       (((psVar1[0x58] & 0x1000U) != 0 ||
        (iVar2 = FUN_80080100((int *)&DAT_803dd32c,2,(int)*(short *)(iVar9 + 0x274)), iVar2 != -1)))
       ) {
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
    FUN_8003b9ec((int)psVar1);
    *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - *(float *)(iVar9 + 0x7c8);
    if ((*(uint *)(iVar9 + 0x360) & 0x8000000) != 0) {
      *(float *)(psVar1 + 6) = (float)in_f31;
      *(float *)(psVar1 + 8) = (float)in_f30;
      *(float *)(psVar1 + 10) = (float)in_f29;
    }
    if (param_6 != '\0') {
      FUN_802ab6e0((int)psVar1,iVar9,(int)uVar10,param_3,param_4);
    }
    FUN_80038378(psVar1,6,2,(float *)(iVar9 + 0x3c4));
    FUN_80038524(psVar1,0xb,(float *)(iVar9 + 0x768),(undefined4 *)(iVar9 + 0x76c),
                 (float *)(iVar9 + 0x770),0);
    uVar3 = FUN_800e8024('\x01',0);
    if (uVar3 == 0) {
      if (DAT_803df0a8 != 0) {
        *(uint *)(DAT_803df0a8 + 0x3c) = *(uint *)(DAT_803df0a8 + 0x3c) & 0xffefffff;
        DAT_803df0a8 = 0;
      }
    }
    else if (DAT_803df0a8 == 0) {
      piVar4 = (int *)FUN_8002b660((int)psVar1);
      iVar8 = *piVar4;
      for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar8 + 0xf8); iVar2 = iVar2 + 1) {
        iVar5 = FUN_800284e8(iVar8,iVar2);
        if (*(char *)(iVar5 + 0x41) == '\x02') {
          FUN_8004c3cc(iVar5,1);
          DAT_803df0a8 = iVar5;
          *(uint *)(iVar5 + 0x3c) = *(uint *)(iVar5 + 0x3c) | 0x100000;
          break;
        }
      }
    }
    iVar2 = *(int *)(psVar1 + 0x5c);
    if ((*(int *)(iVar2 + 0x7f8) != 0) && (*(int *)(*(int *)(iVar2 + 0x7f8) + 0xf8) == 1)) {
      FUN_80038524(psVar1,8,&local_98,&local_94,&local_90,0);
      FUN_80038524(psVar1,9,&local_8c,&local_88,local_84,0);
      local_98 = FLOAT_803e8b30 * (local_98 + local_8c);
      local_94 = FLOAT_803e8b30 * (local_94 + local_88);
      local_90 = FLOAT_803e8b30 * (local_90 + local_84[0]);
      if (*(short *)(*(int *)(iVar2 + 0x7f8) + 0x46) == 0x112) {
        local_94 = local_94 + FLOAT_803e8b6c;
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
    if ((FLOAT_803e8b3c < *(float *)(iVar9 + 0x79c)) || ((*(ushort *)(iVar9 + 0x8d8) & 2) != 0)) {
      local_84[1] = (float)DAT_803e8b00;
      local_84[2] = (float)DAT_803e8b04;
      FUN_8009a010((double)FLOAT_803e8b34,(double)FLOAT_803e8b78,psVar1,
                   (uint)local_84[*(byte *)(iVar9 + 0x7a8) >> 5] & 0xff,(int *)0x0);
    }
    if ((*(ushort *)(iVar9 + 0x8d8) & 1) != 0) {
      FUN_8009a010((double)FLOAT_803e8b34,(double)FLOAT_803e8b78,psVar1,8,(int *)0x0);
    }
    if (*(float *)(iVar9 + 0x838) <= FLOAT_803e8b3c) {
      if (((&DAT_80333e8c)[*(byte *)(iVar9 + 0x86c)] == '\x06') ||
         ((&DAT_80333e8c)[*(byte *)(iVar9 + 0x86c)] == '\x03')) {
        if ((*(ushort *)(iVar9 + 0x8d8) & 8) != 0) {
          local_84[3] = FLOAT_803e8c04 * *(float *)(psVar1 + 0x12);
          local_74 = FLOAT_803e8c04 * *(float *)(psVar1 + 0x14);
          local_70 = FLOAT_803e8c04 * *(float *)(psVar1 + 0x16);
          local_60 = FLOAT_803e8cb0 * *(float *)(psVar1 + 0x12) + *(float *)(iVar9 + 0x3c4);
          local_5c = FLOAT_803e8cb0 * *(float *)(psVar1 + 0x14) + *(float *)(iVar9 + 0x3c8);
          local_58 = FLOAT_803e8cb0 * *(float *)(psVar1 + 0x16) + *(float *)(iVar9 + 0x3cc);
          local_64 = FLOAT_803e8bb0;
          local_6c[0] = (ushort)(byte)(&DAT_80333e8c)[*(byte *)(iVar9 + 0x86c)];
          for (cVar6 = '\x05'; cVar6 != '\0'; cVar6 = cVar6 + -1) {
            (**(code **)(*DAT_803dd708 + 8))(psVar1,0x7e6,local_6c,0x200001,0xffffffff,local_84 + 3)
            ;
          }
          local_60 = FLOAT_803e8cb0 * *(float *)(psVar1 + 0x12) + *(float *)(iVar9 + 0x3d0);
          local_5c = FLOAT_803e8cb0 * *(float *)(psVar1 + 0x14) + *(float *)(iVar9 + 0x3d4);
          local_58 = FLOAT_803e8cb0 * *(float *)(psVar1 + 0x16) + *(float *)(iVar9 + 0x3d8);
          local_64 = FLOAT_803e8bb0;
          local_6c[0] = (ushort)(byte)(&DAT_80333e8c)[*(byte *)(iVar9 + 0x86c)];
          for (cVar6 = '\x05'; cVar6 != '\0'; cVar6 = cVar6 + -1) {
            (**(code **)(*DAT_803dd708 + 8))(psVar1,0x7e6,local_6c,0x200001,0xffffffff,local_84 + 3)
            ;
          }
          *(ushort *)(iVar9 + 0x8d8) = *(ushort *)(iVar9 + 0x8d8) & 0xfff7;
        }
        if ((*(ushort *)(iVar9 + 0x8d8) & 4) != 0) {
          local_84[3] = FLOAT_803e8bdc * *(float *)(psVar1 + 0x12);
          local_74 = FLOAT_803e8bdc * *(float *)(psVar1 + 0x14);
          local_70 = FLOAT_803e8bdc * *(float *)(psVar1 + 0x16);
          local_60 = *(float *)(psVar1 + 0xc);
          local_5c = FLOAT_803e8ba8 + *(float *)(psVar1 + 0xe);
          local_58 = *(float *)(psVar1 + 0x10);
          local_64 = FLOAT_803e8b78;
          local_6c[0] = (ushort)(byte)(&DAT_80333e8c)[*(byte *)(iVar9 + 0x86c)];
          for (bVar7 = 0; bVar7 < 10; bVar7 = bVar7 + 1) {
            (**(code **)(*DAT_803dd708 + 8))(psVar1,0x7e6,local_6c,0x200001,0xffffffff,local_84 + 3)
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
  FUN_80286884();
  return;
}

