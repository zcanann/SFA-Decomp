// Function: FUN_80217630
// Entry: 80217630
// Size: 1800 bytes

/* WARNING: Removing unreachable block (ram,0x80217920) */
/* WARNING: Removing unreachable block (ram,0x80217d18) */

void FUN_80217630(void)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  undefined2 *puVar6;
  char cVar7;
  undefined2 *puVar8;
  int iVar9;
  int *piVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  undefined4 local_88;
  float local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined auStack116 [12];
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined auStack92 [12];
  int local_50;
  int local_4c;
  int local_48;
  double local_40;
  double local_38;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar1 = (short *)FUN_802860d8();
  piVar10 = *(int **)(psVar1 + 0x5c);
  iVar9 = *(int *)(psVar1 + 0x26);
  iVar2 = FUN_8002b9ec();
  *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - (float)piVar10[0x68];
  if ((*(byte *)(piVar10 + 0x6a) & 1) != 0) {
    local_84 = FLOAT_803e68f8;
    iVar3 = FUN_80036e58(0x4a,psVar1,&local_84);
    piVar10[0x65] = iVar3;
    if (iVar3 != 0) {
      *(undefined *)((int)piVar10 + 0x1a7) = 1;
      FUN_80037d2c(psVar1,piVar10[0x65],0);
      FUN_8021fad0(piVar10[0x65]);
    }
    *(byte *)(piVar10 + 0x6a) = *(byte *)(piVar10 + 0x6a) & 0xfe;
  }
  if (((*(byte *)(piVar10 + 0x6a) >> 3 & 1) == 0) &&
     (iVar3 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e)), iVar3 != 0)) {
    *(byte *)(piVar10 + 0x6a) = *(byte *)(piVar10 + 0x6a) & 0xf7 | 8;
    *(byte *)(piVar10 + 0x6a) = *(byte *)(piVar10 + 0x6a) & 0x7f | 0x80;
    psVar1[3] = psVar1[3] | 0x4000;
  }
  if (-1 < *(char *)(piVar10 + 0x6a)) {
    if (piVar10[100] != 0) {
      *(undefined4 *)(piVar10[100] + 0xc) = *(undefined4 *)(psVar1 + 6);
      *(float *)(piVar10[100] + 0x10) = *(float *)(psVar1 + 8) - FLOAT_803e68fc;
      *(undefined4 *)(piVar10[100] + 0x14) = *(undefined4 *)(psVar1 + 10);
    }
    if ((*(byte *)(piVar10 + 0x6a) >> 1 & 1) == 0) {
      FUN_80098270((double)FLOAT_803e6900,(double)FLOAT_803e6904,psVar1,1,
                   '\x05' - *(char *)((int)piVar10 + 0x1a6));
      if (piVar10[100] != 0) {
        FUN_80170380(piVar10[100],5);
      }
      piVar10[0x66] = piVar10[0x66] + 1;
      if (*(char *)((int)piVar10 + 0x1a6) == '\0') goto LAB_80217d18;
    }
    else {
      iVar3 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x20));
      if (iVar3 != 0) {
        *(byte *)(piVar10 + 0x6a) = *(byte *)(piVar10 + 0x6a) & 0xfd;
        if (piVar10[100] != 0) {
          FUN_80170380(piVar10[100],5);
        }
      }
    }
    iVar3 = FUN_80217258(psVar1,piVar10 + 0x4a);
    if ((iVar3 != 0) && ((*(short *)(piVar10 + 0x69) == -1 || (iVar4 = FUN_8001ffb4(), iVar4 == 0)))
       ) {
      iVar4 = 1;
      dVar12 = (double)FUN_80021690(iVar3 + 0x18,psVar1 + 0xc);
      local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x1a) ^ 0x80000000);
      if ((double)(float)(local_40 - DOUBLE_803e68d8) <= dVar12) {
        *psVar1 = *psVar1 + DAT_803dc2ac;
        psVar5 = (short *)FUN_800395d8(psVar1,0xb);
        *psVar5 = *psVar5 >> 1;
      }
      else {
        iVar4 = FUN_80216eac(psVar1,iVar3,piVar10 + 0x4c,0x168,piVar10 + 4);
        if (iVar4 != 0) {
          FUN_8000bb18(psVar1,0x1ad);
        }
      }
      if ((iVar4 != 0) ||
         (local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x1a) ^ 0x80000000),
         (double)(float)(local_40 - DOUBLE_803e68d8) <= dVar12)) {
        if (piVar10[0x65] != 0) {
          FUN_8021fab4();
        }
      }
      else {
        if (iVar3 == iVar2) {
          FUN_802966cc(iVar2);
        }
        if (*(char *)((int)piVar10 + 0x1a7) == '\x01') {
          piVar10[0x67] = 0x1b5;
          FUN_8021fad0(piVar10[0x65]);
        }
        else if (*(char *)((int)piVar10 + 0x1a7) == '\0') {
          piVar10[0x67] = 0x429;
          iVar2 = FUN_800801a8(piVar10 + 0x4b);
          if (iVar2 != 0) {
            local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x1c) ^ 0x80000000);
            iVar2 = FUN_80221c18((double)((float)(local_40 - DOUBLE_803e68d8) / FLOAT_803e6908),
                                 iVar3,piVar10 + 4,&local_80);
            if (iVar2 != 0) {
              iVar2 = *(int *)(psVar1 + 0x5c);
              cVar7 = FUN_8002e04c();
              if (cVar7 == '\0') {
                iVar2 = 0;
              }
              else {
                puVar8 = (undefined2 *)FUN_8002bdf4(0x20,0x429);
                *puVar8 = 0x429;
                *(undefined *)(puVar8 + 1) = 8;
                *(undefined *)(puVar8 + 2) = 1;
                *(undefined *)(puVar8 + 3) = 0xff;
                *(undefined *)((int)puVar8 + 5) = 1;
                *(undefined *)((int)puVar8 + 7) = 0xff;
                *(undefined4 *)(puVar8 + 4) = *(undefined4 *)(iVar2 + 0x10);
                *(undefined4 *)(puVar8 + 6) = *(undefined4 *)(iVar2 + 0x14);
                *(undefined4 *)(puVar8 + 8) = *(undefined4 *)(iVar2 + 0x18);
                iVar2 = FUN_8002df90(puVar8,5,(int)*(char *)(psVar1 + 0x56),0xffffffff,0);
              }
              if (iVar2 != 0) {
                local_50 = piVar10[4];
                local_4c = piVar10[5];
                local_48 = piVar10[6];
                local_68 = local_80;
                local_64 = local_7c;
                local_60 = local_78;
                local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x1c) ^ 0x80000000);
                (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))
                          ((double)((float)(local_40 - DOUBLE_803e68d8) / FLOAT_803e6908),iVar2,
                           auStack92,auStack116);
                *piVar10 = iVar2;
                FUN_80030334((double)FLOAT_803e690c,psVar1,1,0);
                piVar10[0x49] = (int)FLOAT_803e6910;
                FUN_8000bb18(psVar1,0x1ab);
                FUN_8000bb18(psVar1,0x1ac);
              }
            }
            FUN_80080178(piVar10 + 0x4b,(int)(short)((int)*(char *)(iVar9 + 0x19) << 2));
          }
        }
      }
    }
    puVar8 = (undefined2 *)piVar10[0x65];
    if (puVar8 != (undefined2 *)0x0) {
      if ((puVar8[0x58] & 0x40) == 0) {
        puVar6 = (undefined2 *)FUN_800395d8(psVar1,0xb);
        local_40 = (double)CONCAT44(0x43300000,(int)*psVar1 ^ 0x80000000);
        iVar2 = (int)((float)(local_40 - DOUBLE_803e68d8) + FLOAT_803ddd68);
        local_38 = (double)(longlong)iVar2;
        *puVar8 = (short)iVar2;
        puVar8[1] = *puVar6;
      }
      else {
        piVar10[0x65] = 0;
      }
    }
    if ((*(byte *)(piVar10 + 0x6a) >> 2 & 1) == 0) {
      local_88 = 1;
      cVar7 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e691c,piVar10 + 7,psVar1,&local_88,0);
      if (cVar7 == '\0') {
        *(byte *)(piVar10 + 0x6a) = *(byte *)(piVar10 + 0x6a) & 0xfb | 4;
        *(int *)(psVar1 + 6) = piVar10[0x21];
        *(int *)(psVar1 + 10) = piVar10[0x23];
        *(int *)(psVar1 + 8) = piVar10[0x22];
      }
    }
    else {
      FUN_80222358((double)(FLOAT_803e6914 * FLOAT_803dc2a8),(double)FLOAT_803e6918,
                   (double)FLOAT_803e6908,psVar1,piVar10 + 7,1);
      FUN_8002b95c((double)(*(float *)(psVar1 + 0x12) * FLOAT_803db414),
                   (double)(*(float *)(psVar1 + 0x14) * FLOAT_803db414),
                   (double)(*(float *)(psVar1 + 0x16) * FLOAT_803db414),psVar1);
    }
    iVar2 = FUN_8002b9ac();
    if (iVar2 != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,psVar1,1,2);
    }
    iVar2 = FUN_8002fa48((double)(float)piVar10[0x49],(double)FLOAT_803db414,psVar1,0);
    if ((psVar1[0x50] == 1) && (iVar2 != 0)) {
      FUN_80030334((double)FLOAT_803e690c,psVar1,0,0);
      piVar10[0x49] = (int)FLOAT_803e6920;
    }
    dVar12 = DOUBLE_803e6930;
    local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)piVar10 + 0x1aa));
    iVar2 = (int)(FLOAT_803e6924 * FLOAT_803db414 + (float)(local_38 - DOUBLE_803e6930));
    local_40 = (double)(longlong)iVar2;
    *(short *)((int)piVar10 + 0x1aa) = (short)iVar2;
    uStack44 = (uint)*(ushort *)((int)piVar10 + 0x1aa);
    local_30 = 0x43300000;
    dVar12 = (double)FUN_80293e80((double)((FLOAT_803e6928 *
                                           (float)((double)CONCAT44(0x43300000,uStack44) - dVar12))
                                          / FLOAT_803e692c));
    piVar10[0x68] = (int)(float)((double)FLOAT_803e68ec * dVar12);
    *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) + (float)piVar10[0x68];
  }
LAB_80217d18:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286124();
  return;
}

